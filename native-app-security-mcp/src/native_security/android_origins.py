"""Bounded SSA value provenance along a selected same-DEX invocation path.

This identifies definitions of observed arguments, not feasible execution paths,
attacker control, successful validation or exploitability.
"""
import time
import json

INTENT_RETURNS = {
    "android.content.Intent.getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
    "android.content.Intent.getData()Landroid/net/Uri;",
    "android.content.Intent.getDataString()Ljava/lang/String;",
    "android.content.Intent.getExtras()Landroid/os/Bundle;",
}


def unknown(reason):
    return {"kind": "unknown", "reason": reason}


def copy_origin(value, depth, budget):
    budget[0] -= 1
    if depth > 24 or budget[0] < 0 or not isinstance(value, dict):return unknown("provenance_budget")
    result = {}
    for key, item in value.items():
        if key in {"value", "receiver"}:
            result[key] = copy_origin(item, depth+1, budget)
        elif key == "choices":
            if not isinstance(item, list) or len(item) > 8:return unknown("provenance_budget")
            result[key] = [copy_origin(c, depth+1, budget) for c in item]
        elif item is None or type(item) in {bool, int} or isinstance(item, str) and len(item) <= 2048:
            result[key] = item
        else:return unknown("provenance_metadata_budget")
    return result


def evaluate(expression, context, depth=0, budget=None):
    if budget is None:budget = [128]
    budget[0] -= 1
    if depth > 24 or budget[0] < 0:return unknown("provenance_budget")
    if not isinstance(expression, dict):return unknown("missing_expression")
    kind = expression.get("kind")
    if kind == "constant":
        return {"kind": "constant", "value_type": expression.get("value_type") if expression.get("value_type") in {"const_str", "const", "const_class", "literal"} else "unspecified"}
    if kind == "parameter":
        index = expression.get("index")
        if type(index) is not int or not 0 <= index < len(context["parameters"]):return unknown("parameter_not_bound")
        return {"kind": "parameter_binding", "unit_id": context["unit_id"], "parameter_index": index,
                "value": copy_origin(context["parameters"][index], depth+1, budget)}
    if kind == "receiver":return copy_origin(context["receiver"], depth+1, budget)
    if kind == "constructed_object":return {"kind": "constructed_object"}
    if kind == "merge":
        choices = expression.get("choices")
        if not isinstance(choices, list) or not 1 <= len(choices) <= 8:return unknown("invalid_merge")
        return {"kind": "merge", "choices": [evaluate(c, context, depth+1, budget) for c in choices],
                "branch_feasibility": "not_analyzed"}
    if kind == "invoke_return":
        target = expression.get("target")
        if target in INTENT_RETURNS:
            return {"kind": "intent_api_return", "api": target, "unit_id": context["unit_id"],
                    "ir_offset": expression.get("site"), "receiver": evaluate(expression.get("receiver"), context, depth+1, budget),
                    "external_control": "not_proven", "dispatch_effectiveness": "not_analyzed"}
        if isinstance(target, str) and target.endswith(".getIntent()Landroid/content/Intent;"):
            return {"kind": "get_intent_candidate", "declared_method": target, "unit_id": context["unit_id"],
                    "ir_offset": expression.get("site"), "receiver": evaluate(expression.get("receiver"), context, depth+1, budget),
                    "override_behavior": "not_analyzed", "external_control": "not_proven"}
        # Unknown calls may discard, replace or validate their arguments. Their
        # return value must not inherit argument provenance by assumption.
        return unknown("unmodelled_invoke_return")
    if kind == "unknown":
        reason = expression.get("reason", "unsupported_definition")
        return unknown(reason if isinstance(reason, str) and len(reason) <= 96 else "unsupported_definition")
    return unknown("unsupported_expression")


def origin_kinds(value, depth=0):
    if depth > 32 or not isinstance(value, dict):return {"unknown"}
    kind = value.get("kind")
    if kind == "parameter_binding":return origin_kinds(value.get("value"), depth+1)
    if kind == "merge":
        return set().union(*(origin_kinds(c, depth+1) for c in value.get("choices", []))) or {"unknown"}
    return {kind} if kind in {"constant", "intent_api_return", "entry_parameter", "constructed_object"} else {"unknown"}


def argument_trace(path, unit_by_id, flows, deadline):
    result = {"analysis_kind": "jadx_ssa_argument_origins", "status": "unavailable", "parameter_index": 0,
              "contexts": [], "observed_origin_kinds": [], "coverage": "partial", "runtime_observed": False,
              "control_flow_feasibility": "not_analyzed", "external_control": "not_proven", "unknowns": []}
    chain = path["code_path"]
    if not chain or len(chain) > 7:return result
    first = flows.get(chain[0], {})
    if first.get("status") != "captured_partial":
        result["unknowns"] = ["entry_ssa_not_captured"]
        return result
    count = first.get("parameter_count")
    if type(count) is not int or not 0 <= count <= 16:
        result["unknowns"] = ["entry_parameter_budget"]
        return result
    contexts = [{"unit_id": chain[0], "parameters": [{"kind": "entry_parameter", "unit_id": chain[0], "index": i} for i in range(count)],
                 "receiver": {"kind": "entry_receiver", "unit_id": chain[0]}, "call_chain": []}]
    gaps, expansions, all_kinds, output_bytes = set(), 0, set(), 0
    for level, uid in enumerate(chain):
        if time.monotonic() >= deadline:
            gaps.add("analysis_time_budget"); break
        flow = flows.get(uid, {})
        if flow.get("status") != "captured_partial":
            gaps.add("method_ssa_not_captured"); break
        if flow.get("truncated"):gaps.add("ssa_capture_truncated")
        invokes = flow.get("invocations", [])
        if not isinstance(invokes, list) or len(invokes) > 128:
            gaps.add("invalid_invocation_budget"); break
        target = path["api"] if level == len(chain)-1 else unit_by_id[chain[level+1]]["identity"]
        matched = [i for i in invokes if isinstance(i, dict) and i.get("target") == target]
        if not matched:
            gaps.add("method_use_without_captured_invocation"); break
        next_contexts = []
        for context in contexts:
            for invoke in matched:
                expansions += 1
                if expansions > 128 or time.monotonic() >= deadline:
                    gaps.add("invocation_context_budget"); break
                args = invoke.get("arguments")
                if not isinstance(args, list) or len(args) > 16:
                    gaps.add("invalid_arguments"); continue
                call = {"unit_id": uid, "declared_target": target, "ir_offset": invoke.get("site"),
                        "site_kind": "jadx_ir_offset", "dispatch_exact": invoke.get("dispatch_exact") is True}
                calls = [*context["call_chain"], call]
                if level == len(chain)-1:
                    if not args:gaps.add("sink_parameter_unavailable"); continue
                    value = evaluate(args[0], context)
                    kinds = origin_kinds(value)
                    item = {"call_chain": calls, "origin": value, "observed_origin_kinds": sorted(kinds)}
                    amount = len(json.dumps(item, ensure_ascii=False).encode())
                    if output_bytes + amount > 128 * 1024:
                        gaps.add("evidence_output_budget"); break
                    output_bytes += amount; all_kinds.update(kinds)
                    result["contexts"].append(item)
                    if len(result["contexts"]) >= 16:gaps.add("context_output_budget"); break
                else:
                    next_uid = chain[level+1]
                    if not call["dispatch_exact"]:
                        gaps.add("non_exact_interprocedural_dispatch"); continue
                    if unit_by_id[uid]["component"] != unit_by_id[next_uid]["component"]:
                        gaps.add("cross_component_dispatch"); continue
                    next_flow = flows.get(next_uid, {})
                    if next_flow.get("parameter_count") != len(args):
                        gaps.add("callee_parameter_mismatch"); continue
                    next_contexts.append({"unit_id": next_uid, "parameters": [evaluate(a, context) for a in args],
                        "receiver": evaluate(invoke.get("receiver"), context), "call_chain": calls})
                    if len(next_contexts) >= 16:gaps.add("context_fanout_budget"); break
            if expansions > 128 or len(next_contexts) >= 16 or len(result["contexts"]) >= 16:break
        contexts = next_contexts
        if level < len(chain)-1 and not contexts:break
    result["status"] = "partial" if result["contexts"] else "unresolved"
    result["observed_origin_kinds"] = sorted(all_kinds)
    result["unknowns"] = sorted(gaps)
    return result
