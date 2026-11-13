import time
import unittest
import json

from native_security.android_origins import argument_trace, evaluate, origin_kinds

SOURCE = "android.content.Intent.getStringExtra(Ljava/lang/String;)Ljava/lang/String;"
SINK = "android.webkit.WebView.loadUrl(Ljava/lang/String;)V"


class AndroidOriginTests(unittest.TestCase):
    def graph(self, exact=True):
        units = {"entry": {"identity": "Example.onCreate(Landroid/os/Bundle;)V", "component": {"path": "classes.dex"}},
                 "helper": {"identity": "Example.helper(Ljava/lang/String;)V", "component": {"path": "classes.dex"}}}
        source = {"kind": "invoke_return", "target": SOURCE, "site": 4, "receiver": {"kind": "constructed_object"}, "arguments": []}
        flows = {"entry": {"status": "captured_partial", "parameter_count": 1, "invocations": [
            {"target": units["helper"]["identity"], "site": 8, "dispatch_exact": exact, "arguments": [{"kind": "constant"}]},
            {"target": units["helper"]["identity"], "site": 12, "dispatch_exact": exact, "arguments": [source]}]},
            "helper": {"status": "captured_partial", "parameter_count": 1, "invocations": [
                {"target": SINK, "site": 0, "dispatch_exact": False, "arguments": [{"kind": "parameter", "index": 0}]}]}}
        return {"code_path": ["entry", "helper"], "api": SINK}, units, flows

    def test_same_helper_distinct_callsite_bindings_and_zero_offset(self):
        path, units, flows = self.graph()
        result = argument_trace(path, units, flows, time.monotonic()+2)
        self.assertEqual(["constant", "intent_api_return"], result["observed_origin_kinds"])
        self.assertEqual(2, len(result["contexts"]))
        self.assertEqual([8, 12], [c["call_chain"][0]["ir_offset"] for c in result["contexts"]])
        self.assertTrue(all(c["call_chain"][-1]["ir_offset"] == 0 for c in result["contexts"]))
        self.assertEqual("not_proven", result["external_control"])

    def test_unknown_return_does_not_inherit_source_from_its_argument(self):
        context = {"unit_id": "entry", "parameters": [], "receiver": {"kind": "entry_receiver"}}
        value = evaluate({"kind": "invoke_return", "target": "Example.replace(Ljava/lang/String;)Ljava/lang/String;",
                          "arguments": [{"kind": "invoke_return", "target": SOURCE}]}, context)
        self.assertEqual({"unknown"}, origin_kinds(value))

    def test_non_exact_dispatch_and_cross_dex_never_bind_as_exact(self):
        path, units, flows = self.graph(False)
        result = argument_trace(path, units, flows, time.monotonic()+2)
        self.assertFalse(result["contexts"])
        self.assertIn("non_exact_interprocedural_dispatch", result["unknowns"])
        flows["entry"]["invocations"][0]["dispatch_exact"] = True
        units["helper"]["component"] = {"path": "classes2.dex"}
        result = argument_trace(path, units, flows, time.monotonic()+2)
        self.assertFalse(result["contexts"])
        self.assertIn("cross_component_dispatch", result["unknowns"])

    def test_missing_capture_invoke_and_expired_budget_are_explicit(self):
        path, units, flows = self.graph()
        result = argument_trace(path, units, {}, time.monotonic()+2)
        self.assertEqual("unavailable", result["status"])
        flows["entry"]["invocations"] = []
        result = argument_trace(path, units, flows, time.monotonic()+2)
        self.assertIn("method_use_without_captured_invocation", result["unknowns"])
        result = argument_trace(path, units, flows, time.monotonic()-1)
        self.assertIn("analysis_time_budget", result["unknowns"])

    def test_phi_keeps_both_origins_and_internal_intent_is_not_external_proof(self):
        context = {"unit_id": "entry", "parameters": [], "receiver": {"kind": "entry_receiver"}}
        source = {"kind": "invoke_return", "target": SOURCE, "site": 0, "receiver": {"kind": "constructed_object"}}
        value = evaluate({"kind": "merge", "choices": [{"kind": "constant"}, source]}, context)
        self.assertEqual({"constant", "intent_api_return"}, origin_kinds(value))
        self.assertEqual("not_proven", value["choices"][1]["external_control"])
        self.assertEqual("constructed_object", value["choices"][1]["receiver"]["kind"])

    def test_cycles_invalid_bindings_and_context_fanout_are_bounded(self):
        context = {"unit_id": "entry", "parameters": [], "receiver": {"kind": "entry_receiver"}}
        recursive = {"kind": "merge"}
        recursive["choices"] = [recursive]
        self.assertEqual({"unknown"}, origin_kinds(evaluate(recursive, context)))
        self.assertEqual("parameter_not_bound", evaluate({"kind": "parameter", "index": True}, context)["reason"])
        path, units, flows = self.graph()
        flows["entry"]["invocations"] = [flows["entry"]["invocations"][0]] * 30
        result = argument_trace(path, units, flows, time.monotonic()+2)
        self.assertLessEqual(len(result["contexts"]), 16)
        self.assertIn("context_fanout_budget", result["unknowns"])
        shared = {"kind": "constant"}
        for _ in range(4):
            context["parameters"] = [shared]
            shared = evaluate({"kind": "merge", "choices": [{"kind": "parameter", "index": 0}] * 8}, context)
            self.assertLess(len(json.dumps(shared)), 128 * 1024, "shared SSA origin must not expand exponentially")
