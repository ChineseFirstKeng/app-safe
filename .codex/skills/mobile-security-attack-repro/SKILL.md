---
name: mobile-security-attack-repro
description: 为授权的 APK/IPA 测试生成可复现的移动端安全攻击方案、统一文档、操作脚本、验证证据和完整性约束检查。
---

# 移动端安全攻击复现

Use this skill when the user wants an APK/IPA security attack or tampering experiment turned into a repeatable package that another tester can run directly.

## Scope gate

Before touching an app, confirm that the package, device, account, server, and data are authorized test assets. Keep all traffic on a declared local, lab, or test endpoint. Do not target third-party production systems, bypass real-user access controls, or write passwords, tokens, cookies, signing passwords, or private keys into generated documents or scripts. Credentials may be entered manually or supplied through environment variables.

The output is an attack reproduction and defensive evidence package, not a production malware package. Keep injected behavior visibly marked as test behavior and provide a restore path.

## Required output

For each independent attack, create a separate Chinese-named directory. Read [references/output-schema.md](references/output-schema.md) before creating it. The directory must contain:

- one main workflow script with stable subcommands;
- every non-trivial step implemented by an existing child script or an explicit tool check;
- the tested artifact or a deterministic build command;
- a Chinese Markdown report with the same section names as the other attack directories;
- a verification command that produces observable evidence;
- cleanup/restore commands;
- a machine-checkable validation result.

Use the following minimum report sections, in this order:

1. `攻击目标与范围`
2. `前置条件`
3. `攻击手段`
4. `攻击获得信息`
5. `攻击流程和操作`
6. `工具、脚本和参数`
7. `攻击成功判据`
8. `实际验证结果`
9. `可能造成的后果`
10. `防护方案`
11. `清理和恢复`
12. `局限和未验证事项`

Every command in `攻击流程和操作` must point to a script present in the same attack directory. Raw ADB/curl/python commands are allowed only for harmless prerequisite checks or when the report explicitly states why no wrapper is needed. Prefer one main script such as `run_<attack>_attack.sh`, with child scripts under `scripts/`.

## Workflow

1. Inventory the supplied APK/IPA, device, test endpoint, account method, and expected business effect. Do not infer authorization for production assets.
2. Separate independent attack chains. Do not merge log replay, repackaged-response tampering, and client-page replacement into one vague report.
3. Build the directory and main workflow first. Define subcommands such as `preflight`, `build`, `install`, `attack`, `verify`, `reopen`, and `restore-original` according to the attack.
4. Implement child scripts for parsing, replay, mock responses, binary patching, repackaging, device installation, UI/log verification, and cleanup as needed. Scripts must use explicit paths, fail fast, redact secrets, and return non-zero on failed prerequisites or failed evidence.
5. Run a controlled test and record only evidence needed to prove the claim: status codes, object IDs where safe, UI text, Activity names, hashes, timestamps, and redacted logs.
6. If the user asks for detection, review, comparison, or completeness checking, you MUST start a fresh independent agent for that check. Give it the generated directory and the checklist, but not the intended conclusion or suspected defects. The independent agent must inspect the actual files and return pass/fail findings. Do not claim detection is complete without its result.
7. Run the local validator in `scripts/validate_attack_package.py`, fix every error, and rerun the validator. Validation must cover directory structure, required report sections, referenced script existence, executable main script, secret-pattern scan, and restore command presence.
8. Report what was actually executed, what was only prepared, what succeeded, what failed, and the exact artifact paths. Never describe an unexecuted attack as successful.

## Script conventions

- Shell entrypoints use `set -euo pipefail`, resolve `ROOT` from the script location, validate tools/devices, and expose `help`.
- Destructive test actions require an explicit subcommand such as `clean-install` or `restore-original`; never hide them behind a default action.
- Build scripts accept input/output paths and use environment variables for signing secrets.
- Verification scripts must not print full tokens, cookies, passwords, request bodies, or private-key material.
- A successful HTTP response alone is not a successful business attack. Require before/after comparison, UI evidence, or an equivalent causal proof.
- Preserve prior user files and use exact artifact paths. Do not delete broad directories.

## References

- Read [references/output-schema.md](references/output-schema.md) when creating or normalizing an attack directory.
- Read [references/validation-checklist.md](references/validation-checklist.md) before declaring the package complete.
