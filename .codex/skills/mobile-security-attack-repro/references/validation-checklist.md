# Completion checklist

## Structure

- [ ] Directory name is descriptive and Chinese.
- [ ] Exactly one report is identified as the current report.
- [ ] A main workflow script exists and has `help`.
- [ ] Every referenced child script exists.
- [ ] Final APK/IPA or deterministic build command exists.
- [ ] Evidence and historical artifacts are distinguishable.

## Report

- [ ] Scope and authorization are explicit.
- [ ] 前置条件 is present.
- [ ] 攻击手段 is present.
- [ ] 攻击获得信息 is present.
- [ ] 攻击流程和操作 is present.
- [ ] Tools, scripts, arguments, and expected output are present.
- [ ] Success criteria are stronger than an HTTP 200.
- [ ] Actual verification is separated from planned steps.
- [ ] Consequences and defensive controls are present.
- [ ] Cleanup and restore are scripted.
- [ ] Limitations are stated.

## Execution

- [ ] Shell syntax checks pass.
- [ ] Python/Java/Gradle checks appropriate to the package pass.
- [ ] Preflight fails clearly when a tool, device, privilege, or input is absent.
- [ ] Secrets are redacted and not persisted.
- [ ] Attack uses only the declared lab/test target.
- [ ] Verification emits reproducible evidence.
- [ ] Restore has been tested or explicitly marked untested.

## Independent review

- [ ] If detection/review/completeness was requested, a fresh agent inspected the actual generated files.
- [ ] The reviewer received the checklist but not the expected conclusion.
- [ ] Reviewer findings are recorded with pass/fail and file references.
- [ ] Any reviewer failure is fixed before declaring complete.
