# App Security

App Security bundles a local MCP server and three workflow skills in one plugin. It imports user-selected Android APK or iOS IPA files into private local storage, checks supported resources and bounded code constants, and returns redacted candidates, evidence locations, remediation guidance and coverage limitations. It does not execute applications or test credentials against external services. A result with no findings is not a security certification.

Requires Node.js 22+ and Python 3. Android resource/DEX decoding needs Android SDK aapt2 and dexdump. Optional independent verification uses a separately configured REA installation. Run get_analysis_capabilities to inspect dependencies.

Codex: select `$app-security:android:check-hardcoding` or `$app-security:ios:check-hardcoding` and provide the absolute package path. Claude Code: select the corresponding app-security workflow from the `/` command menu. MCP and skills install together; no separate skill installation or shared token is required for local stdio operation.

Tasks and reports persist in APP_SECURITY_DATA_DIR, defaulting to ~/.app-security/artifacts. Use delete_scan before deleting a referenced imported artifact. Original source packages are retained.
