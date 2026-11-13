# 本地分析能力检查（0.18.0）

调用 `get_analysis_capabilities({platform:"android"})` 或 `{platform:"ios"}`，无需导入安装包。接口仅在 stdio 本地模式注册。

- Python：执行内置探测脚本，成功返回实际版本；失败返回 unavailable_or_probe_failed 或 unknown，不泄露命令、路径和错误原文。
- AAPT2/dexdump：复用扫描器的查找逻辑；located_not_executed 仅表示定位到可执行文件，missing 表示未找到。未执行工具，版本为 null，不声称可正常分析目标。
- REA：按现有复核器规则读取环境或配置，只返回 configured_not_verified / missing_or_invalid。不返回命令、参数、环境变量或配置内容，不启动 REA、不下载引擎。JADX/Ghidra 运行能力仍在实际定点复核时验证。
- static-basic：已实现受限扫描；static-deep 自动深度分析尚未实现，目前实际执行 static-basic 流程。定点复核仍需单独调用。

探测进程有 5 秒超时、16 KiB 输出上限。接口不接收安装包或用户命令，不执行目标代码。返回依赖状态、实现范围、预算与限制，不提供“完整覆盖”或“环境全部就绪”结论。

独立接口现已实现，但原方案的全部分析器版本和实际运行可用性检测尚未完成；仅定位或配置存在的状态保留为未验证。

## 验收

33 项严格测试通过、零跳过。新增测试覆盖缺少 Android 工具、Python 不可启动、REA 配置存在但不得声称引擎可用、参数校验以及敏感配置不出现在结果。

实际安装 0.18.0 后，通过其 stdio MCP 调用两平台接口：Python 3.9.6 可运行，AAPT2/dexdump 已定位但未执行，REA 配置有效但本次未验证引擎；Codex 发现 3 个 Skill、21 个工具。证据 artifacts/validation/capabilities-real.json。此步骤未扩展检测规则，也未重新扫描用户 APK/IPA。
