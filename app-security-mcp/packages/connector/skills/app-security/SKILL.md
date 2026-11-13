---
name: app-security
description: 使用 app-security MCP 检查连接、验证调用链路，以及执行文本回显、数字相加、文本 SHA-256 和安装包文件名识别示例。用户提到 app-security 或要求验证该 MCP 时使用。
---

# App Security

通过已连接的 `app-security` MCP 执行用户要求的操作。当前是接入演示服务，不提供 APK/IPA 漏洞扫描。

## 工具选择

| 用户目标 | 工具 | 输入示例 |
| --- | --- | --- |
| 检查连接 | `health_check` | `{}` |
| 测试回显 | `echo` | `{"message":"你好 MCP"}` |
| 数字相加 | `add_numbers` | `{"a":12,"b":30}` |
| 文本摘要 | `text_sha256` | `{"text":"abc"}` |
| 识别包名后缀 | `inspect_package_filename` | `{"filename":"demo.apk"}` |

用户仅说“测试整条链路”时，依次调用健康检查、回显、12 + 30、abc 的摘要和 demo.apk 文件名识别。确认实际返回，不根据预期自行生成工具结果。`add_numbers` 应为 42；文件名识别应为 Android/APK 且 `scanned: false`。

只执行用户需要的工具，保留文本原样。`text_sha256` 会将输入文本发送到远程服务，不主动读取或发送本地文件内容。文件名识别仅按后缀判断，不读取安装包，不能据此宣称完成安全分析。

## 连接问题

若当前会话没有相关工具，明确说明“Skill 已加载，但 MCP 工具未连接”，不要用本地计算冒充 MCP 调用。建议先运行安装包的 `doctor --client codex`，再完全重启 Codex 并新建对话。

401 表示 token 缺失或错误；连接超时可能是网络或服务问题。不要输出配置中的 token。安装器的诊断通过只证明配置和协议链路正常，不证明当前对话已加载工具。

结果简要报告实际调用的工具及返回值；如某一步失败，说明失败位置和已完成部分。
