# 硬编码内容报告验收（插件 0.36.0）

日期：2026-11-11。本轮按用户要求优先补齐“具体检出了什么、在哪里、为什么可能有风险、如何修复”，不继续扩展无关基础设施。REA 共享容量试验已移至被忽略的 artifacts/deferred-rea-capacity，不随插件交付。

## 实现范围

- 报告正文逐项列出候选内容、文件/偏移/方法、用途线索、未知事项、修复及复测；待核查 Key/客户端标识单独展示，不再只藏于 JSON 附录。
- 扫描命中项保留私有原值：资源字段、URL（含 path/query）、连接串、Basic/Bearer、私钥、选定联系字段以及受支持的 DEX 固定密钥/IV/Nonce/盐/比较字符串。字节材料记录实际选中范围的 hex；原值和位置关联，不用“常量字节”替代。
- 私有原值与普通扫描结果分离，权限 600。export_report(include_sensitive_values=true) 将捕获原值写入本机 JSON/Markdown 文件，MCP 返回文件路径；默认报告、状态和证据读取保持脱敏。
- 每值上限 256 KiB、累计 4 MiB，超限设置 private_evidence.values_truncated；未捕获的导出值明确为 [NOT_CAPTURED]，不静默冒充完整。删除任务同时删除关联原值和导出文件。旧扫描没有保存原值时要求复扫已有 artifact_id。
- 捕获内容不等于确认漏洞；不把普通地址/接口路径、客户端标识或用途未知的 Key 自动认定为泄密。

## 自动与安装验收

- test/private-report.test.mjs：APK/IPA 合成包完整内容、URL/path/query、密码/令牌/连接串/联系字段、默认脱敏、私有文件权限、身份不符拒绝、符号链接拒绝及删除。
- test/dex.test.mjs：真实 Java→DEX 编译，密钥/IV 切片、Base64 后切片、GCM Nonce、PBE 盐、UTF-8 返回值以及认证比较原值与期望材料一致，普通报告脱敏。
- HC-009 单元测试改为检查内部回调保留实际比较值；公开 MCP 层脱敏仍由 DEX 集成测试验证。首次全量回归发现旧内部脱敏断言与新契约冲突，已修正后重跑。
- 57/57 严格回归通过，零失败、零跳过。统计见 artifacts/validation/acceptance-summary.json；安装记录位于 artifacts/validation。Codex 插件发现 3 个 Skill、23 个工具；Codex 隔离安装及 Claude Code 隔离安装和 MCP 握手通过。Claude 模型实际 Skill 调用仍未验证。

## 用户 APK 实测

使用已导入快照，不重复导入、不执行 App、不使用提取凭证联网。

- SHA-256：968460c42b849e0b91f2a1de46a8c1c18a12027066251aaaac190267c8545c38
- 新任务：142ddd41859c4c1896c8fb1a14bd7bac；static-basic；终态 partial。
- 安全候选 0；待核查标识 1；捕获原值 1；原值未截断。
- 实际项：resources.arsc → string/google_api_key → aapt2-resources-line:6509；预览 AIza…UMNM。完整值只在本机核查文件中，不写入本仓库文档。
- 原值 Markdown：/Users/h1610/.app-security/artifacts/_scans/142ddd41859c4c1896c8fb1a14bd7bac-5451a7ffe1d44fb9b6e5cb8c9d6d8df5.md
- 原值 JSON：/Users/h1610/.app-security/artifacts/_scans/142ddd41859c4c1896c8fb1a14bd7bac-92747016312f4373921bd4f051943236.json
- 脱敏 Markdown：/Users/h1610/.app-security/artifacts/_scans/142ddd41859c4c1896c8fb1a14bd7bac-b0add2b364f14bf49f3b32f08c577a5e.md
- 已检查完整值存在于原值报告、默认报告/状态不含完整值、文件权限 600。结构化验收：artifacts/validation/content-report-apk.json。

## 边界

这次补齐的是命中内容的可核查性，没有扩大规则匹配范围。当前 APK 仍只有一个用途/权限/应用限制未知的 Key；不能称为已确认泄密。Flutter Dart AOT、一般跨方法数据流、完整原生用途及运行验证仍未覆盖，不能承诺列出全包所有真实问题。
