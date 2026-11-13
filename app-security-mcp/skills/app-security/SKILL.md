---
name: app-security
description: App Security MCP 入口：检查连接，或组织指定 APK/IPA 的硬编码候选扫描、脱敏证据、修复建议与覆盖缺口；用户提到 app-security 或要求检查该服务时使用。
---

# App Security

## 内容与核查报告（0.36.0，优先于下方历史脱敏说明）

先报告逐条内容及风险依据，再简述覆盖：候选编号、内容、文件与方法/偏移、已知用途线索、尚未确认事项、修复与复测。始终读取 client_identifier_review，finding_count=0 时也列出待核查 Key；不把标识存在说成已确认泄密，也不把普通服务器地址或接口路径直接说成漏洞。

用户要求具体内容或判断依据时，调用 export_report({scan_id,format:"markdown",include_sensitive_values:true})，提供本机文件链接。该文件包含本次捕获原值，权限 600；工具响应只返回路径。聊天默认仅给脱敏预览、位置和结论，完整密码、Token、私钥等在本机报告中供用户核对。JSON 报告也支持同一选项；字节材料用 hex 并标明编码，结构化记录用 JSON。检查 private_evidence.values_truncated、候选/标识截断和未捕获值，不能承诺列全未分析内容。旧扫描未保存原值时复用已有 artifact_id 重扫，不重复导入原包。

正常 get_scan_status、list_findings、read_evidence 和默认报告继续脱敏。不自动使用捕获凭证连接服务。不确定用途的项目明确标为待核查，不能升级为已确认漏洞。


当前已实现资源、Android DEX、ELF 及 iOS Mach-O 字符串基础硬编码候选检测。用户要求安全检查时，导入指定 APK/IPA 后调用对应 scan_android_hardcoding / scan_ios_hardcoding，再查询状态并使用 list_findings/get_finding 获取脱敏证据与修复建议。Android 二进制 XML 和资源表使用 AAPT2 解码，缺少依赖或解码失败会记录覆盖缺口。DEX 通过 dexdump 检查常量和受限直线指令，verify_android_finding 可通过独立 REA MCP 恢复候选方法体；查看 dex_scan 和 verifications 的覆盖缺口。iOS 检查 App/Framework/Extension 多架构与加密状态，查看 ios_native_scan。有已知函数符号或提供方返回的函数地址时，可用 verify_ios_finding 复核所选函数及字符串引用；不要把字符串地址当作函数地址。通常结果为 partial，复杂数据流、原生实际用途与运行验证未全面实现。下方第 2 步的“不扫描”说明仅指 import_local_artifact 本身，不能用于描述 scan 工具。

本 Skill 随 App Security 插件一起安装，指导调用插件自带的 MCP 工具。无需单独安装 Skill。

通过插件提供的 `app-security` MCP（工具名称可能包含插件命名空间） 执行用户要求的操作。当前提供有界静态硬编码候选检查；完整用途与运行验证仍需补充证据。

## 工具选择

| 用户目标 | 工具 | 输入示例 |
| --- | --- | --- |
| 检查连接 | `health_check` | `{}` |
| 测试回显 | `echo` | `{"message":"你好 MCP"}` |
| 数字相加 | `add_numbers` | `{"a":12,"b":30}` |
| 文本摘要 | `text_sha256` | `{"text":"abc"}` |
| 识别包名后缀 | `inspect_package_filename` | `{"filename":"demo.apk"}` |

用户仅说“测试整条链路”时，依次调用健康检查、回显、12 + 30、abc 的摘要和 demo.apk 文件名识别。确认实际返回，不根据预期自行生成工具结果。`add_numbers` 应为 42；文件名识别应为 Android/APK 且 `scanned: false`。

只执行用户需要的工具，保留文本原样。`text_sha256` 会将输入文本发送到当前连接的 MCP 服务，不主动读取或发送本地文件内容。文件名识别仅按后缀判断，不读取安装包，不能据此宣称完成安全分析。

## 连接问题

当前会话缺少工具时说明 MCP 未连接，不用本地计算冒充调用。检查 MCP 配置，重新连接或新建会话。
HTTP 部署的 401 表示 token 缺失或错误；本地 stdio 模式不需要 token。不要输出凭证。
结果简要报告实际调用的工具及返回值；如某一步失败，说明失败位置和已完成部分。

## 安装包导入与内容清点（第 2 步）

用户给出明确 APK/IPA 文件路径并要求检查时，调用 `import_local_artifact`，传入绝对路径和 expected_platform（android 或 ios）。保存返回的 artifact_id，再调用 `inspect_imported_artifact` 分页查看清单。需要完整清单时根据 next_offset 继续；不要重复导入来翻页。
报告包摘要、结构识别结果、文件分类和 coverage。当前只验证 ZIP 完整性及包布局，尚未验证 Manifest/plist 语义、签名、可安装性，也未执行硬编码扫描。不能把导入成功说成安全检查通过。文件名分类仅是线索。
用户要求删除导入数据时调用 `delete_imported_artifact`，原始文件保留。Python 3 缺失则说明依赖缺失；HTTP 模式不提供本地文件导入工具。不要自行选择附近安装包作为目标。

Android 原生查看 android_native_scan：ELF/ABI、分段字符串、受限单层解码和 JNI 导出线索。有已知函数符号或提供方返回的函数地址时，verify_android_native_finding 可复核原生候选；不要把字符串地址当函数地址。动态 JNI 注册和 Flutter AOT 语义仍未知。

## 证据和任务清理

使用 read_evidence(scan_id, evidence_id) 读取候选的脱敏证据和来源身份；不读取秘密原文。list_findings 支持 rule_id、severity、confidence 筛选，next_cursor 必须配合同样的筛选条件继续；结果更新后失效。next_cursor 为空仅表示当前列表读完，不代表全包已分析。
用户要求清理时，先取消正在运行的任务，再 delete_scan 删除已结束结果及导出报告；共享快照保留。delete_imported_artifact 在任何扫描仍引用快照时拒绝删除，需先清理所有相关扫描。复核/导出/创建和删除通过跨进程锁协调；忙时稍后重试。异常退出遗留锁会阻止操作，确认所有相关进程退出后由本机运维清理，不能自动猜测锁已失效。

## 自动方法复核

Android 请求 profile=static-deep 时，基础检查后按 DEX 路径/类/方法原型去重，最多复核 deep_method_limit 个方法（默认 3、最大 10），追加阶段总预算 150 秒。查看 deep_scan 的 eligible/attempted/recovered/remaining 统计、reason 和 verifications；依赖或容量受阻不抹去基础结果。effective_profile 只有恢复方法体后才显示 static-basic+rea-dex-corroboration。恢复方法体不等于确认值传播、用途或漏洞。iOS/ELF 现支持原始字面量的有界自动引用/函数选择，见下方说明。cancel_scan 可中止自动阶段，已保存的候选保留。

## 自动原生引用复核

profile=static-deep 会对原始 ELF/Mach-O 字面量自动校验成员/切片摘要和原文件偏移，再读取引用地址及所属函数。deep_native_limit 默认 2、最大 5 个去重字面量，与 DEX 阶段共享追加的 150 秒预算。先检查已知地址的偏移映射，失败时最多映射前 128 个提供方字符串地址，最多检查 32 个引用。iOS 使用切片内相对偏移，不用 FAT 容器偏移直接匹配。解码值、无映射或无函数引用保持未复核，不猜测附近函数。查看 eligible_native_literals、attempted_native_literals、recovered_functions、remaining_native_literals，以及 verifications 内 discovery 的证据链与截断标志。函数体恢复和静态字符串引用不证明安全用途或运行行为。

## 私钥格式解析

HC-006 的 key_validation.status=parsed_private_key 表示 Node/OpenSSL 成功创建私钥对象；报告仅包含算法和可用位数。支持 PEM 与 DER 的 PKCS1/PKCS8/SEC1，公钥/证书不作为私钥候选；无效材料与不支持格式仍有边界。加密 PEM、加密 DER 及 OpenSSH 包装可能仅记录未完成验证的线索，不能宣称已解密或证实密钥用途。查看 key_material_scan 的 parsed/public_material/unresolved/budget_skipped。每次扫描最多 32 次解析，每项 128 KiB、3 秒，遵守整体时间预算。PKCS12/JKS 容器及口令破解未实现；OpenSSH 单密钥 Ed25519/RSA/ECDSA 无口令材料现可解析，见下方说明。

## 嵌套归档与 OpenSSH

读取 nested_archive_scan：ZIP/JAR/APK/IPA/AAR 按后缀或 ZIP 魔数递归检查，最多两层归档、32 个归档、5000 个内部条目、每条目 8 MiB、累计发现读取 64 MiB、发现预算 10 秒，仍受全局预算限制。危险路径/重复条目/特殊文件/CRC 错误的归档不展开；超限和失败必须说明。证据保存 archive_chain 路径/摘要及 member_path，展示路径中的 !/ 仅是显示，不能据此猜测归档身份。归档路径脱敏后不能可靠提取时，独立复核保持未知。嵌套原生成员可以按记录链重新校验和复核；嵌套 DEX 独立 JADX 复核、嵌套 Android 二进制资源和 Java class 字节码尚未支持。

OpenSSH 单密钥未加密 Ed25519、RSA、ECDSA nistp256/384/521 可进行结构解析及公私钥一致性检查。加密容器只报告口令需求，不尝试口令；不支持的类型/多密钥包装保留未知状态。格式可解析不证明密钥用途、权限或安全强度。

共享数据目录的 POSIX 静态工作进程上限为 2；容量不足时任务可能 queued 后转 blocked，原因 global_scan_capacity_exceeded，表示未执行检测。不要删除 _capacity/scan-*.lock 来释放容量；锁由实际工作进程退出释放。宿主退出后仍存活的工作进程继续持槽，不能仅凭任务 failed 就删其结果/快照。REA 容量目前仍按进程限制，Windows 静态准入尚未支持。
