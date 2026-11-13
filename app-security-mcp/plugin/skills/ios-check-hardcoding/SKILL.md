---
name: ios:check-hardcoding
description: 检查 IPA 的资源及 Mach-O 字符串硬编码候选，覆盖 App、Framework 和 Extension 的多架构切片；明确加密、解析失败和用途未知项。
---

# iOS 硬编码检查

## 内容与核查报告（0.36.0，优先于下方历史脱敏说明）

先报告逐条内容及风险依据，再简述覆盖：候选编号、内容、文件与方法/偏移、已知用途线索、尚未确认事项、修复与复测。始终读取 client_identifier_review，finding_count=0 时也列出待核查 Key；不把标识存在说成已确认泄密，也不把普通服务器地址或接口路径直接说成漏洞。

用户要求具体内容或判断依据时，调用 export_report({scan_id,format:"markdown",include_sensitive_values:true})，提供本机文件链接。该文件包含本次捕获原值，权限 600；工具响应只返回路径。聊天默认仅给脱敏预览、位置和结论，完整密码、Token、私钥等在本机报告中供用户核对。JSON 报告也支持同一选项；字节材料用 hex 并标明编码，结构化记录用 JSON。检查 private_evidence.values_truncated、候选/标识截断和未捕获值，不能承诺列全未分析内容。旧扫描未保存原值时复用已有 artifact_id 重扫，不重复导入原包。

正常 get_scan_status、list_findings、read_evidence 和默认报告继续脱敏。不自动使用捕获凭证连接服务。不确定用途的项目明确标为待核查，不能升级为已确认漏洞。


1. 使用用户明确提供的 IPA 绝对路径或已有 iOS artifact_id，不自行选择其他业务包。调用 import_local_artifact 时 expected_platform=ios。
2. 调用 scan_ios_hardcoding，再用 get_scan_status 查询；只在 queued/running 时轮询。正常总状态仍为 partial。
3. 查看 ios_native_scan：组件路径与 Info.plist 声明、各 Mach-O 文件及架构切片、失败原因、section_gaps 和截断。slice 的 encrypted=true 或解析失败时为 blocked；不得把未分析的加密内容说成安全。files_checked 仅表示完成容器检查尝试，不代表所有切片成功。
4. 使用 list_findings/get_finding 获取候选及修复建议。当前 HC-001/002/003/004/006 只覆盖部分文本/资源和原生字符串模式；HC-005/007 等其他 iOS 规则尚未执行。候选不是漏洞，severity=needs_review。零候选不表示安全。
5. 原生证据含成员摘要、slice_index/slice_offset/slice_sha256、架构、分段、文件偏移和虚拟地址。对象图、Swift 小字符串、运行时解密、复杂原生数据流及真实用途未全面分析。static-deep 在基础扫描后追加有界原生引用和函数复核。
6. 有已知函数符号或 REA 返回的函数地址时，可调用 verify_ios_finding(scan_id,finding_id,procedure)。不要把字符串地址当作函数地址，也不要猜函数。工具通过独立 REA/Ghidra 分析所选未加密切片，核对摘要，返回函数范围、伪代码摘要及精确地址字符串引用情况。
7. function_body_recovered 只代表恢复了函数体；string_reference_observed=true 只代表返回的静态引用中有匹配。usage_confirmed=false，不等于已确认漏洞；false 也不证明没有使用。缺配置/引擎返回 blocked。复核写入任务 verifications。
8. 用户需要报告时调用 export_report，提供文件路径、包摘要、覆盖范围、阻塞项和建议。取消使用 cancel_scan。不执行包内程序、不发送提取凭证到外部服务、不输出完整秘密。

插件 0.6.0：资源/Mach-O 字符串基线与定点函数复核，尚非完整 iOS 安全审计。

## 修复前后对比（0.8.0）

用户提供修复前后包或两个扫描 ID 时，分别完成同平台扫描，再调用 `compare_scans({before_scan_id, after_scan_id})`。展示分组数量和两次 coverage 中的失败、跳过、截断与未执行规则。settings_match 只表示扫描设置一致，不代表覆盖完整。

still_detected 表示同规则/证据范围仍有候选，不证明秘密值相同；newly_detected 表示本次新增检出的组；not_redetected 只能描述为“本次未再检出，修复尚未确认”。匹配忽略重编译偏移，但路径、架构改变仍可能形成新旧两个组。不能把轮换成另一个硬编码值判为已修复，也不能把扫描失败或覆盖减少判为通过。需要具体修复建议时，通过对应 ID 调用 get_finding。

## HC-010 配置线索（0.11.0）

支持 HTTP(S)/WS(S) URL 中的私有 IPv4 网段与 IPv6 ULA 字面量，以及选定字段 debug/debugMode/enableDebug/debugEnabled/debuggable 的明确开启值。查看 evidence.method 区分 private_network_url 和 enabled_debug_flag。这些是发行配置复核线索，不等于凭证泄露、配置已生效或地址可达；合法局域网功能不能仅因私网地址判漏洞。不联网探测，不输出完整 URL。普通公网域名、回环、文档网段、关闭值不会触发本规则。其他调试数据、发行环境识别和实际用途仍未知，规则保持 partial。

## HC-011 联系人记录（0.12.0）

仅检查 JSON/plist 同一个对象中的明确姓名字段（如 full_name、contact_name、姓名）及邮箱/国际电话形状字段。不跨对象拼接，不据格式确认真实身份，record_authenticity 保持 unknown。证据只包含节点位置和固定数据类别，不复述姓名、邮箱、号码；用户需核实是否为真实数据、公开业务联系人或未识别的合成样本。已知占位值和示例域名会排除，但不代表所有测试数据均能识别。数据库、CSV、任意业务敏感数据及代码中记录重建未覆盖，规则为 partial。

## HC-012 标识清点（0.13.0）

从 get_scan_status 或 export_report 的 client_identifier_review 读取清点项，最多 100 条，检查 items_truncated。它们不计入 finding_count/list_findings，也不参与 compare_scans 候选分组。字段上下文仅用于区分 client_identifier 与 api_key_role_unknown，不能认定某个 API Key 是公开值或服务端秘密。权限、应用限制、提供方与误用均未验证，不得把清点项说成泄密漏洞，也不能因 findings 为零就说没有需要核查的标识。请求用户提供配置证据后再核查用途、权限、应用绑定和配额；不自动联网使用这些值。报告不输出原值。

## 编码字面量（0.16.0）

Mach-O 支持有限单层 Base64/Hex 文本还原：每切片默认最多 2000 次尝试、每候选最多 8192 字符，查看 slices[].literal_decoding 计数和 section_gaps。带前缀 base64:/hex: 或符合受限 Base64 形状的字符串才尝试。native_decoded_literal_only 的原始位置指向编码材料，transform 标记转换；这是启发式还原，不证明存在解码 API 调用。verify_ios_finding 可以恢复所选函数，但解码候选的 direct_literal_reference_applicable=false，不能把编码地址引用当作明文引用。加密切片仍不扫描、不解密，递归/自定义解码及 Swift 对象图未实现。

## 解码预算（0.17.0）

scan_ios_hardcoding 可传 ios_decode_attempt_limit，整数 1～20000，默认 2000，按切片独立计数。遇到 literal_decoding.skipped_budget > 0，可提高预算重扫同一 artifact_id；最多尝试一次提高预算的复扫，再报告剩余缺口。提高预算不会放宽全局时间、字节或字符串范围限制。核对 scan_options 与切片 literal_decoding.attempt_limit；旧报告缺少设置时不要猜默认值。compare_scans 会提示 scan_options_mismatch_or_missing，此时新增检出可能来自覆盖增加，不能判断包内容改变或修复效果。

## 扫描前能力检查（0.18.0）

先调用 get_analysis_capabilities({platform:"ios"})。Python available 表示探测脚本实际运行成功；located_not_executed 只表示找到可执行文件；REA configured_not_verified 只表示配置有效，不证明引擎可运行。缺少可选分析器时可继续支持范围内扫描，但必须解释缺口。static-deep 自动追加有界原生引用/函数复核，查看 deep_scan 和 effective_profile；完整用途判断仍未实现。能力检查不替代扫描报告中的目标实际覆盖。

## 证据和任务清理

使用 read_evidence(scan_id, evidence_id) 读取候选的脱敏证据和来源身份；不读取秘密原文。list_findings 支持 rule_id、severity、confidence 筛选，next_cursor 必须配合同样的筛选条件继续；结果更新后失效。next_cursor 为空仅表示当前列表读完，不代表全包已分析。
用户要求清理时，先取消正在运行的任务，再 delete_scan 删除已结束结果及导出报告；共享快照保留。delete_imported_artifact 在任何扫描仍引用快照时拒绝删除，需先清理所有相关扫描。复核/导出/创建和删除通过跨进程锁协调；忙时稍后重试。异常退出遗留锁会阻止操作，确认所有相关进程退出后由本机运维清理，不能自动猜测锁已失效。

SQLite 资源查看 sqlite_scan：支持普通未加密主数据库文件的列/行字段候选；每文件最多 1000 行、64 个 schema 条目、128 列，文本单元格最多 4096 UTF-8 字节。读取预算和跳过项必须报告；视图、生成列、BLOB、加密、WAL/日志及删除记录未分析。行序号为查询位置，不是稳定主键。

## 自动原生引用复核

profile=static-deep 会对原始 ELF/Mach-O 字面量自动校验成员/切片摘要和原文件偏移，再读取引用地址及所属函数。deep_native_limit 默认 2、最大 5 个去重字面量，与 DEX 阶段共享追加的 150 秒预算。先检查已知地址的偏移映射，失败时最多映射前 128 个提供方字符串地址，最多检查 32 个引用。iOS 使用切片内相对偏移，不用 FAT 容器偏移直接匹配。解码值、无映射或无函数引用保持未复核，不猜测附近函数。查看 eligible_native_literals、attempted_native_literals、recovered_functions、remaining_native_literals，以及 verifications 内 discovery 的证据链与截断标志。函数体恢复和静态字符串引用不证明安全用途或运行行为。

## 私钥格式解析

HC-006 的 key_validation.status=parsed_private_key 表示 Node/OpenSSL 成功创建私钥对象；报告仅包含算法和可用位数。支持 PEM 与 DER 的 PKCS1/PKCS8/SEC1，公钥/证书不作为私钥候选；无效材料与不支持格式仍有边界。加密 PEM、加密 DER 及 OpenSSH 包装可能仅记录未完成验证的线索，不能宣称已解密或证实密钥用途。查看 key_material_scan 的 parsed/public_material/unresolved/budget_skipped。每次扫描最多 32 次解析，每项 128 KiB、3 秒，遵守整体时间预算。PKCS12/JKS 容器及口令破解未实现；OpenSSH 单密钥 Ed25519/RSA/ECDSA 无口令材料现可解析，见下方说明。

## 嵌套归档与 OpenSSH

读取 nested_archive_scan：ZIP/JAR/APK/IPA/AAR 按后缀或 ZIP 魔数递归检查，最多两层归档、32 个归档、5000 个内部条目、每条目 8 MiB、累计发现读取 64 MiB、发现预算 10 秒，仍受全局预算限制。危险路径/重复条目/特殊文件/CRC 错误的归档不展开；超限和失败必须说明。证据保存 archive_chain 路径/摘要及 member_path，展示路径中的 !/ 仅是显示，不能据此猜测归档身份。归档路径脱敏后不能可靠提取时，独立复核保持未知。嵌套原生成员可以按记录链重新校验和复核；嵌套 DEX 独立 JADX 复核、嵌套 Android 二进制资源和 Java class 字节码尚未支持。

OpenSSH 单密钥未加密 Ed25519、RSA、ECDSA nistp256/384/521 可进行结构解析及公私钥一致性检查。加密容器只报告口令需求，不尝试口令；不支持的类型/多密钥包装保留未知状态。格式可解析不证明密钥用途、权限或安全强度。

共享数据目录的 POSIX 静态工作进程上限为 2；容量不足时任务可能 queued 后转 blocked，原因 global_scan_capacity_exceeded，表示未执行检测。不要删除 _capacity/scan-*.lock 来释放容量；锁由实际工作进程退出释放。宿主退出后仍存活的工作进程继续持槽，不能仅凭任务 failed 就删其结果/快照。REA 容量目前仍按进程限制，Windows 静态准入尚未支持。
