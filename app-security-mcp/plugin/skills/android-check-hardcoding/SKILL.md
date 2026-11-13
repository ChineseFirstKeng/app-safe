---
name: android:check-hardcoding
description: 检查 android 安装包的硬编码安全候选。接收 APK，覆盖资源、DEX 常量及 ELF 原生字符串、受限解码与 JNI 导出线索，必须说明 partial、未验证用途和未覆盖代码。
---

# android 硬编码检查

## 内容与核查报告（0.36.0，优先于下方历史脱敏说明）

先报告逐条内容及风险依据，再简述覆盖：候选编号、内容、文件与方法/偏移、已知用途线索、尚未确认事项、修复与复测。始终读取 client_identifier_review，finding_count=0 时也列出待核查 Key；不把标识存在说成已确认泄密，也不把普通服务器地址或接口路径直接说成漏洞。

用户要求具体内容或判断依据时，调用 export_report({scan_id,format:"markdown",include_sensitive_values:true})，提供本机文件链接。该文件包含本次捕获原值，权限 600；工具响应只返回路径。聊天默认仅给脱敏预览、位置和结论，完整密码、Token、私钥等在本机报告中供用户核对。JSON 报告也支持同一选项；字节材料用 hex 并标明编码，结构化记录用 JSON。检查 private_evidence.values_truncated、候选/标识截断和未捕获值，不能承诺列全未分析内容。旧扫描未保存原值时复用已有 artifact_id 重扫，不重复导入原包。

正常 get_scan_status、list_findings、read_evidence 和默认报告继续脱敏。不自动使用捕获凭证连接服务。不确定用途的项目明确标为待核查，不能升级为已确认漏洞。


1. 使用用户明确提供的 APK 绝对路径或该平台已有 artifact_id，不自行选择其他安装包。
2. 需要导入时调用 import_local_artifact，expected_platform 使用 android。
3. 调用 scan_android_hardcoding，用返回的 scan_id 查询 get_scan_status。只在 queued/running 时适度轮询，终态停止。
4. 当前仅扫描支持的资源，正常终态为 partial。使用 list_findings 分页读取候选，get_finding 查看脱敏证据、未知项、修复和复测建议。
5. HC-001/002/003/004/006 覆盖部分资源和 DEX 模式；DEX 分析方法体后另执行 HC-005/007 的固定密钥/IV 参数规则和 HC-008 的受限 PBEKeySpec 固定盐规则，HC-009/010/011 提供受限分支/配置/记录规则，HC-012 为单独标识清点，具体状态以 rules 为准。Android 二进制 XML、资源表通过本机 AAPT2 解码，查看 resource_scan.android_resources 的成功数和 failures；缺依赖、超时与格式错误都属于覆盖缺口。查看 dex_scan 的文件数、failures、methods_without_flow 和 methods_skipped_limit。DEX 支持标准字符串池、静态字符串字段及部分直线指令：赋值、拼接、字节数组和已知参数调用；含分支的方法不传播值，未知指令清空传播状态。原生指令用途、Flutter Dart AOT 语义、跨方法传播、任意解码、嵌套归档和运行用途未分析；资源引用只支持直接字符串，不完整解析引用链。static-deep 也不代表执行了深度分析。
6. 候选不是已确认漏洞；severity=needs_review 表示待判断风险。finding_count 为零不表示全包安全，为 null 表示检测尚未完成。findings_truncated 表示数量达到上限。
7. 对有类、方法和原型的 DEX 候选，可调用 verify_android_finding 做独立 REA 方法身份与方法体复核。缺配置/依赖会 blocked；method_body_recovered 只代表恢复了方法体，usage_confirmed=false，不能据此升级成漏洞。结果写入任务 verifications，可随报告导出。
8. 用户要求报告时调用 export_report，并提供生成的文件路径。取消使用 cancel_scan，已结束时说明实际终态。
9. 报告原包摘要、平台、任务状态、已完成覆盖和缺口。不执行包内程序，不发送提取凭证到外部服务，不输出完整秘密，不用模型猜测填充证据。

本 Skill 随 app-security 插件分发。插件 0.5.0 增加 DEX 基础检测与独立 REA 定点复核；深度数据流及运行验证留待后续。

## Android 原生补充（0.7.0）

- 查看 android_native_scan，逐库检查 ABI 与路径是否一致、failures/gaps、files_omitted。覆盖已分配非执行区的 ASCII 字符串及单层 Base64/显式 Hex 解码，解码预算触顶为缺口。未完整恢复 Unicode 原生字符串、XOR/自定义解码或 Flutter 业务语义。
- jni_exports 只是动态符号表中可见的 Java_* / JNI_OnLoad 线索，不证明 JNI 调用、动态注册或权限问题。jni_symbol_status 缺表时不能把零导出解释为没有 JNI。
- ELF 候选有已知函数符号或提供方返回的函数地址时，使用 verify_android_native_finding(scan_id,finding_id,procedure)，不要用字符串地址猜函数。原有 verify_android_finding 仍只用于 DEX。
- 原生复核恢复函数体，并通过提供器地址映射到原始 ELF 文件偏移核对静态字符串引用（0.9.0）。读取 reference_mapping 的 status、checked、failed、truncated 和 matches/evidence_id；每次最多映射 32 个返回的唯一地址。映射必须校验二进制摘要和提供器身份，失败保持未知，不猜装载偏移。usage_confirmed=false；解码后的值不当作直接引用，false 不证明没有使用。

## 修复前后对比（0.8.0）

用户提供修复前后包或两个扫描 ID 时，分别完成同平台扫描，再调用 `compare_scans({before_scan_id, after_scan_id})`。展示分组数量和两次 coverage 中的失败、跳过、截断与未执行规则。settings_match 只表示扫描设置一致，不代表覆盖完整。

still_detected 表示同规则/证据范围仍有候选，不证明秘密值相同；newly_detected 表示本次新增检出的组；not_redetected 只能描述为“本次未再检出，修复尚未确认”。匹配忽略重编译偏移，但路径、架构改变仍可能形成新旧两个组。不能把轮换成另一个硬编码值判为已修复，也不能把扫描失败或覆盖减少判为通过。需要具体修复建议时，通过对应 ID 调用 get_finding。

## HC-008 固定派生盐（0.10.0）

仅识别 Android DEX 受限直线代码中的 PBEKeySpec 三参数/四参数构造调用：非空常量字节盐、已知正迭代次数及适用时已知正密钥长度。证据记录 salt_length、iteration_count、key_length_bits、调用方法和偏移，不输出盐/口令。它不证明实际 KDF 执行或跨用户复用，也不评价迭代次数是否足够。盐无需保密，不能建议仅将固定盐换成另一个固定值。iOS、其他派生 API、分支/跨函数及未知参数仍未覆盖。

## HC-010 配置线索（0.11.0）

支持 HTTP(S)/WS(S) URL 中的私有 IPv4 网段与 IPv6 ULA 字面量，以及选定字段 debug/debugMode/enableDebug/debugEnabled/debuggable 的明确开启值。查看 evidence.method 区分 private_network_url 和 enabled_debug_flag。这些是发行配置复核线索，不等于凭证泄露、配置已生效或地址可达；合法局域网功能不能仅因私网地址判漏洞。不联网探测，不输出完整 URL。普通公网域名、回环、文档网段、关闭值不会触发本规则。其他调试数据、发行环境识别和实际用途仍未知，规则保持 partial。

## HC-011 联系人记录（0.12.0）

仅检查 JSON/plist 同一个对象中的明确姓名字段（如 full_name、contact_name、姓名）及邮箱/国际电话形状字段。不跨对象拼接，不据格式确认真实身份，record_authenticity 保持 unknown。证据只包含节点位置和固定数据类别，不复述姓名、邮箱、号码；用户需核实是否为真实数据、公开业务联系人或未识别的合成样本。已知占位值和示例域名会排除，但不代表所有测试数据均能识别。数据库、CSV、任意业务敏感数据及代码中记录重建未覆盖，规则为 partial。

## HC-012 标识清点（0.13.0）

从 get_scan_status 或 export_report 的 client_identifier_review 读取清点项，最多 100 条，检查 items_truncated。它们不计入 finding_count/list_findings，也不参与 compare_scans 候选分组。字段上下文仅用于区分 client_identifier 与 api_key_role_unknown，不能认定某个 API Key 是公开值或服务端秘密。权限、应用限制、提供方与误用均未验证，不得把清点项说成泄密漏洞，也不能因 findings 为零就说没有需要核查的标识。请求用户提供配置证据后再核查用途、权限、应用绑定和配额；不自动联网使用这些值。报告不输出原值。

## HC-009 固定比较分支（0.14.0）

仅在选定认证命名方法（check/verify/validate/authenticate + password/pin/otp/passcode/verificationcode）中，识别方法入口直线前缀的常量字符串与参数 String.equals 比较，结果直接控制唯一向前 if-eqz/if-nez 分支。证据包括比较和分支偏移、目标偏移及 selection_basis=authentication_method_name_hint。名称只是筛选线索，security_purpose=unknown，不得称为已确认后门、万能验证码或绕过。分支两侧行为、成功方向和服务端复核未知。遇到其他控制流、未知调用或覆盖则停止该模式判断；整数验证码、混淆命名、return-only 和 iOS 尚未覆盖。原有其他规则依然不做一般分支传播。

## DEX Base64 常量还原（0.15.0）

受限直线指令中支持 java.util.Base64.getDecoder().decode(String)，以及 android.util.Base64.decode(String,int) 的已知 flags 0/2。输入须为已恢复的常量字符串，最多 8192 字符，仅一层；URL-safe/MIME、byte[] 重载、未知 flags、自定义解码仍不支持。结果可供已有密钥/IV/盐参数规则使用，UTF-8 文本可进入已有模式检测。读取 dex_scan.constant_decode_attempts/recovered/unresolved；这些计数仅覆盖实际分析到的调用，不包含未解析方法。证据 transform、decode_file_offset、decode_code_unit_offset 标记来源，调用位置仍在原 evidence.file_offset；不输出编码值或还原值，不据静态还原声称已执行或可利用。

## 扫描前能力检查（0.18.0）

先调用 get_analysis_capabilities({platform:"android"})。Python available 表示探测脚本实际运行成功；located_not_executed 只表示找到可执行文件；REA configured_not_verified 只表示配置有效，不证明引擎可运行。缺少可选分析器时可继续支持范围内扫描，但必须解释缺口。static-deep 自动追加有界 DEX 方法身份/方法体复核，查看 deep_scan 和 effective_profile；完整用途分析仍未实现，其他定点复核使用 verify 工具。能力检查不替代扫描报告中的目标实际覆盖。

## GCM 固定 Nonce（0.19.0）

HC-007 增加 GCMParameterSpec 的整数组与已知有效切片构造方式。evidence.usage=constant_nonce_to_GCMParameterSpec，记录 nonce_length、tag_length_bits 和 source_array_offset，保留 Base64 来源。构造参数常量不证明用于加密或同一密钥下复用，encryption_use/same_key_nonce_reuse 保持 unknown；解密和测试向量需要单独核实。通过 get_finding 查看用途核查、修复与复测建议，不把 Nonce 说成秘密。未知参数、分支、随机填充后的数组及跨方法来源不推断。

## 密钥与 IV 数组切片（0.20.0）

SecretKeySpec/IvParameterSpec 仅识别精确构造签名和非空已知字节范围。查看 material_length、source_array_offset、source_array_length；它们分别是实际选用长度、数组起点和原数组长度。Base64 来源仍保留。SecretKeySpec 算法必须是已知字符串，但不评估提供方是否接受算法或长度；provider_acceptance/runtime_use 为 unknown。空值、未知参数或无效切片不会作为此类候选，不代表相关代码安全。

## 显式 UTF-8 字节传播（0.21.0）

支持常量 String.getBytes("UTF-8"/"utf8")、StandardCharsets.UTF_8 及对应 Charset.forName。后续密码参数候选记录 transform=string_getbytes_utf8、编码指令位置和 encoded_length；按字节而非字符计算长度。输入及输出上限均为 8192，其他字符集、未知输入、非法 Unicode 不推断。该来源标记不证明后续业务使用或漏洞。

## 字节数组复制（0.22.0）

支持 Arrays.copyOf/copyOfRange 的 byte[] 重载，已知常量经过截取或补零后继续传播到支持的密码参数。array_copy_steps 记录最多 8 步的调用位置、输入输出长度、from/to 和补零数量；transform 保留原 Base64/UTF-8 来源，无转换来源时为 constant_array_copy。输入输出均限 8192 字节，未知参数和无效范围不推断。复制并不消除硬编码风险，也不证明材料实际用于加密；依据 get_finding 的用途核查和修复建议复核。

## 字节到 UTF-8 字符串（0.23.0）

支持 new String(byte[], UTF-8字符集/名称) 及带 offset/length 的对应构造方式。已知数组可来自受支持的 Base64 或数组复制。候选证据 usage=constant_utf8_string_constructor，保留原转换来源并增加 string_constructor_file_offset、string_byte_offset、string_byte_length；还原对象写入字段时保留这些证据。源数组最多 8192 字节，仅严格 UTF-8，未知/非法输入不推断。对象的所有后续方法、默认字符集构造、跨方法与运行用途未全面支持；同一材料在多个阶段检出不等于多个独立凭证。

## 静态方法固定返回值（0.24.0）

支持同一 DEX 内 static 无参 String 方法，仅忽略 nop 后恰好 const-string 与对应 return-object 两条指令。按完整类/方法/原型匹配 invoke-static，最多 10000 个摘要。证据含 callee_* 和 caller_invoke_* 位置；dex_scan 提供 constant_method_summaries、constant_method_returns_propagated，达到摘要上限时 method_summaries_truncated=true。目前可继续用于字段赋值及无参 getBytes 后的密码参数检查；其他后续字符串操作未全面适配。跨 DEX、递归、包装方法、参数传播、分支和实例方法不推断，不能称为完整跨方法数据流。调用时保守清除其他寄存器，避免推断被类初始化影响的旧状态。

## 静态包装调用（0.25.0）

在 0.24.0 基础上，支持同 DEX 最多 4 层静态无参 String 包装方法，每层忽略 nop 后只能 invoke-static、move-result-object、return-object，返回寄存器须一致。return_chain 逐层记录方法及位置，wrapper_depth 为包装层数；叶子仍须直接返回固定字符串。递归、缺失目标、超深和额外操作不推断，constant_method_summaries_unresolved 统计未解决的已收集摘要，不代表所有不支持的方法数量。仍不支持跨 DEX、带参数、实例或分支方法。

## 返回值与转换衔接（0.26.0）

受支持的方法返回值及 UTF-8 还原字符串可接入显式 UTF-8 getBytes、Java 基础 Base64 和 Android Base64 flags=0/2。转换后的 transform 标识最后转换，return_chain、caller_invoke_* 及编码/解码位置继续保留。已有 Base64 解码来源的字符串不再进行第二次解码。摘要调用时仅保留已识别的不可变字符集/基础解码器标记，其他旧寄存器仍清除。参数传播、跨 DEX、其他字符集与任意解码链仍未实现。

## 证据和任务清理

使用 read_evidence(scan_id, evidence_id) 读取候选的脱敏证据和来源身份；不读取秘密原文。list_findings 支持 rule_id、severity、confidence 筛选，next_cursor 必须配合同样的筛选条件继续；结果更新后失效。next_cursor 为空仅表示当前列表读完，不代表全包已分析。
用户要求清理时，先取消正在运行的任务，再 delete_scan 删除已结束结果及导出报告；共享快照保留。delete_imported_artifact 在任何扫描仍引用快照时拒绝删除，需先清理所有相关扫描。复核/导出/创建和删除通过跨进程锁协调；忙时稍后重试。异常退出遗留锁会阻止操作，确认所有相关进程退出后由本机运维清理，不能自动猜测锁已失效。

SQLite 资源查看 sqlite_scan：支持普通未加密主数据库文件的列/行字段候选；每文件最多 1000 行、64 个 schema 条目、128 列，文本单元格最多 4096 UTF-8 字节。读取预算和跳过项必须报告；视图、生成列、BLOB、加密、WAL/日志及删除记录未分析。行序号为查询位置，不是稳定主键。

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
