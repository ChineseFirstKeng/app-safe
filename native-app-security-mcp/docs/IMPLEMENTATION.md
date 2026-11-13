# 实施与验收记录

更新日期：2026-11-11。

## 当前任务

当前版本 0.5.0。A1/A2 核心链路已交付；B 已交付有界代码索引首版：JADX 方法、LLVM 原生函数/汇编及部分静态引用，可通过 MCP 和 CLI 查询。输入仍只有 APK/IPA，不需要源码。已增加 Android 显式导出入口的敏感 API 方法使用关联及有限 SSA 参数来源；Ghidra 原生伪代码已完成本机特定样本验收；真实 MobSF 和完整安全评估尚未验收。方案见 DESIGN.md，当前代码验收见 B-CODE-INDEX-VALIDATION.md；A2-VALIDATION.md 保留 0.2 历史。

## 阶段状态

| 阶段 | 状态 | 验收 |
| --- | --- | --- |
| 设计基线 | 已落盘 | 与本轮用户限定的双平台原生范围一致 |
| A1 导入与 MCP | 已通过当前主机验收 | 私有快照、完整成员读取/摘要、SQLite、CLI、真实 stdio |
| A2 MobSF 与报告 | 核心链路已交付，真实 MobSF 待验收 | 原十工具及新增代码查询、异步任务、取消/超时/重启、有限配置检查、证据和阶段报告；真实 AAPT2 正反例通过 |
| B 代码索引 | 有界首版及 Ghidra 本机样本已验收 | JADX 方法、LLVM 汇编、Ghidra 部分伪代码/字符串引用；十四工具与私有原值导出 |
| C 专项与 AI | Android 入口关联与有限 SSA 参数来源已验收；完整数据流与 AI 待实现 | 十组实际编译 APK 对照、真实 MCP 参数证据复核；仍仅攻击面，不确认漏洞 |
| D 运行与交付 | 待实现 | 未部署或修改客户端配置 |

## 环境记录

初始探测：macOS；PATH 中 python3 为 3.9.6；未定位到 uv、Docker、JADX、aapt2、Ghidra；/usr/bin/java 存在但尚未验证 JDK 能力。MCP SDK 当前主线要求 Python 3.11+，计划在工程内部准备隔离运行环境。依赖存在不等于已成功分析样本。

工程内已安装 uv 0.13.7、CPython 3.12.16、MCP SDK 2.3.0；依赖锁定在 uv.lock。Python 安装器初始创建的全局 python3.12 链接已核对目标后移除，保留工程内运行环境；后续安装使用 --no-bin。不修改客户端配置或 shell 配置。

进一步确认：SDK build-tools/36.0.0 下有实际 aapt2、D8、dexdump、apksigner；aapt2 2.20-13193326 已运行核验。Android platform android.jar 可用；NDK 28.2.13676358 已编译 arm64 ELF。系统 /usr/bin/java 与 java_home 无已注册运行时，但 Android Studio 自带完整 JBR/JDK 25.0.2，已实际编译运行索引程序。先前“无 Java Runtime”只对应系统注册状态。

JADX 1.5.6 已按 engines.lock.json 的大小与 SHA-256 安装至 .tools，并实际分析 DEX。Xcode clang、swiftc 和 iPhoneOS SDK 26.5 已编译 Objective-C App/Swift Framework；Apple LLVM 21.0.0 已实际索引 ELF/Mach-O。Ghidra 12.2 官方包在用户授权的 proxy enable 下下载并完整校验，成功后 proxy disable，确认代理未开启。补齐发行包缺失的 macOS arm64 反编译辅助程序后，实际样本恢复伪代码及字符串引用通过。下载、构建与验证记录见 B3-GHIDRA-VALIDATION.md。Docker 未定位，MobSF 未配置。

## 已实现范围

- 文件从打开的普通文件描述符复制为权限 600 快照，计算 SHA-256，检查复制时源变化。
- ZIP 中央目录先做预算检查；完整读取各成员校验 CRC 和 SHA-256；不解出成员到任意路径。
- 拒绝路径穿越、绝对路径、控制字符、重复条目、文件目录冲突、符号链接、加密归档条目、多盘及当前不支持的 ZIP64 中央目录、超预算条目。
- 同包导入去重、并发去重、快照篡改核对、SQLite 分页与跨实例读取。结构识别不证明 APK/IPA 可安装；Mach-O 魔数仅作候选识别。
- 可识别本期范围外的部分 Flutter/RN/Unity 文件标记，不把标记缺失当作原生业务已证明。
- 十四个 MCP 工具通过官方 SDK 实际子进程通信，覆盖导入、任务、分页、详情、证据、代码查询、引用、私有导出和报告。
- MobSF 本机同步 REST：流式上传、上传与报告身份校验、拒绝重定向/远程 URL、响应预算、原始 HTTP 响应受限保存；错误不回显凭证或提供方错误原文。
- baseline CLI 对缺配置保存 blocked 回执；收到报告仍标记评估未完成，不做漏洞真实性承诺。
- SQLite 任务和结果原子发布，内核锁保证每目录一个控制器，最多两个工作进程，排队上限 16。只终止持有的进程组；工作进程检测父进程消失并退出。重启撤销旧发布权限，运行任务 interrupted、排队任务重新调度。
- 完整任务硬超时、排队/运行取消、会话关闭与结果检查点；工作进程发布终态后终止其整个所属进程组，实际测试确认辅助进程不会随正常完成遗留。持久化任务结果是终态依据，工作进程有意通过进程组信号退出。本机取消不代表停止 MobSF 服务端任务。
- Android 实际 aapt2 解码、命令输出与版本留证，检查显式调试、明文流量、导出组件、scheme、备份声明；无法还原的配置值标记 partial。
- iOS App/Extension Info.plist 检查 ATS、URL scheme 与文件共享声明；Framework/资源 bundle 配置只作清点，不误当宿主配置。超预算和损坏项单列。
- MobSF 已识别代码/Manifest/原生候选结构的有界投影；info/secure 属于观察，其他命中仅为未复核候选。未知结构与投影限制单列。
- 证据引用、包/成员/输出摘要重新校验，报告拒绝被篡改来源；默认脱敏且保留非秘密配置可读，原值只进本机核查文件；Markdown 对目标内容转义。

- 代码索引直接恢复包内 DEX、ELF、Mach-O：方法完整签名区分重载，原生切片保留架构/子类型、加密状态和摘要；加密切片不交给引擎。每任务最多 4 DEX/4 原生切片，超预算与失败单列。
- JADX 返回部分 Java 表达及静态方法使用引用；LLVM 返回有符号函数的汇编与部分直接引用。间接/外部目标保持未知，无可用指令偏移则 null，不把汇编当伪代码。
- 代码单位与关系原子发布，包/成员/切片/引擎/适配器摘要留证；读取前重核原始索引与代码身份。普通代码遮盖字面量、数字与注释；原值仅权限 600 的本机 JSON。CLI 增加 symbols/code/references/export-code。

- Android 入口关联：从显式导出且未明确禁用的组件匹配完整回调签名，沿部分方法使用关系寻找敏感 API；结果是静态推断的 surface，不是漏洞 finding。派生证据同时绑定 Manifest、DEX 索引及规则适配器摘要；读取与导出重验依赖。

## 当前验收

命令：`.venv/bin/python scripts/acceptance.py`。

2026-11-11：66 项测试通过，0 失败、0 错误、0 跳过。记录位于 runtime/validation/acceptance.json、acceptance.log。包含真实 stdio 全链路、CLI、独立工作进程、取消、真实硬超时、队列恢复、控制器锁、撤销旧发布、归档与证据完整性、脱敏、报告转义、配置正反例及受控 HTTP。基础历史范围见 A2-VALIDATION.md，新增代码范围见 B-CODE-INDEX-VALIDATION.md。

另行执行 `.venv/bin/python scripts/verify_android_manifest.py`：实际 aapt2 link 编译正反例，正例命中 AND-CONFIG-001/002，反例不命中；任务和阶段报告通过。记录与报告路径见 runtime/android-manifest-verification/summary.json。第一次实际验收发现当前 aapt2 使用完整 namespace 和可读布尔格式，已修正并补回归；不能只靠手写旧格式断言解析可用。

上述 Manifest 正反例仅为配置样本。新增 `.venv/bin/python scripts/verify_code_index.py` 实际编译 Java→DEX、Android ELF、Objective-C App 和 Swift Framework，组装 APK/IPA 并交给真实 JADX/LLVM 分析。当前 APK 恢复 5 个方法、8 个 ELF 函数、5 条部分静态关系；IPA 恢复 91 个函数、199 条部分静态关系。计数含编译器生成函数，不等于业务覆盖或漏洞数量。记录 runtime/code-index-verification/summary.json。

`.venv/bin/python scripts/verify_mcp_code.py` 通过真实 stdio 发现十四工具，完成编译 APK 的导入、任务、方法查询、脱敏代码、引用、原值导出和报告；记录 runtime/mcp-code-verification/summary.json。四项新增 CLI 命令实际核验，原值文件权限 600；0.5.0 wheel 已构建且包含 Android 入口关联模块与两个 Java 导出脚本。

所有样本只编译与静态解析，未运行目标、未访问包内地址。受控 HTTP 不是真实 MobSF；Ghidra 已在特定原生样本运行，报告仍为实际覆盖内的 partial。Kotlin 业务和大型多 DEX 尚无独立实际验收。新增实际 stripped ELF/Mach-O、arm64/arm64e fat 与 Extension 载体验证已通过 LLVM：剥离样本明确返回未恢复节点，fat 与 Extension 恢复 18 个函数；仅静态载体，不证明 Extension 安装/功能。记录 runtime/native-variants-verification-llvm/summary.json。与 REA 未进行质量对比，不能宣称更优。

Android 十组实际编译对照及 MCP 入口/参数追踪已通过，记录 runtime/android-review-verification/summary.json、runtime/mcp-review-verification/summary.json；外部输入与常量 URL 均只列攻击面，未导出与 disabled 不生成该关联；原始来源篡改会阻止派生证据及报告通过。0.4 历史见 C-ANDROID-ENTRY-VALIDATION.md，0.5 当前验收见 C2-ANDROID-SSA-VALIDATION.md。

0.4 引擎安装增加分段续传：只解析一次官方资产 URL，后续直接从官方 CDN 获取，核对精确 Content-Range 与最终完整 SHA-256；避免逐片消耗 GitHub API 请求额度。受控 HTTP 验证续传、服务器忽略 Range、错误摘要与非官方源拒绝。早期 Ghidra 续传受 CDN 超时影响；随后按用户要求使用 proxy enable 完成并校验整个归档，立即关闭代理，再离线编译本机依赖及运行验收。历史见 B2，当前结果见 B3-GHIDRA-VALIDATION.md。

## 已知缺口与下一步

1. 配置并验收本机 MobSF 同步服务；当前 Docker 不在 PATH、MobSF 未配置，无法完成真实引擎验收。适配器仍可独立开发测试，不伪造引擎成功。
2. 扩大 Ghidra 的 Swift、复杂 C++ 与真实应用覆盖，补充按入口优先索引、按需恢复和大型多 DEX 验证；当前仅在特定 C/ObjC 剥离符号、多架构与 Extension 载体上确认伪代码链路。
3. 扩展 Android 已有 SSA 参数来源：方法返回值、字段/数组、保护条件与库函数语义；接入 ObjC/Swift 入口关联，再实现风险调查与 AI 闭环。当前局部定义关系不等于完整数据流、可达性或可利用性证明。
4. 解析器容器隔离、内存/CPU 总预算、版本比较、AI 调查与更完整代码覆盖仍需实现。

导入仍采用进程内有界线程，单 MCP 进程一次导入；取消导入会等待该线程结束后释放准入，不宣称立即终止导入解析器。异步分析已有独立进程硬超时，但不等于所有资源均已隔离。SQLite/快照仅作本机私有存储，未覆盖管理员或同账户恶意并发篡改的所有竞态。

## 接续要求

每一步执行后更新本文件，记录命令、结果、能力边界和下一项。真实安装包只作用户授权的本地离线检查，测试产物不提交。不将 Flutter 样本的清点结果记为原生业务分析成功。

## 0.5 参数来源补充

已实际在 JADX SSATransform 后、MoveInlineVisitor 前捕获调用和有界定义关系。精确同 DEX 调用按参数位置及调用位置绑定；赋值覆盖不会仅因同方法存在 Intent 读取而误判来源，两个 helper 调用和 PHI 合流分别保留。未知函数返回值不自动继承参数来源，非精确派发不强行贯通；内部构造 Intent 的读取不当作外部控制证明。

十组实际编译样本覆盖 external/private/disabled/constant/overwrite/mixed/merge/unknown/non_exact/internal_intent；当前均不生成代码风险 finding。66 项基础测试及原 APK/IPA 索引回归通过，真实 MCP 读取参数证据、代码/引用及报告通过。报告明确 partial_android_ssa_argument_origins，完整数据流仍未完成；iOS 参数来源未实现。

来源图复制、调用上下文及派生输出均有预算，防止共享 SSA 来源在多层合流中指数展开。源文件依赖摘要校验继续生效；源码、常量及代码 IR 只来自包内 DEX，不增加源码入参。

## Ghidra 依赖解除阻塞

完整归档 569712708 字节、SHA-256 与 engines.lock.json 一致；代理下载成功后已关闭，后续步骤未使用下载代理。官方发行包缺失 mac_arm_64/decompile，已新增 build_ghidra_native.py，以归档内核对过的 231 个源文件及 Makefile 在工程内构建，不下载 Gradle、不改全局设置。

三组原生样本实际验收通过：stripped.apk 15 个函数/15 份正文，stripped.ipa 3/3，fat-extension.ipa 27/27；已核对字符串及其函数引用、切片身份、相同地址隔离和报告导出。Ghidra 的入口命名为 entry，验证已适配该命名。计数包括桩及编译器代码，不是漏洞数。详见 B3-GHIDRA-VALIDATION.md。

## XHome 大型原生 APK 实测（2026-11-11）

用户提供 `XHome_5.4.0.1109_97_1109_TEST_debug.apk`，313449237 字节，SHA-256 `2e3f952436a47ac17bd4e42b54053fc107fe192b2d0d88d569fa23467fdc4151`。真实 MCP SDK stdio 驱动导入、默认异步分析、读取全部结果/证据、代码查询与 Markdown/JSON 导出，源码摘要前后未变；没有调用 REA、MobSF 或另一个扫描器，没有执行目标或访问包内 URL。

- 命令：在 `runtime/evaluation-xhome-5.4.0.1109-20261111-160339` 执行 `../../.venv/bin/python run_mcp.py`，随后 `check_business_queries.py` 与 `build_report.py`。数据与脚本仅本机私有目录，不提交。
- 分析 `an_08a70f5b14974f3b831f5d4fcd4208a9`，客户端耗时 92.239 秒，48 次非状态 MCP 工具调用、10 次轮询；另有 3 次只读业务检索。终态 partial，MobSF 未配置。没有附加 40 次调用上限。
- 完整清点 6415 成员、38 DEX、71 ELF，framework_indicators=[]；不能把标记为空当成对全部框架的完整排除。
- 输出 1 项 needs_review：实际 Manifest debuggable=true；这是 TEST/debug 包，应按测试用途解释，不作生产漏洞确认。另有 14 项导出声明、2 项 scheme 声明和 12 项普通观察。
- 默认仅处理 classes.dex/classes10.dex/classes11.dex/classes12.dex；四个 DEX 引擎共报告 90669 方法，索引 8000，正文 1247。34 个 DEX 因数量上限省略。索引内 com.sdmc.* 方法 5578 个，仅 190 个有正文；两类登录查询的首 100 条及指定 SecuritySummaryActivity.onNewIntent 无正文。
- 入口检查见到 14 个显式导出入口、索引到 4 个回调，恢复 0 路径，data_flow=not_run_no_entry_paths；记录 alias/继承回调/跨 DEX 等缺口，不认定安全。
- Ghidra 索引 4 原生切片，其余 67 个因数量上限省略；libCHIPController 的自动分析超时后仅导出部分结果。DebugProbesKt.bin 的 Mach-O 魔数候选解析失败不算漏洞。
- 29 条结果所引用证据均通过实际 MCP read_evidence 校验，原始两类导出哈希、输入及源码摘要、报告本地链接均复核。额外符号查询与自动发现分开记录，不回填人工发现。
- 用户报告：[XHome MCP 实测报告](../reports/XHome-5.4.0.1109-MCP静态安全评估报告.md)。原始回执、证据和覆盖统计在该报告链接的私有运行目录。

本次实测未达到业务安全评估目标，不能以链路可运行代替质量验收。后续应优先实现全包符号清点与跨 DEX 关联、入口/风险优先及按需正文恢复，随后补充专项调查和业务证据报告；仅扩大前几个 DEX 的数量预算不足以解决此问题。此前原生编译样本验收结果不等于大型真实原生应用验收通过。

## 同一 XHome APK 的 REA 独立调查（2026-11-11）

按用户要求另外使用 reverse-engineer-anything Skill 调查同一个 SHA-256 样本；没有把 MCP 的结果当作安全事实来源，没有修改扫描器或向自动结果回填手工发现，也没有沿用此前人为调用上限。REA 配合 DEX/资源格式解析、apksigner 与系统 CommonCrypto 离线计算；未执行目标、访问包内服务或验证凭据。

- 保留 201 条实际成功 REA Evidence：126 方法、62 类、9 引用、2 类名搜索、1 package、1 summary view。完整导出按主调查/入口/网络/密码存储分别保存，合并索引保留原路径与摘要，不伪装成另一个工具的发现。
- 直接解析全部 38 DEX 的 Retrofit 方法注解，恢复 855 条声明、415 个去重 HTTP 方法/路径组合；全部路径 span/成员哈希已核对。声明不证明调用/服务器在线/越权。
- 确认内置 AES 包装配置能离线恢复为合法 JSON；原始解密字节与格式化 JSON 分开留存和计算摘要，秘密原值只在本机 0600 文件。普通报告只给环境与字段结构。
- 具体代码/资源事实包括：access/refresh token 普通私有偏好直写、默认业务 AES 固定 IV、已启用调试头/正文采集、NSC base-config 明文许可、FileProvider root-path 过宽、WebView 混合内容、TEST/debug 验签恒真；导出 CHIP 解析异常为未运行的静态候选。
- 保留 Root 检测、登出清理、token/refresh、Cedar scope 与禁止重定向、媒体 canonical 目录/大小限制、MQTT 证书配置等反证；不把测试包结论推广到 release，不宣称账号/设备/支付/后台已被攻破。
- 报告：[XHome REA 静态报告](../reports/XHome-5.4.0.1109-REA静态安全评估报告.md)；附录：[HTTP 声明](../reports/XHome-5.4.0.1109-REA接口声明附录.md)。来源在 `runtime/evaluation-xhome-5.4.0.1109-20261111-160339/rea`。

这些是 REA 定向调查加本地静态辅助的结果，不是 0.5.0 MCP 已实现能力，也不是全包安全问题穷尽清单。匿名类歧义、部分协程表达、完整参数数据流、71 个原生库与后台行为仍有缺口。
