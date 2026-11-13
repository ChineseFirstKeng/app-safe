# Android 与 iOS 原生静态安全分析 MCP 设计

日期：2026-11-11。状态：实施基线，功能完成情况以 IMPLEMENTATION.md 为准。与 REA 的比较必须遵守 REA-COMPARISON.md；尚无证据证明本项目报告更优。

## 目标与范围

用户提交 APK 或 IPA 后，服务端自动清点组件、执行基础扫描、建立代码索引、发现攻击面、定点追踪并输出可核查报告。固定检查由程序执行，Skill 说明使用方式，AI 根据证据补充调查。目标是在移动安装包评估任务上的自动化、稳定性、可追溯性和复测效率优于人工调度通用逆向工具；是否优于 REA 必须用相同样本、任务和预算比较。

Android 支持 Java/Kotlin DEX 及随包 ELF；iOS 支持 Objective-C/Swift、App、Framework、Extension 与 Mach-O 多架构切片。Flutter、React Native、Unity 等非本期框架只做识别和覆盖声明，不宣称恢复其业务语义。Android JNI 跨语言、完整跨函数数据流、Objective-C/Swift 间接调用精确建模属于后续增强。

全程不执行应用、不登录账号、不连接设备、不访问包内域名。服务端对象鉴权、OAuth 绑定、MQTT ACL、云权限、支付校验的实际有效性均须另行验证。

## 技术架构

| 部分 | 选择 | 职责 |
| --- | --- | --- |
| MCP 与编排 | Python、官方 MCP SDK | stdio、任务提交、分页、证据、报告 |
| 状态与索引 | SQLite | 任务、事实、关系、覆盖、恢复 |
| 大文件与原始产物 | 本机内容寻址目录 | 原始快照、引擎结果、报告 |
| 基础扫描 | 独立 MobSF 服务/容器 | 双平台基线扫描 |
| Android 代码 | JADX、自有 Java 索引程序 | 方法、常量、引用、指令与反编译 |
| 二进制结构 | LIEF 或有界格式解析 | ELF/Mach-O 结构、切片、地址映射 |
| 原生追踪 | LLVM llvm-objdump；Ghidra headless、自有导出脚本 | 已验证 LLVM 符号/汇编和部分直接引用；Ghidra 函数/伪代码为后续验收能力 |
| 规则 | 自有 Python 分析器 | 外部入口、网络、认证、存储、密码、WebView |
| AI | 显式配置的模型服务 | 查询证据、提出假设、申请定点追查 |
| 隔离 | worker 容器与进程监督 | 时间/内存/输出限制、取消、网络边界 |

首版单机本地 stdio，不引入图数据库、向量数据库或集群。远程上传、认证及租户隔离另行设计；远程路径不能当作本地路径使用。

## 固定执行流程

1. 导入：快照、SHA-256、实际类型、ZIP 完整性和预算检查。
2. 清点：组件、架构、配置、代码载体、框架检测；逐个记录未覆盖内容。
3. 规划：按实际组件生成任务，固定检查独立于漏洞候选执行。
4. MobSF：upload → scan → report_json；保留原始结果及其扫描器判断身份。
5. 索引：DEX 方法/字段/引用，ELF/Mach-O 切片、符号、字符串、函数；失败单列。
6. 专项分析：从入口或敏感操作选择追查对象，执行有界静态分析。
7. AI 调查：基于明确问题和预算查询工具，保存支持、反证和缺口。
8. 导出：核对证据身份和结论强度，生成 Markdown、JSON、证据索引。

模型或某个引擎不可用时保留独立阶段结果。任务结束状态与代码覆盖状态分开表达；0 个候选不表示安全。

## Android 分析

Manifest 检查包信息、SDK、权限、组件、导出与权限保护、Intent filter、Deep Link、备份、调试、明文流量及网络安全配置。默认值按平台模型解释，autoVerify 只证明声明，不证明运行时验证成功。

JADX 索引导出类、完整方法签名、字段、常量、引用、调用、反编译文本及可用的指令位置。反编译失败保留失败记录和可用指令，不把生成 Java 行号当作原始源码行号。每包一次索引，后续查询复用。

随包 ELF 按 ABI 清点。基于入口、JNI 导出或敏感引用选择原生追踪，Java 到 JNI 再到 C/C++ 的完整数据流不计为首版完成。

## iOS 分析

逐个 App、Framework、Extension 及其切片分析。提取 Info.plist、URL Types、Associated Domains、ATS、用途说明、entitlements、provisioning、App Groups、Keychain Groups。域名端关联、配置运行时有效性不在离线事实内。

每个 Mach-O 分别记录加密状态、架构、段、地址映射、依赖、导入导出、可恢复的 ObjC 类/selector 与 Swift 符号。加密区域不得作为明文代码分析；其他资源与元数据继续处理。

0.3.0 先交付 LLVM 符号支持的函数、汇编及部分直接调用索引；无函数符号时保留覆盖缺口，不把汇编当作伪代码。Ghidra 适配脚本需实际引擎验收后再声明函数和伪代码能力。ObjC 动态派发、Swift 间接调用保留候选目标与未解析边。单库保存可复用数据库，避免每条候选重新导入。签名信息读取、密码学验证、平台信任与可安装性分开；平台特定验证可接 macOS worker。

## 首批专项分析器

| 模块 | 重点 |
| --- | --- |
| 外部入口 | 导出组件、深链、URL 回调、保护权限、处理方法 |
| 网络协议 | 地址/接口候选、请求构造、TLS 校验、MQTT/WebSocket 线索 |
| 认证 | OAuth 参数、令牌处理、固定认证分支、生物识别线索 |
| 存储 | 数据来源、读写 API、加密处理、文件位置、备份配置 |
| 密码 | 常量/解码/参数到密钥、IV、Cipher 或原生密码 API 的关系 |
| WebView | 外部输入、加载地址、脚本桥、导航、文件访问、证书处理 |

接口字面量与已恢复请求分开；数据库名/建表语句不证明明文写入；未检出 pinning 或完整性检查不证明没有该能力。公开客户端标识不自动作为泄密。SDK 身份和版本无法可靠恢复时不凭文件名认定漏洞版本。

## 数据与证据契约

实体：artifacts、components、analysis_runs、observations、relations、attack_surfaces、findings、evidence、coverage。先用普通关系表和全文索引。

证据包含 evidence_id、包与成员 SHA-256、归档身份链、切片身份、位置、工具版本、参数摘要、原始产物摘要/路径、执行限制。资源定位到字段/节点/偏移；DEX 定位到文件、方法签名和指令偏移；原生定位到切片、文件偏移、虚拟地址和函数范围。

观察事实、静态推断、待验证问题分开保存；直接调用、间接候选和名称相似推断使用不同关系类型。规则状态为命中、已查未命中、不适用、受阻、预算耗尽、未执行。风险严重度与证据强度分别记录。

导出前验证证据存在、属于当前样本、位置有效、源状态和覆盖一致；不存在或身份不符的引用拒绝导出。语义充分性仍须规则正反例和人工抽样。

## MCP 契约

计划业务工具：import_artifact、start_analysis、get_analysis_status、list_results、get_result、read_evidence、cancel_analysis、export_report。可增加 health_check 和 list_artifact_members 辅助诊断与分页。只注册实际实现工具。

start_analysis 返回 analysis_id，后台运行；profile=native-security-review。预算包括总时间、原生阶段时间、内存、输出、模型调用与 token。大型产物以文件输出，不塞进 MCP 文本。普通响应默认脱敏，原值受限保存到本机。

## AI 调查

仅开放 search_observations、read_method、read_function、find_references、trace_value、read_evidence、submit_hypothesis 等受控能力。包内内容属于不可信数据，不能作为执行指令。不提供任意 shell、任意 SQL 或包内网络地址访问。

每项问题按检索证据、提出假设、定点追查、支持/否定、记录缺口循环。模型不可用交付基础报告，新增推断必须引用有效证据；不允许覆盖原始事实。

## 可靠性与安全

阶段独立落盘，缓存键包含样本、组件、引擎、配置和规则版本。持久化租约、幂等阶段和原子结果提交支持恢复。超时保留已完成结果并记录未完成组件，取消终止所属进程和后代。限制 ZIP、解析器、内存、CPU、时间和输出，worker 不执行目标且默认无外网。原始快照不可被分析器修改。

## 报告结构

样本身份与环境 → 应用画像和组件 → 外部入口 → 网络/API 候选 → 专项结果 → 风险及证据 → 成立条件与影响 → 修复复测 → 覆盖/失败/未知 → 原始证据索引。无候选时照常输出事实、攻击面和缺口。

## 里程碑与验收

- A1：隔离工程、官方 SDK、CLI/MCP、私有导入、SQLite 清点、正反例与 stdio 集成验收。
- A2：MobSF 适配、异步基础扫描、真实引擎调用、统一结果和报告；缺引擎明确受阻。
- B：先交付 JADX 方法与 LLVM 原生符号/汇编索引、部分引用和定点查询；随后验收 Ghidra 伪代码与扩展覆盖。真实方法/函数证据可定位。
- C：六组专项分析、有限数据流和 AI 调查，编译正反例验证。
- D：缓存恢复、取消、版本比较、资源隔离和安装交付。

先前 2～3 天为首版跑通、5～7 天为稳定首版的初步工程预算，不代表所有专项和深度数据流已经完成。每阶段以可执行验收和真实记录为准。

测试采用可重复编译的 Java/Kotlin/ObjC/Swift 正反例与修复版本，并覆盖损坏归档、多架构、加密代码、缺依赖、取消、超时和无候选报告。纯构造归档只计导入/契约测试，不计真实 APK/IPA 代码分析。REA 对比固定样本、任务、版本、引擎和预算，测恢复率、误报率、证据完整性、耗时与人工操作量。

## 官方参考

- MCP Python SDK：https://github.com/modelcontextprotocol/python-sdk
- MobSF API：https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/urls.py
- JADX：https://github.com/skylot/jadx
- LIEF：https://github.com/lief-project/LIEF
- Ghidra headless：https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md
- iOS 加密边界：https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0158/

## 0.4 实施补充

已交付 Android 显式导出入口到敏感 API 的有界方法使用关联，作为专项调查前置攻击面，不替代参数数据流或漏洞确认。静态推断与配置观察分开标注，派生证据需重验 Manifest 和各 DEX 索引依赖；实现和已知答案对照见 C-ANDROID-ENTRY-VALIDATION.md。原生切片另核对 CPU 子类型，并已实际验证 arm64/arm64e、剥离符号及 Extension 载体；Ghidra 是否实际通过以实施记录为准。

## 0.5 实施补充

Android 专项已增加有限 SSA 参数来源：由实际 JADX pass 捕获定义，在已选路径中按精确调用位置/参数位置绑定，保留常量、Intent API 返回、合流与未知；不跨越未建模调用语义，不据此认定外部可控或漏洞。当前能力与十组编译反例见 C2-ANDROID-SSA-VALIDATION.md，完整调用图/数据流、守卫分析及 AI 仍是后续目标。
