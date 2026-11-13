# 实施与验收总账

更新时间：2026-11-11。当前插件 0.36.0，3 个 Skill、23 个工具。以本文件及所链接的最新验收记录为准；设计文档里的早期交付段落为历史记录。用户已授权自主逐步实现、验收并继续，不需要逐步确认。

## 已交付和验证

| 原计划 | 实际已实现 | 状态边界 |
| --- | --- | --- |
| 1 设计 | 双平台组件、规则 HC-001～012、证据/修复/未知项约定 | 设计完成 |
| 2 导入 | 私有快照、包/成员摘要、ZIP 危险结构拒绝、分页清单、能力探测 | 已验收；包签名/可安装性不作保证 |
| 3 插件和任务 | Codex 安装发现；Claude Code 隔离安装与组件发现；持久化、取消、报告、证据、筛选分页、删除与引用保护 | 已验收；Claude 模型实际 Skill 调用未验证 |
| 4 资源 | 文本/JSON/plist/XML、AAPT2、PEM/DER 私钥解析、SQLite 普通表及字段规则 | 有界候选检查，非全部格式/用途 |
| 5 Android DEX | 字符串池、字段、常量数组/拼接/受限还原、密码参数、认证分支、同 DEX 无参静态返回和最多 4 层精确包装；REA 方法复核 | 部分语义覆盖 |
| 6 iOS | App/Framework/Extension、多切片、加密标识、Mach-O 分段字面量与有界解码、REA 定点函数复核 | 原生完整数据流未实现 |
| 7 ELF/规则 | 四 ABI、分段字面量、解码、JNI 导出线索、REA 引用地址映射；12 规则均有对应检查或清点入口 | HC-012 仅清点；动态 JNI/完整用途未实现 |
| 8 复测/验收 | 版本/配置/覆盖感知的扫描比较、正反例、缺依赖、取消、真实 100 秒超时、Codex 隔离安装、Claude 安装缓存握手 | 本机 macOS 验收，非跨 OS 全覆盖 |

## 本轮增量

0.36.0：优先补齐逐条硬编码内容与本机原值报告，Key 待核查项进入正文；用户 APK 的原值、位置和默认脱敏已验收；57/57 严格回归通过、零跳过，Codex/Claude 隔离安装握手通过。该增量不扩大规则覆盖。见 [内容报告验收](CONTENT-REPORT-VALIDATION.md)。

1. 0.27.0：证据读取、筛选游标、任务删除、跨进程共享快照锁、引用保护。39/39 严格回归通过。见 [扫描存储验收](SCAN-STORAGE-VALIDATION.md)。
2. 0.28.0：SQLite 表记录检查。41/41 严格回归；真实 APK/IPA 复扫完成，均 0 候选、partial，均未识别到 SQLite 文件。见 [SQLite 验收](SQLITE-RESOURCES.md)。
3. 0.29.0：易读 Markdown 报告、明确 effective_profile、Claude Code 安装兼容；42/42 严格回归零跳过。独立真实超时约 100.3 秒，后代清理通过。见 [双客户端验收](PLUGIN-CROSS-CLIENT.md)。

4. 0.30.0：Android static-deep 自动方法复核、按方法去重、数量/时间预算、取消及依赖降级；44/44 严格回归，真实 150 秒预算（152.4 秒含关闭等待）与提供方清理通过；真实 REA/JADX 合成样本恢复 1 个方法体，用户 APK 无候选、未执行复核。见 [自动方法复核验收](AUTO-DEEP-VALIDATION.md)。

5. 0.31.0：iOS/ELF 原生字面量自动偏移映射、引用定位和函数复核；49/49 严格回归、两平台真实 Ghidra 合成样本及用户 APK/IPA 复扫通过。见 [原生自动复核验收](AUTO-NATIVE-VALIDATION.md)。

6. 0.32.0：支持 PEM/DER 的私钥对象解析与公钥/证书反例，51/51 严格回归；加密材料保留未知状态。真实 APK/IPA 复扫无适用材料。见 [私钥格式验收](KEY-MATERIAL-VALIDATION.md)。

7. 0.33.0：有界嵌套 ZIP 视图与归档身份链，内部原生文件重新提取及真实 Ghidra 复核通过。见 [归档验收](NESTED-ARCHIVE-VALIDATION.md)。

8. 0.34.0：未加密单密钥 OpenSSH Ed25519/RSA/ECDSA 解析；本机 ssh-keygen 10 例兼容验证通过。见 [OpenSSH 验收](OPENSSH-KEY-VALIDATION.md)。

9. 0.35.0：共享数据目录下 POSIX 静态容量与孤儿工作进程保护。见 [共享容量验收](SHARED-STATIC-CAPACITY.md)。

当前机器私有证据：artifacts/validation/acceptance-summary.json、acceptance.tap、clean-install-summary.json、claude-install-summary.json、worker-timeout-summary.json、sqlite-real-android.json、sqlite-real-ios.json。所有候选保持脱敏。0 候选不表示包安全。

## 原计划尚未完成的实质性范围

- static-deep 已追加有界 DEX 与原生引用/函数复核；多跳引用、自动安全用途及完整数据流验证仍未实现。
- Android 一般参数、实例、分支合流、跨 DEX、反射、动态加载和跨 JNI 数据流。
- iOS 原生指令中的密码参数/认证逻辑、Swift/ObjC 对象图；当前字面量和定点引用不等于用途证明。
- 动态 JNI 注册、Flutter AOT 语义、任意复杂还原。
- 已支持部分 PEM/DER/OpenSSH 私钥结构及有界 ZIP 递归；PKCS12/JKS、其他密钥/归档格式、超预算内容及 SQLite WAL/加密/删除记录仍未实现。
- 同一目录的 POSIX 静态工作进程容量已共享限制为 2；共享 REA 容量、Windows 准入、目录互斥锁异常自动恢复、保留期限/自动清理仍未完成。
- 全新 OS/用户、Linux/Windows、模型实际 Skill 选择/执行，以及更广泛恶意样本/模糊测试。

这些是未完成项，不因增加限定词而当成已完成。动态设备验证和服务器 Git 部署属于原方案“后续可选”阶段；本轮没有操作服务器或发布公共包。整体目标不能标记全部完成。
