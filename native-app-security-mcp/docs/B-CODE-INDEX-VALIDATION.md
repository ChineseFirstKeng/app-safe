# 代码索引首版验收

日期：2026-11-11；版本：0.3.0；主机：macOS arm64。当前可从 APK/IPA 建立有界代码索引并查询证据；尚不构成完整安全评估。

> 本文保留 0.3 首版验证记录。0.4 新增剥离符号、arm64/arm64e fat 和 Extension 实际载体验证，见 [B2-NATIVE-VARIANTS-VALIDATION.md](B2-NATIVE-VARIANTS-VALIDATION.md)；最新阶段状态和测试数见 IMPLEMENTATION.md。

## 数据如何产生

APK/IPA 私有快照 → 按已核验清单提取 DEX/ELF/Mach-O → 检查摘要、切片和加密 → 独立工作进程调用索引程序 → 私有原始 JSON → SQLite 元数据/关系 → MCP 查询、证据重验和报告。

Android 使用真实 JADX Java API，导出完整方法身份、部分反编译表达及静态方法使用引用。原生使用真实 LLVM 符号表与反汇编，导出函数、汇编和部分静态引用。调用工具与解析过程由程序执行；本阶段不依赖模型提示词或源码输入。

Ghidra headless 导出脚本已编写，但下载未完成，尚未实际运行。自动模式优先尝试已安装 Ghidra，失败留痕后回退 LLVM；本次实测强制 LLVM。后端降级只通过受控测试，不计真实 Ghidra 验收。

## 可复现验证

依赖准备见 README；需要 Android SDK/NDK、Xcode、完整 JDK 和已安装的 JADX。脚本实际编译 fixtures/code 的已知答案源码，不运行生成的程序。

```sh
.venv/bin/python scripts/acceptance.py
.venv/bin/python scripts/verify_code_index.py
.venv/bin/python scripts/verify_mcp_code.py
```

| 验收 | 实际验证 | 记录 |
| --- | --- | --- |
| 基础回归 | 51 项，零失败/错误/跳过；含重载身份、摘要篡改拒绝、撤销发布、加密切片、脱敏、后端降级 | runtime/validation/acceptance.json |
| 编译 APK | javac→D8→DEX；NDK arm64 ELF；JADX 1.5.6/JBR 25.0.2 与 LLVM 21.0.0 实际执行 | runtime/code-index-verification/summary.json |
| 编译 IPA | clang Objective-C 主程序、swiftc Swift Framework；LLVM 21.0.0 实际执行 | 同上 |
| 真实 MCP | 官方 SDK stdio 发现十四工具，导入→任务→查询→脱敏代码→引用→权限 600 原值→报告 | runtime/mcp-code-verification/summary.json |
| CLI 与打包 | symbols/code/references/export-code 实际调用；0.3.0 wheel 包含 Java 索引脚本 | dist/（不提交） |

APK 当前恢复 5 个方法、8 个 ELF 函数、5 条静态关系；验证 endpoint→helper(String) 与 helper(int) 重载区分、常量遮盖及原值导出。ELF 样本用链接器显式本地绑定，以检查可确定的直接目标；PLT/间接目标不强行补成同库调用。

IPA 当前恢复 91 个函数、199 条静态关系；验证 Objective-C 方法符号、C 直接调用与 Swift 导出入口到 Helper 的有限路径。计数含编译器生成函数。样本为未安装、未执行的已知答案包，不代表商业应用覆盖、签名验证或可安装性。

summary.json 保存实际包 SHA-256、analysis_id、各组件原始索引摘要、引擎与适配器版本、计数和报告路径。重新编译可改变包摘要，以最新记录为准。普通输出不含字面量原值；原始索引和代码导出是受限本机文件。

## 查询接口

- list_code_symbols：名称子串与类型分页；返回代码身份、组件、来源和可用性。
- get_code：重验来源摘要及代码身份，返回脱敏表达；body_format 区分 java_like、assembly 或 c_like，original_source=false。
- get_code_references：已恢复的静态入边或出边；未知/外部目标不捏造代码节点。
- export_code：只生成权限 600 的本机 JSON，MCP 返回路径与摘要，不回显原值。

CLI 对应 symbols、code、references、export-code。只提交 APK/IPA，然后使用分析编号与代码编号查询，无需提交源码。符号名称仍是可读的不可信元数据，脱敏不声称移除任何形式编码的所有秘密。

## 预算和未覆盖范围

| 项目 | 当前限制 |
| --- | --- |
| 包内代码 | 每任务最多 4 个 DEX、4 个原生切片；单个载体最多 128 MiB；fat 最多 16 切片 |
| 阶段时间 | 代码阶段最多 180 秒，受任务总截止时间约束；单 DEX 60 秒，Ghidra 90 秒，LLVM 30 秒 |
| JADX | 每 DEX 最多 2000 方法、前 24 个顶层类反编译；每段表达最多 12000 字符、最多 12000 关系 |
| LLVM | 最多 2000 个有函数符号且有反汇编标签的函数、每段汇编 12000 字符、最多 12000 关系 |
| 原始 JSON | 单组件最多 16 MiB；超限拒绝并记录缺口 |
| 原生后端 | LLVM 无伪代码/字符串数据流；Ghidra 导出脚本尚待真实验收 |

加密、失败、缺依赖、遗漏与预算截断单列。JADX 引用是方法使用关系，调用指令偏移和原始行号未知时为 null；LLVM 仅恢复部分直接目标与未解析间接边。未完整解析 ObjC 消息派发、Swift 虚表/见证表、跨组件解析、JNI 桥接、完整调用图、字符串用途或数据流。剥离函数符号可能无法建立 LLVM 函数索引。

当前未单独验收 Kotlin 业务样本、Extension、fat 多架构真实编译包和大型多 DEX；解析合约与单元样本不能代替这些实际场景。反编译成功、索引计数和零候选都不证明应用安全。报告仍为 partial，data_flow=not_implemented，security_assessment_complete=false；真实 MobSF/Ghidra、专项调查、AI 与 REA 比较仍待完成。
