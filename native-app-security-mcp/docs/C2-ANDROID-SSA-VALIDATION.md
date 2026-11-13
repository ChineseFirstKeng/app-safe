# Android SSA 参数来源验收

日期：2026-11-11；服务 0.5.0；规则 android-entry/0.2；JADX 1.5.6、JBR/JDK 25.0.2。本轮新增的是有限范围的 SSA 参数来源分析，完整数据流、可达性、外部控制与漏洞确认仍未完成。

## 实际分析过程

输入仍只有 APK。JADX 自定义 pass 在 SSATransform 后、MoveInlineVisitor 前读取真实指令与 SSA 定义，保存调用目标、调用位置、显式实参和有界定义表达式；不从反编译 Java 文本用正则猜测变量关系。已有类/方法/时间预算继续生效。

针对导出入口的一条已有方法使用路径，分析程序匹配实际捕获的 invoke，按方法签名和实参序号建立调用上下文，再追溯敏感 API 的第 0 个显式参数。中间方法只有静态、直接、super 或已知 private/final 等可确定派发才绑定；跨 DEX 或不确定虚调用保留未知。终点的 WebView 等 API 仍可为虚调用，参数证据只描述其声明调用点，不证明最终运行实现。

SSA 变量按定义区分赋值，move/cast 传递来源，PHI 保留可能来源；常量只导出类型，不导出字面量。模型目前识别部分 Intent 读取 API 返回值、入口参数、构造对象、常量和未知。任意函数的返回值不继承其实参来源；本版尚未消费自定义方法返回摘要、字段/数组存储或通用字符串变换。

## 十组实际编译 APK

源码在 fixtures/review/android，实际经 javac、D8、AAPT2 编译，再走相同工作进程与 JADX；未执行目标或访问样本 URL。

| 样本 | 实际观察的来源 | 需要核对的区别 |
| --- | --- | --- |
| external | intent_api_return | onCreate 的读取返回值绑定到 navigate 的参数 1，再用于 WebView 参数 0 |
| private | 无入口追踪 | exported=false，不执行这条专项 |
| disabled | 无入口追踪 | enabled=false，不执行这条专项 |
| constant | constant | 直接加载常量，只列攻击面 |
| overwrite | constant | 同方法存在 Intent 读取，但目标实参已被常量覆盖，不误认为读取值传入 |
| mixed | constant、intent_api_return | 同一 helper 的两个调用位置分开绑定，保留两个上下文 |
| merge | constant、intent_api_return | PHI 合流保留两类来源，不声称任何分支必定执行 |
| unknown | unknown | 未建模函数返回值不被当成原始输入；本例函数实际替换为常量，分析如实保留未知 |
| non_exact | 无已解析参数上下文 | 可重写的中间虚调用不被强行绑定，保留 non_exact_interprocedural_dispatch |
| internal_intent | intent_api_return，接收者为构造对象 | Intent API 返回值不等于外部输入；不把内部构造的 Intent 当作外部控制证据 |

所有样本均为 surface，没有代码风险 finding。即使恢复了 Intent API 返回值与参数的定义关系，也不证明 Intent 由攻击者提供，不证明 getIntent 未被重写、不证明权限无效、不证明运行路径可达。

```sh
.venv/bin/python scripts/acceptance.py
.venv/bin/python scripts/verify_android_review.py
.venv/bin/python scripts/verify_mcp_review.py
.venv/bin/python scripts/verify_code_index.py
```

基础验收 66 项通过，零失败、错误、跳过。除十组真实编译对照外，测试覆盖不同调用位置绑定、未知返回值、不确定派发、跨 DEX、合流、内部 Intent、缺失 SSA、过期预算、上下文上限及共享来源树的展开预算。MCP 实际 stdio 验收覆盖结果、来源证据、代码节点、静态引用及报告；原有 APK/IPA 的 JADX/LLVM 索引回归仍通过。

主要记录：runtime/validation/acceptance.json、runtime/android-review-verification/summary.json、runtime/mcp-review-verification/summary.json、runtime/code-index-verification/summary.json。每项保存实际包摘要、分析编号与报告路径，重新编译以最新记录为准。来源篡改后的拒绝读取/导出测试继续执行。

## 如何复核

MCP 仍为十四个工具。通过 list_results(kind=surface) 找到 AND-ENTRY-001，再用 read_evidence 查看 argument_trace：

- observed_origin_kinds 是已观察上下文中的来源集合，不是所有运行路径的结论。
- contexts.call_chain 保存代码单位 ID、声明目标和 jadx_ir_offset；同一 helper 的不同调用位置分别保留。
- origin 的 parameter_binding 记录形参与调用方实参的绑定，intent_api_return 记录具体读取 API 与来源位置。
- external_control 始终 not_proven；control_flow_feasibility 始终 not_analyzed。接收者、未知原因与截断另列。

用 get_code/get_code_references 复核对应代码；默认代码仍脱敏，原值仅通过受限本机导出。SSA 表达式不复制 URL、Intent key 或其他常量内容。符号名称仍是可读的不可信元数据。

位置当前只声明为 JADX IR 指令偏移，不换算为 APK/DEX 绝对文件偏移，不充当源代码行号；未知位置为 null。来源绑定原始 Manifest、带 SSA 的 JADX JSON、Java 索引适配器摘要、入口规则与参数分析模块摘要；读证据和导出报告重验原始依赖。

## 状态与预算

entry_review=partial_method_use_paths_and_ssa_arguments 表示执行了有限参数来源分析；data_flow=partial_android_ssa_argument_origins 不表示完整数据流。没有入口路径时为 not_run_no_entry_paths；未捕获 SSA/入口不可用、失败和 iOS 未实现状态分别记录。

argument_trace.status=partial 表示有已观察上下文；unresolved 表示尝试后仍缺派发/调用等证据；unavailable 表示入口 SSA 未捕获。未知和混合来源不升级为安全或漏洞结论。method_use_only 保留为入口路径的基础覆盖说明，新增 SSA 只加强具体参数证据。

| 环节 | 当前预算 |
| --- | --- |
| JADX SSA 捕获 | 原有前 24 类反编译范围；最多 2000 方法、每方法 128 invoke、每 DEX 1000 invoke |
| 单次定义表达式 | 每调用共享 64 节点预算、深度 10、最多 16 显式参数、每 PHI 最多 8 个选项 |
| 参数上下文 | 原有最多 7 个方法节点；每路径最多 128 次调用上下文展开、16 个输出上下文 |
| 跨方法来源复制 | 每次求值 128 节点预算、深度 24，防止共享来源在多层合流时指数展开 |
| 输出 | 每路径上下文约 128 KiB，派生 JSON 最多 8 MiB；超预算明确保留未知或阻止发布 |
| 时间 | 沿用入口遍历 15 秒预算及任务总硬超时；JADX DEX 阶段仍受 60 秒预算限制 |

这些预算不会证明未观察的路径不存在。尚未覆盖通用方法返回值、字段/数组、复杂库函数、跨 DEX、反射/JNI、权限有效性、守卫条件或 iOS 参数来源；其他敏感 API 模型存在不等于已有对应真实编译验收，本轮实际专项仍以 WebView.loadUrl 为主。

实现依据与维护入口：[JADX pass 接口](https://github.com/skylot/jadx/blob/v1.5.6/jadx-core/src/main/java/jadx/api/plugins/pass/types/JadxDecompilePass.java)、[pass 顺序接口](https://github.com/skylot/jadx/blob/v1.5.6/jadx-core/src/main/java/jadx/api/plugins/pass/impl/OrderedJadxPassInfo.java)、[JADX 1.5.6 处理顺序](https://github.com/skylot/jadx/blob/v1.5.6/jadx-core/src/main/java/jadx/core/Jadx.java)。
