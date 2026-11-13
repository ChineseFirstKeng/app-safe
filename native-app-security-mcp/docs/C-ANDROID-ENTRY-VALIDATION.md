# Android 导出入口代码关联首版

日期：2026-11-11；服务 0.4.0；关联规则 android-entry/0.1。

> 本文保留 0.4 的方法使用路径首版记录。0.5 新增有限 SSA 参数来源与十组编译对照，当前范围见 [C2-ANDROID-SSA-VALIDATION.md](C2-ANDROID-SSA-VALIDATION.md)。

当前实现从显式导出的 Android 组件回调出发，在已恢复的 JADX 方法使用图中寻找敏感 API，生成可核查攻击面。它是专项调查的前置能力，尚未执行参数数据流、控制流可达性、鉴权分析或漏洞确认。

## 如何运行

输入仍为 APK。任务完成配置与代码索引后自动执行入口关联，无须新增源码或参数。MCP 继续使用十四个工具，通过 list_results(kind=surface) 找到 AND-ENTRY-001，read_evidence 返回入口方法、代码节点路径、目标 API、Intent 读取 API 使用记录及明确未知项。用 get_code/get_code_references 逐步复核同一条路径。

```sh
.venv/bin/python scripts/acceptance.py
.venv/bin/python scripts/verify_android_review.py
.venv/bin/python scripts/verify_mcp_review.py
```

工程内 Java 源码实际经 javac、D8、AAPT2 生成 APK，再交给独立工作进程与 JADX 1.5.6 分析；测试源码只是建立已知答案，分析入参不需要源码。未运行目标或访问样本内 URL。

## 真实编译对照

| APK | 声明与代码 | 预期及实际结果 |
| --- | --- | --- |
| external | exported=true，onCreate 读取 Intent，再经 navigate 调用 WebView.loadUrl | 1 条两方法路径；观察到 Intent 读取；不声称输入已流入 URL 参数 |
| constant | exported=true，onCreate 使用常量 URL 调用 WebView.loadUrl | 1 条单方法路径；无 Intent 读取；仍只列攻击面，不升级为漏洞 |
| private | 同一输入处理代码，exported=false | 无 AND-ENTRY-001 |
| disabled | 同一输入处理代码，enabled=false | 无 AND-ENTRY-001 |

四组均不生成代码风险 finding。WebView.loadUrl 本身不是漏洞；常量参数是避免把 API 使用当成漏洞的重要对照。来源篡改测试会临时修改原始 JADX JSON，确认派生证据读取与报告导出均拒绝，再恢复原文件。

记录为 runtime/android-review-verification/summary.json。真实 MCP stdio 验证记录为 runtime/mcp-review-verification/summary.json，覆盖导入、任务、结果、证据、路径内代码及引用查询和报告。覆盖字段 entry_review=partial_method_use_paths、data_flow=not_implemented。

## 范围与预算

- 只处理明确 exported=true、未明确禁用的 activity/service/receiver/provider。名称以 Manifest package 补全；隐式导出与 activity-alias 未追踪。
- 只匹配代码中的完整回调签名：Activity onCreate/onNewIntent；Service onStartCommand/onBind；Receiver onReceive；Provider 部分 query/insert/update/delete/openFile。继承而未在索引中声明的回调和其他重载留缺口。
- 目标 API 当前包括 WebView URL/内容加载、JavaScript bridge、System 本机库加载、DexClassLoader 构造及 Runtime.exec 的明确签名。其他 API 尚未覆盖；规则表存在不等于每类都经过真实编译样本验收，当前实际专项样本集中于 WebView.loadUrl。
- 每阶段遍历预算 15 秒（受任务总硬超时约束）、32 个显式导出入口、2000 次节点展开、7 个代码节点深度、50 条路径；图最多 8000 方法和 48000 条关系，来源沿用代码索引的最多 4 DEX。超限、未索引回调、身份歧义、深度限制均记录。
- 只沿已有同组件关系遍历，每节点保存一条候选路径，不枚举全部路径。跨 DEX、反射、JNI、虚调用与动态派发不完整；方法使用关系不等于指令控制流。已有节点无记录不代表不存在相关行为。

permission_declared 仅描述本组件或 application 的通用 permission 声明是否非空；不验证权限生效、保护等级、provider 读写权限或调用方身份。Intent 读取 API 记录也可能来自内部 Intent，不证明攻击者控制参数。所有结果 guard_effectiveness=not_analyzed、parameter_provenance=not_analyzed、runtime_observed=false。

## 证据与报告

派生 JSON 保存实际组件、入口、代码单位 ID、API 及覆盖。来源同时记录规则适配器 SHA-256、原始 Manifest 和每个 DEX 索引摘要。分析前、读取证据及导出报告时复核依赖；派生文件本身完整而原始来源被修改，也不能通过验证。

普通结果只展示代码元数据和明确的未知项，不返回 URL、Intent key、代码字符串等字面量。代码正文继续通过 get_code 脱敏读取；符号名称属于可读的不可信元数据。报告保持 partial、完整评估=false、REA 对比=未执行。

iOS 对应入口调查尚未实现，覆盖明确记 not_implemented_ios。下一步是在这些路径上增加可核查的参数来源、保护条件和反例检查，再决定是否形成风险候选；当前不以方法使用链代替这些证据。
