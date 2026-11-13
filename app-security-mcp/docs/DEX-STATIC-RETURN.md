# Android 静态固定返回值传播（0.24.0）

这是跨方法分析的第一块受限能力。对同一 DEX 的反汇编做两遍处理：先收集静态无参 String 方法摘要，再分析调用方。方法忽略 nop 后必须恰好为 const-string/const-string-jumbo 与返回同一寄存器的 return-object。匹配完整类描述符、方法名、原型以及 invoke-static/invoke-static-range，方法顺序不影响结果。

每 DEX 最多 10000 个摘要，字符串最多 8192 字符；已有反汇编输出预算和全局时间预算继续生效。快照仅存于任务临时目录，正常退出清理。dex_scan 记录 constant_method_summaries、constant_method_returns_propagated；超出摘要容量记录 method_summaries_truncated=true。

返回值可传入字段赋值，或经已有无参 getBytes 进入密码参数检查。证据记录 callee_class_descriptor、callee_method、callee_prototype、常量/返回指令位置以及调用位置，全部关联当前 DEX 成员摘要，不输出原值。调用时清除其他寄存器状态，避免假设类初始化没有影响。真实执行、类初始化是否成功和业务用途依然未知。

不支持跨 DEX、带参数、实例方法、递归、包装调用、分支、多层调用链或一般对象分析。显式字符集 getBytes 等后续方法对摘要对象尚未全面适配。不能称为完整跨方法或 static-deep 分析。

## 验收

真实 Java→D8→DEX 编译测试加入固定返回值字段赋值及密钥构造两个正例；同名参数重载、分支方法、包装方法和实例方法四个反例。通过原型和调用位置断言验证来源，保留报告脱敏测试。独立测试验证静态标记、签名、返回寄存器、不允许额外调用、无效字符串索引和长度预算。

插件包严格回归 36 项通过、零跳过。已安装 0.24.0，Codex 发现 3 个 Skill、21 个工具。通过已安装插件复扫用户 APK：1 个 DEX、22711 方法，匹配本步严格形态的摘要为 0、传播为 0、规则候选为 0，状态 partial。本包未匹配新能力，不能据此宣称已覆盖其跨方法数据流。证据 artifacts/validation/static-return-real-apk.json。
