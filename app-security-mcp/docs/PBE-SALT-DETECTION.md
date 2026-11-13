# HC-008：Android PBEKeySpec 固定盐候选（0.10.0）

本步新增 Android DEX 的固定派生盐候选检测。严格匹配 PBEKeySpec(char[], byte[], int) 和 PBEKeySpec(char[], byte[], int, int) 构造方法。在支持的直线指令范围内，非空常量字节数组流入 salt 参数、迭代次数为已知正整数、四参数形式的密钥长度为已知正整数时产生候选。

API 参数与异常条件参考 [Oracle PBEKeySpec 官方文档](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/PBEKeySpec.html)。构造方法的静态调用不证明后续 SecretKeyFactory 派生实际执行。

证据包括类、方法、原型、调用偏移、成员摘要、salt_length、iteration_count、key_length_bits；不输出盐或口令。报告明确：盐不需要保密，风险需要结合是否跨用户/记录复用、KDF 与用途判断。建议核实后使用按用途独立生成的盐并随结果保存，结合实际 KDF 选择参数，制定旧数据迁移与业务复测方案。不会仅凭参数数值自动判断派生强度或把它定为已确认漏洞。

同时修复 DEX const/const-high16 的整数读取：dexdump 有时把原始整数位显示为浮点文本，现从指令原始字节按有符号整数解析，并检查边界与操作码。

## 本机验证（2026-11-10）

- 实际 JDK/D8 编译：三参数、四参数及 const/high16 大整数正例均检出；参数和盐长度断言通过。
- 反例：外部输入盐、条件分支盐、未知迭代次数、空盐、零/负迭代次数、无盐构造均不产生本规则候选。
- 原有密钥/IV、资源、iOS/ELF、对比及生命周期回归：22 项测试通过，0 跳过。
- 已安装插件 0.10.0 验证通过：3 个 Skill、20 个工具。
- 用户原 APK 经已安装插件复扫，候选 0，HC-008 状态 partial。机器记录：artifacts/validation/pbe-real-apk.json。零候选不代表无此类风险。

## 未覆盖

iOS、原生 KDF、PBEParameterSpec 等其他 API、跨函数及分支数据流、未知数值参数、自定义派生逻辑均未覆盖；不确认运行用途，不评价迭代强度。HC-009～HC-012 仍未实现。HC-008 仅部分实现，不是规则集全部完成。
