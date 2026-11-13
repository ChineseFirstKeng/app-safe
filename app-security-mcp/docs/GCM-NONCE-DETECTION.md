# Android GCM 固定 Nonce 检测（0.19.0）

HC-007 支持精确 GCMParameterSpec 构造签名 `(I[B)V` 与 `(I[BII)V`，在现有受限直线传播中识别非空常量数组、受支持 Base64 还原数组及有效切片。要求标签长度为已知非负整数，切片起点非负、长度大于零且未越界。不据标签长度认定密码提供方支持或强度合适。

证据记录成员摘要、类、方法、指令位置、nonce_length、tag_length_bits、source_array_offset、source_array_length 与转换来源。不输出数组或明文。未知参数、空数组、无效切片、负标签、随机填充、分支来源保守不推断。

结果为 candidate / needs_review。仅证明固定材料进入参数构造，不证明到达 Cipher.init、不区分加密/解密、不确认相同密钥或重复加密。没有实现一般跨方法数据流。

修复先核对使用位置。如用于 GCM 加密，应保证同一密钥下 Nonce 唯一，验证重复调用、并发和重启后的不重复性，并检查解密兼容与认证失败处理。解密已有密文和测试向量不能仅因固定参数就认定漏洞。

API 与约束依据：[Android GCMParameterSpec](https://developer.android.com/reference/javax/crypto/spec/GCMParameterSpec)、[Oracle Cipher](https://docs.oracle.com/en/java/javase/24/docs/api/java.base/javax/crypto/Cipher.html)。

顺带修正报告中的历史 iOS 解码预算说明，使其与 0.17.0 已实现的可配置预算一致。

## 自动验收

现有真实 Java→D8→DEX 编译测试扩充了 11 个 GCM 方法：整数组、有效切片、Base64 来源 3 个正例；外部输入、未知标签、负标签、越界、负偏移、空数组、分支、随机填充 8 个反例。仅 3 个正例产生 GCM 候选，长度、偏移、转换来源及用途未知状态断言通过。

插件包严格回归 33 项通过、零跳过（测试数量不变，扩充既有 DEX 集成用例）。安装 0.19.0 后 Codex 发现 3 个 Skill、21 个工具。

实际已安装插件复扫用户 app-arm64-v8a-release.apk：1 个 DEX、22711 个方法，0 个规则候选（其中 GCM 候选 0），整体仍 partial。此结果仅覆盖支持的分析范围，不能证明没有固定 Nonce 或其他硬编码问题。证据 artifacts/validation/gcm-real-apk.json。
