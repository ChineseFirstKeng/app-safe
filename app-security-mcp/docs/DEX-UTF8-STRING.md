# Android UTF-8 字符串构造还原（0.23.0）

支持四种精确构造签名：String(byte[], String)、String(byte[], Charset) 及各自带 offset/length 的重载。字符集限已知 UTF-8/utf8 名称、StandardCharsets.UTF_8 或受支持的 Charset.forName 结果。字节来源复用已有常量数组、Base64 及 Arrays 复制传播。

在新建 String 对象上恢复已知内容，进入现有文本规则；写入字段时保留内容与转换来源，能结合 client_secret 等字段上下文检出仅凭文本模式无法识别的候选。对象引用别名共享初始化状态，但没有实现一般对象模型、全部 String 方法或跨方法传播。

源数组上限 8192 字节；切片要求已知非负 offset/length 且不越界。严格 UTF-8 解码，不模拟 Java 的非法字节替换行为。未知输入/字符集、非法 UTF-8、无效切片不推断；默认字符集构造和其他重载不支持。

证据保留 Base64/复制来源，新增字符串构造指令位置、源字节范围与字符数；无原转换时 transform=bytes_to_utf8_string。输出脱敏，候选仍为 candidate/needs_review，不确认凭证有效或业务使用。原字节阶段和构造阶段可能各有证据，不应把它们当成独立凭证数量。

API 依据：[Java String 官方文档](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/String.html)。

## 验收

真实 Java→D8→DEX 集成测试增加 3 个正例：Base64 还原后字段赋值、指定名称构造、指定 Charset 的切片构造；5 个反例覆盖外部数组、其他/未知字符集、非法 UTF-8、越界。检查字段候选的转换来源和构造位置，报告不含合成秘密。独立单元测试检查多字节边界、空字符串、8192 字节边界和无效输入。

插件包严格回归 35 项通过、零跳过。

已安装 0.23.0，Codex 发现 3 个 Skill、21 个工具。通过已安装插件复扫用户 app-arm64-v8a-release.apk：1 个 DEX、22711 方法，0 个候选，整体仍 partial。证据 artifacts/validation/utf8-string-real-apk.json；零候选不是完整安全结论。
