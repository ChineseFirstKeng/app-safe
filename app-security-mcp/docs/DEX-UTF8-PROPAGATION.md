# Android 显式 UTF-8 常量传播（0.21.0）

原实现只识别无参数 String.getBytes()，显式字符集重载会丢失常量来源。本次支持 String.getBytes(String) 的 UTF-8/utf8 名称（忽略大小写）、String.getBytes(Charset) 的 StandardCharsets.UTF_8，以及 Charset.forName 对上述已知名称返回的字符集。

只在现有受限直线指令中传播。输入字符串最多 8192 字符、编码输出最多 8192 字节；未知输入、未知/空字符集、其他字符集及无法严格编码的 Unicode 不推断。没有实现跨方法传播或 Kotlin 编译产物的完整模式适配。

证据记录 transform=string_getbytes_utf8、encode_file_offset、encode_code_unit_offset、encoded_length。后续 SecretKeySpec、IvParameterSpec 等支持的参数检测复用这些字节，不输出完整字符串或字节。该改动不确认参数实际使用、运行行为或漏洞。

[Java String 官方文档](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/String.html#getBytes(java.nio.charset.Charset)) 定义字符集重载。本实现对非法 Unicode 保守跳过，不模拟 Java 的替换行为；无参数 getBytes 的既有行为本步未改动。

## 验收

真实 Java→D8→DEX 集成测试增加 4 个正例（三种显式 UTF-8 密钥来源与中文 IV）和 6 个反例（其他/未知/空字符集、外部输入）。验证中文 IV 的 16 字节长度及编码来源定位。候选仍为 needs_review/candidate。

最终插件包严格回归 33 项通过、零跳过；安装 0.21.0 后 Codex 发现 3 个 Skill、21 个工具。确认已安装 DEX worker 与源码一致。通过最终安装版本复扫用户 app-arm64-v8a-release.apk：1 个 DEX、22711 方法，0 候选，整体仍 partial。证据 artifacts/validation/utf8-real-apk.json。无检出不代表全面安全。
