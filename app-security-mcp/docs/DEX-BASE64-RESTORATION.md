# Android DEX Base64 常量还原（0.15.0）

本步扩展现有 DEX 直线指令分析，让编码后的常量字节参与现有检测，而非仅搜索原始字符串。

支持精确 API：

- java.util.Base64.getDecoder().decode(String)：标准字母表。
- android.util.Base64.decode(String,int)：已知 flags 0 或 2，支持有限 ASCII 空白。

只处理非空常量字符串，最多 8192 字符、单层解码；不是完整 API 模拟。未填充末尾的两个/三个字符按支持的 Base64 规则处理，已有 padding 必须格式正确。Java 标准解码器的参数与 padding 语义参考 [Oracle API](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Base64.Decoder.html)，Android 重载/flags 参考 [Android API](https://developer.android.com/reference/android/util/Base64)。

还原的字节可继续进入 SecretKeySpec、IvParameterSpec、PBEKeySpec 的已有候选规则；可解为 UTF-8 的文本进入已有模式检测。不新增规则编号，不改变候选必须复核的性质。解码位置在 decode_file_offset/decode_code_unit_offset，后续调用位置仍由 evidence.file_offset/dex_code_unit_offset 表示，transform 和 decoded_length 记录过程。报告不保留编码值和还原值。

dex_scan 增加 constant_decode_attempts、constant_decode_recovered、constant_decode_unresolved，只统计实际分析到的受支持签名调用，不是全包调用数或覆盖百分比。未知输入、错误格式、未知 flags 或未识别解码器均不能产生已还原常量。分支方法仍跳过常量传播；未知指令继续保守处理。

## 验收（2026-11-10）

- 实际 JDK/D8 编译：Java/Android Base64 字节流入密钥、Java 字节流入 IV、解码令牌文本均命中；flags 0/2 正例通过。
- 动态输入、非法编码、未知 flags、URL-safe 解码器及 flags 8 反例不会产生固定密钥候选。
- 单层、不合法 padding、字母表、空白策略与 8192 字符边界通过。
- 插件包严格回归 29 项通过、零跳过，本机安装版本 0.15.0，3 个 Skill、20 个工具。
- 用户原 APK 通过已安装版本复扫，记录见 artifacts/validation/dex-base64-real-apk.json。

## 未完成

URL-safe/MIME、byte[] 重载、复杂 Charset 转换、自定义解码、递归解码、跨函数及分支数据流、iOS 同类还原尚未实现。静态字节还原不证明密钥有效、算法参数合理、代码实际执行或存在可利用漏洞。所有规则仍有覆盖边界，项目未全部完成。
