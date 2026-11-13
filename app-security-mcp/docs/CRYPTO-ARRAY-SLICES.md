# Android 密钥与 IV 数组切片（0.20.0）

此前 SecretKeySpec/IvParameterSpec 检测只依据构造方法名前缀和常量数组，未验证 offset/length，可能将无效切片报告为固定密码参数。本次改为匹配四个精确构造签名，要求已知非空数组范围，起点非负且不越界；SecretKeySpec 还要求算法参数为已知字符串。

证据新增 material_length、source_array_offset、source_array_length、constructor_descriptor。Base64 还原来源继续保留，不输出原数组、切片或任意算法字符串。provider_acceptance/runtime_use 保持 unknown。没有验证算法对应的合法长度、提供方支持或后续 Cipher/Mac 调用。

空 IV 在参数容器层面未必非法，本规则仅检测非空固定材料；跳过空数组不代表判断其安全。未知算法、外部输入、未知/负偏移、零长度与越界切片保守不推断。规则语义收紧后候选减少不能当作包已修复，compare_scans 会提示规则与扫描器版本差异。

API 依据：[SecretKeySpec](https://docs.oracle.com/en/java/javase/26/docs/api/java.base/javax/crypto/spec/SecretKeySpec.html)、[IvParameterSpec](https://docs.oracle.com/en/java/javase/26/docs/api/java.base/javax/crypto/spec/IvParameterSpec.html)。

真实 Java→D8→DEX 集成测试新增 18 个方法：密钥/IV 普通切片与 Base64 切片 4 个正例，以及空数组、越界、负偏移、零长度、未知偏移、外部输入、空/未知算法共 14 个反例。保留已有整数组、GCM、PBE、分支、脱敏和缺依赖测试。

## 验收

插件包严格回归 33 项通过、零跳过；新增样本扩充既有 DEX 集成测试，未另增测试项计数。安装 0.20.0 后 Codex 发现 3 个 Skill、21 个工具。

实际通过已安装插件复扫用户 app-arm64-v8a-release.apk：1 个 DEX、22711 个方法，0 个规则候选，整体仍 partial。结果不是全包安全证明；跨方法传播等原有缺口未消除。证据 artifacts/validation/crypto-slices-real-apk.json。
