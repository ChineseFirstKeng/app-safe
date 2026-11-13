# Android 方法返回值与转换衔接（0.26.0）

此前受限方法返回值可接入字段赋值及无参 getBytes，但显式字符集与 Base64 接口只接受直接字符串，导致链路中断。本次统一读取受支持的已知字符串值，接通显式 UTF-8 getBytes、Java 基础 Base64 和 Android Base64 flags=0/2。已有 UTF-8 String 构造还原对象也适用这些转换。

保留 return_chain、wrapper_depth、callee_*、caller_invoke_*；transform 表示最后转换，原方法来源由调用链保留。编码/解码位置及字节数继续记录。不输出原值、不确认真实密码用途。

调用已解析方法摘要时，保留已识别的不可变基础 Base64 解码器/UTF-8 字符集标记，以支持 getDecoder().decode(helper()) 这种求值顺序。其他旧寄存器仍清除，避免推断可变数组或对象未被影响。

输入与输出仍使用既有长度限制。Base64 只允许单层：来源证据已有 decode_file_offset 时拒绝第二次解码，避免把本步扩展误称为任意嵌套还原。其他字符集、其他 Base64 模式、跨 DEX/参数传播和一般数据流仍未实现。

## 验收

真实编译样本增加 5 个正例：方法返回值接 UTF-8 名称/Charset 密钥、Java Base64 包装链密钥、Android Base64 密钥及 Java Base64 IV。断言调用链深度、调用位置、最终转换与 16 字节材料长度。3 个反例：其他字符集、不支持的 flags、两次 Base64 解码。现有编译测试扩充，全套 37 项严格回归通过、零跳过。

已安装 0.26.0，Codex 发现 3 个 Skill、21 个工具。实际复扫用户 APK：1 个 DEX、22711 方法，0 个可解析摘要、0 次返回值传播、1 个未解析摘要、0 候选，整体 partial。证据 artifacts/validation/return-transforms-real-apk.json；未检出不等于没有硬编码问题。
