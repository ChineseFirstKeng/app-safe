# Android 字节数组复制常量传播（0.22.0）

支持精确签名 Arrays.copyOf:([BI)[B 和 Arrays.copyOfRange:([BII)[B。只传播已知 byte[] 与已知整数边界。copyOf 可截短或补零；copyOfRange 的起点必须在 0 至原长度之间，终点不得小于起点，但可以超过原长度并补零。空结果允许还原，但现有密钥/IV 检测不将空材料作为候选。

单次输入输出最多 8192 字节，同一来源最多 8 次复制。array_copy_steps 记录每步调用文件位置/DEX 指令位置、输入输出长度、from/to、zero_padding_length，保留已有 Base64/UTF-8 来源。不输出字节。复制结果是独立值；其后遇到不支持的写入会停止传播，不猜测内容。

未知输入、未知长度、负长度、无效起点、反向范围、过大输出和超过复制步数时不产生可传播结果。其他数组类型、System.arraycopy、跨方法及复杂分支未实现。固定材料经过复制后仍是待复核候选，不确认密码提供方接受或运行用途。

语义依据：[Java Arrays 官方文档](https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/util/Arrays.html)。

## 验收

真实 Java→D8→DEX 编译测试新增 4 个正例（补零密钥、截取密钥、Base64 后复制、全零补齐 IV）和 7 个反例（未知数组/长度、负长度、无效起点、反向范围、空结果、超预算）。新增独立单元测试核对实际字节、补零数量、空边界、8192 字节边界和非法输入。

插件包严格回归 34 项通过、零跳过。

已安装 0.22.0，Codex 发现 3 个 Skill、21 个工具。通过已安装插件复扫用户 app-arm64-v8a-release.apk：1 个 DEX、22711 个方法，0 个候选，状态仍 partial。证据 artifacts/validation/array-copy-real-apk.json。零候选不代表不存在硬编码问题。
