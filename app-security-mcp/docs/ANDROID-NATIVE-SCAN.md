# Android ELF/JNI 基础检查（0.7.0）

本步补充标准 ELF 32/64 位、大小端和 ABI 清点；扫描 APK 中 ELF 文件头或 `.so` 成员。校验表范围、文件区间、段映射和符号表关联。损坏/不支持的库 blocked，其他库继续；未实现扩展编号会明确阻塞。

## 支持范围

- 检查分配到内存且非执行的 PROGBITS 数据区中的 ASCII 可打印串。没有 section table 时退到可读非执行 PT_LOAD 文件区，显式标记覆盖缺口；不读取 debug/symbol 名称当作秘密。
- 复用密码、认证串、连接串、Secret、PEM 私钥封装模式。只恢复单层严格 Base64 或显式 `hex:`，不尝试执行初始化函数、暴力 XOR 或任意解密。
- JNI 清点只列动态符号表中可见、已定义的 Java_* 与 JNI_OnLoad 函数，保留链接地址。缺表为 not_run，不表示无 JNI。动态 RegisterNatives 与 DEX/JNI 参数传播尚未分析。
- `dart_snapshot_symbols=true` 只表示找到 Dart 快照符号，不意味着恢复了 Dart 代码。原生库的库名、JNI 入口、算法名称不能独立证明漏洞。

证据保留原始成员摘要、文件偏移、链接时虚拟地址、区域、ABI 及 transform，不输出秘密或解码明文。编码候选的偏移仍指向原编码数据，不冒称解码后的值在该地址实际存在。仍为 candidate/needs_review，并提供规则对应的修复建议。

## 资源限制

单库 64 MiB，全部原生库累计 256 MiB，最多保留 128 个文件结果。每区 32 MiB、每库累计 48 MiB；单字符串 64 KiB、每库 200,000 个字符串；单次解码输入最多 8,192 字符，每库最多 2,000 次、只一层。结构表有计数限制，整个扫描受原 90/100 秒内外时限约束。预算或缺表信息写入 gaps/failures，不能作为通过。全局候选最多 300，触顶标记截断。

基础 ELF 解析使用 Python 标准库，无新增运行依赖。合成测试使用已有 Android NDK；可通过 TEST_NDK_BIN 指定，缺 NDK 明确 skip。已用 NDK 编译 arm64-v8a、armeabi-v7a、x86、x86_64 四种库验证；其他架构不能据此声称通过同等工具链验收。

## 原生定点复核

新增 `verify_android_native_finding(scan_id,finding_id,procedure)`，原 `verify_android_finding` 保持用于 DEX。procedure 必须为已知函数符号或 REA 返回的函数地址，不猜测、不把字符串地址当函数。

复用已有私有 REA/Ghidra 配置（参见 IOS-NATIVE-SCAN.md），独立会话分析重新校验摘要后的 ELF 成员。保存函数范围、伪代码摘要和精确地址引用情况，不保存源码/秘密。usage_confirmed 始终 false；ELF 重定位/分析器装载基址可能造成地址不一致，引用 false 不证明没有使用。Base64/Hex 解码候选不直接认为与原始地址的字符串引用相匹配。

## 尚未覆盖

动态注册 JNI、跨语言调用链、原生加密参数流、完整 Unicode 字符串、自定义多层解码、Flutter Dart AOT 语义以及剩余硬编码规则仍未完成。本步是第 7 步基础交付，不是原计划“复杂常量还原与规则补齐”的全部完成。

格式参考：[ELF Header](https://gabi.xinuos.com/elf/02-eheader.html)、[ELF Symbol Table](https://gabi.xinuos.com/elf/05-symtab.html)。解析器不替代系统加载器，不会加载或执行包内共享库。
