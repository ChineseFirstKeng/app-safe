# Android 原生字符串引用复核（0.9.0）

此前 ELF 扫描器记录链接时地址，Ghidra 返回装载后的地址，直接比较可能漏掉同一字符串的引用。现在 verify_android_native_finding 对 analyze_function 返回的字符串地址调用 address_to_file_offset，将引用连接到同一 ELF 的原始文件偏移。

必须同时满足：映射证据的二进制 SHA-256 与待复核成员一致、提供器身份一致、返回地址与请求地址一致、文件偏移为安全非负整数、偏移与候选位置精确相同。不会推测固定 image base，也不会只凭字符串值相同确认引用。

reference_mapping 返回方法、候选偏移、检查数量、失败数量、截断标志，以及匹配地址和映射 Evidence ID。每次最多映射 32 个唯一的有效地址；地址缺失、工具不支持或映射失败保留未知。源字符串与反编译明文不写入报告。

- matched：在提供器返回的静态引用中找到了对应原始文件位置。
- no_match_in_returned_references：检查了返回引用，未精确匹配；不代表函数绝不使用该值。
- partial / unknown：映射失败、预算截断或缺少可用引用。
- not_applicable：Base64/Hex 解码候选不能当作原地址上直接存在的明文字符串。

这是已知函数的定点复核，仍需 procedure 为已知符号或提供器返回的函数地址。不自动寻找所有使用点，不恢复动态 JNI，不证明运行时调用、敏感用途或漏洞可利用性。usage_confirmed 仍为 false。

## 本机验收（2026-11-10）

实际 Ghidra 12.1.4、同一四 ABI 合成 APK 的 arm64 成员：

- Java_example_Native_secret：提供器引用地址 0x1003ce 映射到文件偏移 974（0x3ce），与候选一致；string_reference_observed=true。
- public_id：函数恢复成功，返回引用映射与目标候选不匹配；string_reference_observed=false。
- iOS _fixture_secret 回归：原有精确地址引用匹配仍通过。

22 项自动测试通过、零跳过，包括错二进制、错提供器、错地址、错偏移、映射失败、解码候选、地址去重与预算上限。实际引擎证据见 artifacts/validation/native-mapping-result.json。

插件为 0.9.0，3 个 Skill、20 个工具。本步不涉及服务器、Git 推送或应用执行。
