# 原生自动引用及函数复核（0.31.0）

## 范围

Android ELF 与 iOS Mach-O 的原始字面量候选在 static-deep 下自动尝试复核。先校验包成员/切片摘要，再将提供方地址映射为原文件偏移；iOS FAT 候选减去 slice_offset，与提取的薄切片匹配。ELF 不猜测加载基址。

映射匹配后读取 xrefs，将引用地址交给 resolve_containing_procedure。只有目标摘要/提供方一致、查询地址一致、引用及函数入口位于返回函数体范围内时，才选择该函数。analyze_function 再校验身份、入口与引用所在范围。报告保存地址和证据标识，不保留伪代码、字符串原文或提供方完整原始结果。

深度扫描按成员/切片/字面量偏移去重；deep_native_limit 默认 2、最大 5，与 DEX 共用追加阶段 150 秒预算。候选地址先直接验证，失败时最多检查前 128 个提供方字符串地址、最多 32 个引用；截断/失败显式记录。SDK 传输消息上限 4 MiB。解码后的明文不当作原文件直接字面量，不自动复核。

只选择首个有有效证据的函数，不声称穷尽所有引用。函数恢复和静态引用均保持 candidate/usage_confirmed=false；安全用途及运行行为未确认。extraction/REA 取消信号连通，复核结束后等待关闭传输再释放任务与快照锁。

## 验收

- 49 项严格回归通过，零失败/零跳过。阶段快照 artifacts/validation/acceptance-031-summary.json。
- test/native-discovery.test.mjs：ELF 重定位、iOS 相对偏移、错误身份/查询、体范围之外、外部函数、解码值、无引用及预算边界。
- test/native-auto.test.mjs：两平台模拟 REA 协议、错误包/提供方/函数身份、报告脱敏、Python 提取期间取消、进程与临时目录清理。
- test/deep-scan.test.mjs：原生候选去重、单独数量预算、解码候选排除及 DEX 取消回归。
- 真实 Ghidra 12.1.4：合成 IPA 3 个候选，限 1 个字面量时恢复 1 个函数并观察到字符串引用；剩余 2 个未尝试。
- 真实 Ghidra：四 ABI ELF 合成包 12 个候选，4 个原始字面量适用；限 1 个时恢复 1 个函数，文件偏移映射匹配成功，Ghidra 地址与链接地址不同。
- 用户 IPA/APK 均 partial、0 候选，未触发原生复核，effective_profile=static-basic。
- 证据为 artifacts/validation/auto-native-{ios-fixture,elf-fixture,user-ios,user-android}.json。

原有 0.30.0 真实 150 秒预算测试覆盖共享调度超时路径；本阶段新增原生提取取消测试。未将此说成任意 Ghidra/JVM 后代进程的完整隔离或本阶段独立 150 秒原生引擎停滞验收。

## 仍未完成

通过数据指针/ObjC 对象图的多跳引用、完整值流、安全 API 参数语义、运行时解密及所有引用路径。缺映射/引用不表示值未被使用。大字符串清单可能因 4 MiB 消息预算受阻。
