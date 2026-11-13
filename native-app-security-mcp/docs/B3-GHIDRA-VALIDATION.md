# Ghidra 原生反编译实际验收

日期：2026-11-11；服务 0.5.0；本机 macOS arm64；Ghidra 12.2、JBR/JDK 25.0.2。

## 下载与代理状态

按用户要求，在交互式 zsh 中执行 proxy enable，使用本机代理续传官方 Ghidra 发行资产。完整归档为 569712708 字节，SHA-256 与 engines.lock.json 一致：

```text
2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
```

校验成功后执行 proxy disable，随后 proxy status 返回“代理未开启”。代理只用于下载进程的环境；安装、编译和以下分析验收均在这些代理环境变量关闭后进行，没有修改全局 shell 或客户端配置。状态保存在 runtime/setup/ghidra-download.json。

## Apple Silicon 本机依赖

首次实际运行发现发行包只带 Windows/Linux 等平台的部分预编译组件，没有 os/mac_arm_64/decompile。Java 分析器能产生函数和字符串，但 15 个函数均没有伪代码；不能把这次运行记为反编译成功。

新增 scripts/build_ghidra_native.py，从已校验官方归档逐文件核对 231 个 C/C++ 源码、头文件和 Makefile，再用本机 Xcode clang++ 构建官方 decompiler。采用发行包内 Makefile 的 ghidra_opt 目标，显式覆盖 arm64 与 macOS 11.0 编译参数，并使用包内已生成的解析器文件；不下载 Gradle，不改官方源码，不安装全局工具。

生成文件放在工程 .tools/ghidra/Ghidra/Features/Decompiler/build/os/mac_arm_64/decompile，Ghidra 优先使用该本机构建目录。原始归档、源码集合、编译器、命令参数、架构和二进制摘要记录在 runtime/setup/ghidra-native-build.json，构建日志是本机运行材料。

```sh
.venv/bin/python scripts/install_engines.py --engines ghidra
.venv/bin/python scripts/build_ghidra_native.py
.venv/bin/python scripts/verify_native_variants.py --engine ghidra --no-rebuild
```

最后一项需要已有样本；首次可去掉 --no-rebuild，实际重新编译样本。构建的是分析引擎，不是执行目标应用。

## 三组已知答案样本

| 样本 | 函数 | 定义字符串 | 恢复正文 | 部分静态引用 |
| --- | --- | --- | --- | --- |
| stripped.apk | 15 | 32 | 15 | 10 |
| stripped.ipa | 3 | 9 | 3 | 3 |
| fat-extension.ipa | 27 | 140 | 27 | 39 |

这些计数包含编译器辅助函数、桩和运行库相关代码，不是业务函数数或漏洞数。LLVM 对同一剥离样本恢复 0 个函数；Ghidra 实际恢复了函数和 C 风格伪代码。检查同时验证：

- 私有 helper 的符号已剥离，没有依赖原私有符号名完成恢复。
- 已知字符串被恢复，并有来自函数的静态引用。
- 正文明确为 c_like，默认查询仍脱敏；原值只进入受限本机导出。
- arm64 与 arm64e 切片及 Extension 独立索引，连同相同地址的函数也保留不同代码单位 ID。
- Ghidra 将 Mach-O 入口命名为 entry；验证按后端入口命名检查，不把它误认为切片合并。
- 报告导出成功，保存包、切片、索引摘要和引擎版本。

完整记录在 runtime/native-variants-verification-ghidra/summary.json。分析未执行目标、未安装 APK/IPA、未验证 Extension 功能，未调用真实 MobSF。它证明本机特定样本的引擎链路可用，不证明所有原生应用能完整恢复。

## 尚未覆盖

原生结果仍为 indexed_partial。函数发现、已定义字符串、调用和伪代码均受预算限制；间接派发、ObjC/Swift 完整语义、跨库/JNI、加密切片及完整数据流仍有缺口。Swift Framework 当前的实际函数路径验证仍来自 LLVM，尚未完成 Ghidra 专项验收；不能把此次 ObjC/C 样本成功扩大为完整 Swift 反编译证明。

Ghidra 的其他本机辅助组件没有因此全部构建或验收。取消/超时、资源隔离、复杂 C++ 与大型真实应用的全面覆盖仍需后续验证。0.3/0.4 记录中的“下载受阻、尚未实际运行”是历史状态，当前状态以本文及 IMPLEMENTATION.md 为准。
