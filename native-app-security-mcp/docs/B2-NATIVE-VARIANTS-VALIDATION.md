# 原生索引扩展样本验收

日期：2026-11-11；服务：0.4.0；当前实际后端：Apple LLVM 21.0.0。Ghidra 尚未实际运行。

> 本文保留 0.4 的历史状态。Ghidra 已在用户授权的代理下载后完成安装、本机组件构建及特定样本验收，当前记录见 [B3-GHIDRA-VALIDATION.md](B3-GHIDRA-VALIDATION.md)。

## 可复现步骤

```sh
.venv/bin/python scripts/verify_native_variants.py --engine llvm
```

脚本从本工程源码实际编译 Android arm64 ELF、iOS Mach-O、arm64/arm64e fat Mach-O 和 Objective-C Extension 载体，执行符号剥离，组装 APK/IPA，交给同一任务工作进程分析。不执行目标、不安装包、不访问包内地址。已有构建可加 --no-rebuild。

| 样本 | 当前实测结果 | 含义 |
| --- | --- | --- |
| stripped.apk | 0 个函数；no_code_units_recovered | ELF 的普通符号表被剥离，LLVM 后端不捏造函数恢复 |
| stripped.ipa | 0 个函数；no_code_units_recovered | 同一限制在实际 strip 处理的 Mach-O 上可复现 |
| fat-extension.ipa | 18 个函数，3 个分别索引的组件/切片 | arm64 与 arm64e 主程序切片独立，Extension 另列 |

剥离样本全局覆盖为 partial_no_code_units_recovered；这表示引擎确实执行但没有恢复节点，不表示没有函数或安全问题。含有符号的样本返回 partial。结果保存在 runtime/native-variants-verification-llvm/summary.json，含实际 SHA-256、分析编号、来源摘要与报告路径。

fat 样本通过 Xcode lipo 实际生成。CPU 类型相同，但子类型分别为 0 与 2147483650（arm64e 能力位）；载体偏移分别为 16384、98304。本次验证检查切片摘要、偏移、子类型和代码单位身份，两个 main 不会合并。解析器另拒绝 fat 表与薄切片 CPU 子类型不一致的构造输入。

arm64e 认证间接分支归入未解析目标，不猜测指向任意函数；对应指令合约测试已加入。报告展示切片序号、架构变体、CPU 子类型、载体偏移、引擎版本、恢复正文数及来源摘要。Extension 仅验证包内配置与 Mach-O 载体发现，不声称签名、安装、Extension 功能或生命周期正确。

## 工作进程与下载可靠性

工作进程先持久化终态，再终止其所属进程组，避免反编译辅助进程在正常任务完成后遗留。真实进程测试由受控工具产生一个后台辅助进程，确认任务完成后它停止；不按数据库旧 PID 清理无关进程。这仍不是容器或针对恶意守护进程的完整隔离。

引擎安装新增 scripts/engine_download.py：首次解析官方 GitHub 发行资产，随后对官方 CDN 做精确分段请求，保留完整片段供续传；所有片段拼接后核对锁定大小和完整 SHA-256，才发布为可安装归档。签名下载 URL 不进入普通输出或持久化配置。受控 HTTP 验证断点复用、忽略 Range 拒绝、摘要不匹配不发布以及来源/传输拒绝；不是实际 Ghidra 运行验证。

## Ghidra 当前阻塞

本轮尝试官方网页入口、官方 API 入口和 CDN。网页入口出现连接超时；逐片请求 API 曾触发匿名额度限制，现已改为每次下载只解析一次 API，后续直接请求 CDN。额度恢复后完成了一部分续传，但仍因范围请求超时终止。已缓存完整片段保留在 .tools，尚无整个归档的摘要验证，未解压启用引擎。

状态见 runtime/setup/ghidra-download.json，诊断和下载片段为本机运行材料，不提交。后续可直接重试：

```sh
.venv/bin/python scripts/install_engines.py --engines ghidra
.venv/bin/python scripts/verify_native_variants.py --engine ghidra
```

第二条是待执行的验收命令，当前不能写成已通过。Ghidra 导出脚本增加未知调用边、正文格式、时间预算与枚举未完成标记，但在实际编译运行成功之前仍属于未验收适配。现有 LLVM 结果不替代 Ghidra 的剥离函数恢复、字符串引用或伪代码证据；Swift Framework 当前仅有 LLVM 实测。
