# 自动 Android 方法复核（0.30.0）

## 行为

scan_android_hardcoding(profile="static-deep") 在基础检查后进入 automatic_method_corroboration 阶段，按 DEX 路径、类、方法名/原型去重，调用既有独立 REA 方法适配器。deep_method_limit 默认 3，最大 10；追加阶段总预算 150 秒，基础 Python 检查仍使用原 100 秒硬超时。

每个方法结束即保存脱敏验证，deep_scan 记录 eligible_methods、attempted_methods、recovered_methods、remaining_methods、候选范围和结束原因。remaining_methods 表示尚未尝试的数量；尝试过不等于成功恢复，需另外查看 recovered_methods 及具体 verifications。只有成功恢复方法体后，effective_profile 才显示 static-basic+rea-dex-corroboration；缺依赖或无候选时保持 static-basic。同方法的候选共享复核来源标识。

REA 阻塞后停止追加，保留基础候选和已保存复核。任务最终仍 partial，绝不把方法体恢复自动升级为 static_usage_confirmed 或漏洞。iOS 请求返回 automatic_native_verification_not_implemented，不猜测函数地址。

自动阶段共享本进程复核容量与跨进程 artifact 锁。cancel_scan 发送 AbortSignal，中止 REA 请求，迟到结果不覆盖 cancelled；清理结束前任务不能删除/释放深度容量。取消后的清理可能短暂滞后于状态返回。REA 由 SDK 关闭连接并停止其直接进程；不把该行为宣称为任意分析器后代进程的完整沙箱。

## 验收

- test/deep-scan.test.mjs：方法去重/共享结果、数量预算、无适用项、原生不适用、已取消信号、阻塞即停止；通过实际 stdio MCP + 模拟 REA 协议验证成功、缺依赖、运行中取消、直接进程结束、临时目录清理和结果不泄漏源文本。
- test/rea-verification.test.mjs：继续验证包摘要、方法重载、错误身份、重复类和临时目录清理。
- 完整严格回归 44/44，零失败/跳过；原有资源、取消、存储引用保护与协议回归保持通过。
- 安装缓存中的 0.30.0 + 真实 REA/JADX：合成 probe.apk 3 个候选，2 个符合条件的候选同属 1 个方法，只复核 1 次并恢复方法体。effective_profile=static-basic+rea-dex-corroboration，usage_confirmed=false。记录 artifacts/validation/auto-deep-fixture.json。
- 用户 APK：0 候选、0 适用方法、partial，reason=no_eligible_dex_findings，effective_profile=static-basic。记录 artifacts/validation/auto-deep-user-apk.json。

此步未改变 iOS 检测器，不重复扫描 IPA。新增 150 秒预算已进行真实等待的端到端验收：152432 ms 后 partial/deep_cancelled_or_timeout（含约 2 秒传输关闭等待），保留 1 个基础候选，直接提供方进程结束、临时目录移除、任务可删除。记录 artifacts/validation/deep-timeout-summary.json，复验命令 npm run check:deep-timeout。

## 剩余范围

自动结果仅是第二引擎方法身份和反编译体佐证；一般值流、跨 DEX/JNI、代码可达性、密钥实际使用和服务权限均未确认。iOS/ELF 的自动引用/函数发现以及完整原生安全用途判断仍需实现。真实配置的 REA/JADX 引擎可用性仍需目标级验证，依赖探测不作就绪保证。

## 实测修复记录

首次生产预算测试发现：SDK 在初始化握手失败时发起未等待的 close，随后的 close 调用可能立即返回，任务先结束而直接进程尚存活。新增单次传输关闭 Promise 共享封装，DEX 与原生适配器的 finally 等待同一个关闭任务；快速握手停滞/取消回归已确认进程结束、临时目录清理后才返回。修复后的生产预算复验通过（152432 ms）；未缩短生产计时器。
