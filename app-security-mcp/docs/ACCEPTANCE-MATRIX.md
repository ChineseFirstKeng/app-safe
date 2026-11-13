> 0.36.0：逐条内容/Key 待核查项与本机原值报告，新增双平台内容集成测试和真实 DEX 原值校验。最新记录见 [内容报告验收](CONTENT-REPORT-VALIDATION.md)，完整回归以 artifacts/validation/acceptance-summary.json 为准。

> 0.33～0.35 最新增量：嵌套归档身份链、OpenSSH 格式解析和共享 POSIX 静态容量；56 项严格回归通过。当前进度见 [实施总账](IMPLEMENTATION-STATUS.md)。

> 0.31.0/0.32.0 最新增量：原生自动引用/函数复核，以及 PEM/DER 私钥格式解析。当前 51 项严格回归通过；完整当前状态见 [实施总账](IMPLEMENTATION-STATUS.md)。下方旧版本计数为历史记录。

> 0.30.0 增加有界自动 DEX 方法复核：44 项严格回归、真实 REA/JADX 验收与用户 APK 复扫通过，见 [自动复核记录](AUTO-DEEP-VALIDATION.md)。

> 当前版本 0.29.0：42 项严格回归零失败/零跳过；新增存储保护、SQLite、报告与 Claude 安装验收。完整最新状态见 [实施总账](IMPLEMENTATION-STATUS.md)，下文各版本数据保留为历史记录。

更新：插件 0.22.0 已通过 Codex 隔离配置安装、Skill/工具发现、双平台资源样本扫描及缺依赖降级专项验收，见 CLEAN-INSTALL-VALIDATION.md。仅覆盖当前 macOS 主机的独立 Codex 配置，不代表全新系统或 Claude Code 验收。当前确定性测试最近记录为 34 项通过；下文数量及未完成项包含历史记录。

更新：0.10.0 增加 HC-008 PBEKeySpec 固定盐正反例；当前严格验收共 22 项通过、零跳过。HC-008 已部分实现，原生地址对齐也已补齐，历史未完成项以相应功能文档为准。

# 当前实现的验收矩阵

2026-11-10：插件 0.8.0，19 项自动测试通过，0 失败、0 跳过。此次仅新增测试与验收入口，没有改变扫描行为或插件版本。

运行 `npm run test:acceptance`，结果写入 `artifacts/validation/acceptance.tap` 和 `acceptance-summary.json`。有失败、取消、跳过，或无法读到测试统计时，命令返回失败。普通 `npm test` 仍允许依赖缺失时跳过平台样本，不能用它的成功退出代替严格验收。

| 范围 | 已自动验证 | 测试文件 |
| --- | --- | --- |
| 导入/身份/存储 | 内容识别、SHA、分页、跨进程读取、删除不影响源包、错误平台 | artifacts.test.mjs |
| 危险归档 | 路径穿越、重复条目、文件目录冲突、符号链接、CRC 损坏、高压缩率 | artifacts.test.mjs |
| 资源候选 | 两平台文本/JSON/XML/plist/PEM、公开标识反例、报告脱敏、大小限制、候选截断、快照篡改 | resources.test.mjs |
| Android 编译资源 | 实际 AAPT2、资源引用、缺少解码器、损坏二进制 XML、解码输出和时间限制 | android-resources.test.mjs |
| DEX | 实际编译、multidex、字段、拼接、数组、密钥/IV 模式、分支保守处理、缺失依赖、损坏 DEX | dex.test.mjs |
| iOS 原生 | 实际多架构 App/Framework、加密 Extension 阻断、损坏镜像、大小端、fat64、重叠、UTF16、抽取身份校验 | ios-macho.test.mjs |
| Android 原生 | 实际四 ABI、JNI 导出、单层 Base64/Hex、损坏 ELF、大小端、无节表回退、抽取摘要校验 | elf.test.mjs |
| REA 适配 | 模拟提供器验证 DEX 身份/重载、候选状态、脱敏、临时目录清理 | rea-verification.test.mjs |
| 任务生命周期 | 真实工作进程并发上限、取消终止后代进程、取消状态不被覆盖、输出超限、异常输出、失败后容量恢复 | scan-lifecycle.test.mjs |
| 扫描对比 | 两平台前后包；保留组换值、移除组、新增组；失败状态、跨平台、截断、版本差异、同包复扫 | comparison.test.mjs |
| 连接与配置 | stdio 发现与参数、HTTP 鉴权与来源校验、连接器、配置保留与安装器回归 | stdio/http/connector/setup.test.mjs |

生命周期用专用可控工作进程验证真实调度和进程终止，不把其结果计为安全检测器识别能力。POSIX 进程组断言在 Windows 跳过，因此严格验收在 Windows 不会宣称通过。

## 依赖与证据边界

编译样本需要 Python 3、JDK、Android SDK（AAPT2、framework、D8、dexdump）、NDK 和 Xcode iPhoneOS SDK。测试中的默认 SDK 路径来自当前开发机；可用覆盖变量见各测试文件。严格验收不自动下载这些依赖。

REA 自动测试使用模拟提供器；此前已记录真实 Ghidra/JADX 定点验证，但本命令不重复真实引擎验证。此矩阵也不代表完整安全规则集：HC-008～HC-012、动态 JNI、跨函数/跨语言数据流、Flutter AOT 与自定义解码仍存在实现缺口。

## 尚未验收

- 干净用户环境的插件安装与依赖降级；Linux/Windows、Claude Code 的安装兼容性。
- 完整扫描工作进程 100 秒硬超时的端到端触发；当前自动测试覆盖的是解码器时间限制，以及扫描进程取消/输出限制。
- 所有归档预算边界的穷举、大规模模糊测试、真实加固壳样本。
- REA 原生提供器地址归一化与运行时敏感用途证明。

因此，本次完成的是当前已实现能力的回归矩阵与任务生命周期缺口补测，不宣称第 8 步或“所有硬编码问题覆盖”已全部完成。下一子步骤是隔离的干净用户配置安装验收。
