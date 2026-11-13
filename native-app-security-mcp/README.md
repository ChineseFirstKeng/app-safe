# 原生应用静态安全分析 MCP

独立的新工程，面向 Android Java/Kotlin 与 iOS Objective-C/Swift。当前 0.5.0：私有导入、异步任务、有限配置检查、JADX 方法索引、LLVM 原生函数与汇编索引、静态引用查询、Android 导出入口方法使用关联、部分 SSA 参数来源、证据和 Markdown/JSON 阶段报告已可运行；本机 MobSF 为可选基线。完整数据流、iOS 入口调查与 AI 调查尚未实现，不宣称完整评估或优于 REA。

- [完整设计](docs/DESIGN.md)
- [实施与验收](docs/IMPLEMENTATION.md)
- [与 REA 的质量对比要求](docs/REA-COMPARISON.md)
- [异步任务与报告验收（0.2 历史）](docs/A2-VALIDATION.md)
- [代码索引验收与覆盖限制](docs/B-CODE-INDEX-VALIDATION.md)
- [剥离符号、多架构与 Extension 验收](docs/B2-NATIVE-VARIANTS-VALIDATION.md)
- [Ghidra 与 Apple Silicon 本机反编译验收](docs/B3-GHIDRA-VALIDATION.md)
- [Android 导出入口关联验收（0.4 历史）](docs/C-ANDROID-ENTRY-VALIDATION.md)
- [SSA 参数来源与十组编译对照](docs/C2-ANDROID-SSA-VALIDATION.md)

## 隔离安装

需要 POSIX 系统和用于引导的 Python 3。当前在 macOS arm64 验证，未宣称 Linux/Windows 均已验收。运行环境固定 Python 3.12.16、MCP SDK 2.3.0，其余依赖记录在 uv.lock。

```sh
python3 -m venv .bootstrap
.bootstrap/bin/python -m pip install uv==0.13.7
UV_PYTHON_INSTALL_DIR="$PWD/.python" UV_CACHE_DIR="$PWD/.cache/uv" .bootstrap/bin/uv python install 3.12.16 --no-bin
UV_PYTHON_INSTALL_DIR="$PWD/.python" UV_CACHE_DIR="$PWD/.cache/uv" .bootstrap/bin/uv sync --locked --python 3.12
```

Python、环境、缓存保存在本工程内，不修改 shell 配置或客户端全局设置。真实包、数据库、原始报告及环境目录均在 .gitignore 中。

## 代码引擎准备

在工程根目录安装已锁定的 JADX，安装器支持分段续传，核对精确 Range、大小和最终完整 SHA-256 后才启用：

```sh
.venv/bin/python scripts/install_engines.py --engines jadx
```

当前引擎安装清单 engines.lock.json 面向 macOS arm64。Java 优先使用 NATIVE_SECURITY_JAVA_HOME，其次工程内 JDK，再次 Android Studio 内置 JBR；本机实际验证 JBR 25.0.2。需要完整 JDK 编译索引程序。原生索引使用 LLVM llvm-objdump，可由 NATIVE_SECURITY_OBJDUMP 指定，或从 PATH/Xcode 查找；本机验证 Apple LLVM 21.0.0。

Ghidra 12.2 已完成完整归档校验、本机原生组件编译，并实际通过 stripped ELF/Mach-O、arm64/arm64e fat 与 Extension 载体验收。Apple Silicon 需要额外构建反编译辅助程序：

```sh
.venv/bin/python scripts/install_engines.py --engines ghidra
.venv/bin/python scripts/build_ghidra_native.py
```

默认 auto 在已安装 Ghidra 时尝试它，失败留痕并回退 LLVM；可用 NATIVE_SECURITY_NATIVE_ENGINE=llvm 固定 LLVM，或 ghidra 强制它且不回退。Ghidra 可返回部分 c_like 伪代码，LLVM 返回 assembly；不承诺完整函数发现、ObjC/Swift 动态派发或跨组件调用图。详细实际范围见 B3 验收。

## 已实现的命令

```sh
.venv/bin/python -m native_security health
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" import /绝对路径/app.apk
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" members pkg_返回的64位摘要 --limit 100
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" analyze pkg_返回的64位摘要 --timeout 600
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" status an_返回的任务编号
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" results an_返回的任务编号 --kind finding
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" symbols an_返回的任务编号 --query 方法名
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" code an_返回的任务编号 cu_返回的代码编号
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" references an_返回的任务编号 cu_返回的代码编号 --direction outgoing
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" export an_返回的任务编号
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" serve
```

IPA 使用同一导入命令。格式根据包内结构识别，导入不是签名验证、可安装性检查或安全扫描。普通 ZIP 即使改后缀也不会被视为安装包。

当前 MCP 暴露十四个工具：health_check、import_artifact、list_artifact_members、start_analysis、get_analysis_status、list_results、get_result、read_evidence、cancel_analysis、export_report、list_code_symbols、get_code、get_code_references、export_code。SDK 客户端/服务端已实际通过 stdio 通信验收；未自动修改 Codex/Claude 的配置。

CLI analyze 等待结束；MCP start_analysis 立即返回任务编号。iOS 检查 App/Extension 的部分 Info.plist 声明，Framework/资源 bundle 的 ATS 键不当作宿主应用生效配置。Android 用实际 aapt2 检查明确 Manifest 配置，可从 PATH、ANDROID_HOME、ANDROID_SDK_ROOT 及常用 SDK 目录发现工具。缺依赖、损坏配置或资源引用无法恢复时记录覆盖缺口。

默认返回事实、攻击面和 needs_review 候选；普通结果不回显任意原值。明确布尔配置、结构计数、合法 scheme 等非秘密配置可读。需要原始证据时用 export_report 的 include_sensitive_values=true 或 CLI export --include-sensitive-values，仅生成权限 600 的本机文件。报告包含样本与证据摘要校验；被篡改的来源拒绝导出。

代码索引直接从包内 DEX、ELF、Mach-O 恢复，无需提供源码。查询普通代码时遮盖字符串、字符、数字常量与注释；符号名称仍是可读的不可信元数据。export_code（CLI export-code）只生成权限 600 的本机原值 JSON。每个组件记录包/成员/切片、引擎/适配器和原始索引摘要；无可用偏移时返回 null。当前最多分析 4 个 DEX、4 个原生切片，预算与遗漏均见覆盖记录。

list_results 返回 revision；任务运行中结果可能更新，续页携带 revision 可检测变化并要求重新分页。翻页完成不代表分析覆盖完成。

Android 任务在索引后自动关联显式导出入口与部分敏感 API。AND-ENTRY-001 仍为静态推断的攻击面：SSA 定义关系可区分已观察参数的常量、Intent API 返回值、混合及未知来源，并按调用位置绑定部分同 DEX 方法实参。常量参数也会列出，不当作漏洞；外部控制、权限、鉴权、运行路径和完整数据流尚未证明。结果的代码路径可通过 get_code 与 get_code_references 复核。read_evidence 和报告导出同时重验派生文件与原始 Manifest/JADX 依赖摘要；iOS 入口关联记为 not_implemented_ios。

任务状态为 queued/running/cancelling/partial/blocked/failed/cancelled/timed_out/interrupted。每个数据目录一个内核锁控制器，默认最多两个并发任务；其他控制器可以读取结果，但不能夺取调度。任务结束和会话退出终止其持有的工作进程组，运行任务记 interrupted、排队任务保留；下次控制器启动恢复队列，并撤销旧工作进程的发布权限。不会根据数据库中旧 PID 杀进程。

取消与硬超时停止本机工作进程，不保证终止独立 MobSF 服务端任务。容器隔离、内存/cgroup 限额及提供方出网限制尚未验收。

## MobSF 适配器

先在本机配置同步扫描的 MobSF 服务，将地址和凭证分别放入 NATIVE_SECURITY_MOBSF_URL 与 NATIVE_SECURITY_MOBSF_API_KEY 环境变量。地址仅允许 localhost、127.0.0.1、::1，禁止重定向、URL 内凭证和查询参数，不使用环境代理。服务必须单独限制出网；适配器的本机连接限制不等于 MobSF 容器已隔离。

```sh
.venv/bin/python -m native_security --data-dir "$PWD/runtime/data" baseline pkg_返回的64位摘要 --timeout 600
```

这是保留的同步开发入口；异步任务会调用同一适配器。缺配置时，配置检查仍可输出 partial 阶段报告；同步 baseline 命令则返回 blocked、退出码 2。收到提供方报告仅证明摘要匹配，security_assessment_complete 仍为 false。原始 HTTP 响应 JSON 保存为权限 600 的私有文件。仅投影已识别结构；缺少结构、截断与未知覆盖均明确记录。info/secure 规则不提升为风险候选。不支持 MobSF 自身的异步队列模式，尚未完成真实 MobSF 验收。

## 验收

```sh
.venv/bin/python scripts/acceptance.py
.venv/bin/python scripts/verify_android_manifest.py
.venv/bin/python scripts/verify_code_index.py
.venv/bin/python scripts/verify_mcp_code.py
.venv/bin/python scripts/verify_native_variants.py --engine llvm
.venv/bin/python scripts/verify_android_review.py
.venv/bin/python scripts/verify_mcp_review.py
```

第一项记录写入 runtime/validation/acceptance.json 和 acceptance.log，失败或跳过时返回非零。包含实际 stdio、工作进程、取消/超时/恢复、证据与报告，MobSF 使用受控 HTTP 对端。第二项要求已安装 aapt2 和 Android platform framework，实际编译二进制 Manifest 正反例并执行完整任务、检查规则、导出报告；记录在 runtime/android-manifest-verification/summary.json。该包只有配置，不计 DEX 或原生函数分析。

当前基础验收为 66 项全通过。代码专项验收用本工程源码实际编译 Java→DEX、Android ELF、Objective-C App 和 Swift Framework，随后分析 APK/IPA；MCP 专项通过真实 stdio 查询代码、引用及受限导出。记录分别在 runtime/code-index-verification/summary.json、runtime/mcp-code-verification/summary.json。编译不执行目标；这些已知答案样本不等于真实复杂业务覆盖验收。

0.4 新增实际剥离符号 APK/IPA、arm64/arm64e fat Mach-O 与 Extension 载体验证，以及四组 Android 入口代码对照和真实 MCP 入口追踪。Extension 仅验证静态载体，不验证安装或功能。详细记录见实施与专项验收文档。

0.5 通过实际 JADX 自定义 SSA pass 获取参数定义，不以 Java 文本匹配代替来源分析；十组编译 APK 对照涵盖赋值覆盖、不同调用实参、PHI 合流、未知返回值、非精确派发与内部 Intent。entry_review/data_flow 会区分部分 SSA 分析、没有入口未执行、SSA 缺失、失败和 iOS 未实现。详细预算与未知项见 C2 验收。
