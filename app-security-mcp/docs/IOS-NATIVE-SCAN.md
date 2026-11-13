# iOS Mach-O 基础检查（0.6.0）

本步在资源检测之上增加多组件、多架构 Mach-O 的分段字符串检查，以及指定函数的独立 REA/Ghidra 复核。不会运行 IPA、绕过加密或验证包签名。

## 组件与切片

扫描 ZIP 中所有成员的文件头，不依赖可执行文件扩展名。App、Framework、Extension 的角色来自 bundle 路径，并读取 Info.plist 的 CFBundleExecutable；路径角色不代表组件实际加载。未声明可执行文件、缺文件或格式不符都会保留缺口。组件最多保留 128 项，多余项显式标记 components_truncated。

支持 thin Mach-O 32/64 位、大小端，以及 fat/fat64 容器。校验切片范围、重叠、对齐、CPU 元数据、load command 范围和 section 文件/虚拟地址范围。未知结构、越界和损坏切片标 blocked，其他有效切片仍可继续检查。

LC_ENCRYPTION_INFO/LC_ENCRYPTION_INFO_64 的 cryptid 非零时整片 blocked，不读取其中字符串；不会因为测试样本的加密区域仍是明文就继续扫描。没有加密标志只代表未标记，不证明没有加壳或自定义加密。

## 检测与证据

- S_CSTRING_LITERALS、常见 C/ObjC/Swift 反射字符串段中的 UTF-8 字符串。
- __ustring 的 UTF-16 字符串。
- __const/__data 中受限的可打印 ASCII 连续内容，只作为字面候选。
- 复用 HC-001/002/003/004/006 的密码字段、认证串、连接串和私钥封装模式；不将普通 client_id 或公开标识直接当成秘密。
- 完整值统一 [REDACTED]；证据包含包内路径、成员 SHA-256、切片索引/偏移/摘要、架构、section、文件偏移和虚拟地址。

Swift 小字符串、Objective-C 对象图/CFString 指针关系、运行时拼接/解密、常量到加密接口的数据流、原生代码行为均未全面处理。字符串存在、函数引用和漏洞确认是不同结论。HC-005/007 的 Android 参数规则不自动套用到 iOS。

`ios_native_scan.files_checked` 表示完成容器检查尝试，不等于每片成功。查看 files[].slices[].status、reason、section_gaps 与 slice 阻塞数量。正常总扫描仍是 partial；零候选不能说明安全。

## 资源上限

单个原生文件 64 MiB、累计 256 MiB；每个 fat 最多 16 个切片、每片最多 4,096 个 section；报告最多 128 个原生文件。累计切片达到 128 后不再启动下个文件（最后一个容器最多额外 15 片）。每个可读字符串段最多 8 MiB，每片累计 32 MiB、100,000 个字符串，单字符串最多 64 KiB。单片最多保存 32 条 section_gap，另外记录总数。受扫描总时限 90 秒及外部 100 秒限制。

基础 Mach-O 解析只需要现有 Python 标准库，没有新增平台 SDK 或第三方解析依赖。测试编译真实 Mach-O 使用 Xcode iPhoneOS/Simulator SDK；无 SDK 时对应编译测试明确 skip，格式边界测试仍运行。

## 独立函数复核

`verify_ios_finding(scan_id, finding_id, procedure)` 接收已知函数符号或提供方返回的函数地址；字符串地址不能当函数地址。

工具重新核对包、成员和切片摘要，提取单个未加密切片到私有临时目录，启动独立 REA MCP 会话，明确选定 native_provider（默认 ghidra），再调用 analyze_function。成功后关闭 REA、删除临时文件，不影响用户其他 REA 会话。普通异常会清理；进程被强制终止时可能留下私有临时目录。

配置复用 `~/.app-security/rea.json` 或 APP_SECURITY_REA_CONFIG；命令可由 APP_SECURITY_REA_COMMAND/APP_SECURITY_REA_ARGS 覆盖。JSON 配置可增加：

```json
{
  "native_provider": "ghidra",
  "env": {
    "JAVA_HOME": "/absolute/jdk-home",
    "GHIDRA_INSTALL_DIR": "/absolute/ghidra-install"
  }
}
```

这是对现有配置的字段说明，不是完整可运行配置；保留原 command/args 及其他平台所需环境。插件不下载或安装引擎，缺依赖会返回 blocked。本机只复用了已配置的 Ghidra 路径，未改 Codex 原 REA 配置。

报告保留 Evidence ID、提供方、函数地址及范围、伪代码 SHA-256 和字节数、原候选字符串地址及 string_reference_observed。后者只判断返回 referenced_strings 是否有精确地址匹配；false 不证明不存在间接引用。usage_confirmed 始终 false，不因伪代码恢复或静态引用升级为漏洞。伪代码明文和字符串值不写入报告。

## 格式依据

Mach-O 结构参照 Apple 开源的 [loader.h](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h) 与 [fat.h](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h)。这是受限静态检查器，不替代系统加载器、签名验证或完整反编译器。
