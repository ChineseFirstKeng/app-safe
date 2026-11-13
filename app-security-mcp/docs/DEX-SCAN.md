# Android DEX 基础检测（0.5.0）

本步增加 DEX 常量/位置证据和独立 REA 方法复核。标准 DEX 字符串池按文件内 string_ids 提取并校验摘要；dexdump 解析静态字段及方法指令。不会运行 APK 或使用提取凭证访问服务。

## 已实现与边界

- 遍历 APK 中所有 `.dex` 条目，包含 multidex；仅支持标准 little-endian DEX 035/037/038/039/040，其他版本明确降级。
- 字符串池内容执行既有格式规则，证据含 string_index 和文件偏移；字符串存在不代表使用。
- 静态字段字符串、const-string/jumbo、直线赋值/部分 StringBuilder 与 concat、常量 byte 数组、getBytes，以及已知 key/value API 的参数。
- HC-005：可恢复的固定 bytes 传入 SecretKeySpec；HC-007：固定 bytes 传入 IvParameterSpec。不凭 `AES` 字样或字符串相邻就确认用途。
- 遇到分支、跳转、switch、异常入口的方法不传播值；未知指令/未知调用清空寄存器信息，不做跨方法/跨字段推断。复杂数组、引用传播、自定义编码/解密、反射、动态加载、加壳和 Flutter/native 均未全面分析。
- `dex_scan.files_checked` 表示受限常量检查流程结束，不表示方法用途完全覆盖。查看 methods_without_flow、methods_skipped_limit、failures；任务仍为 partial。
- 同一常量在字符串池和指令位置可能各产生候选；候选数量不是唯一秘密数量。UI 文案和第三方库示例仍可能误报，所有发现均为 candidate/needs_review。
- DEX 文件校验/解析失败独立记入 dex_scan，不抹掉已完成的资源结果。

## 依赖、上限与隐私

`APP_SECURITY_DEXDUMP` 指向绝对可执行路径；否则搜索 PATH，再查 AAPT2 所在 SDK build-tools 目录。已用 Android SDK Build Tools 36.0.0 验证；其他 dump 文本版本需要另行验证。

单个 DEX 32 MiB、所有 DEX 128 MiB；所有 dexdump 输出累计 192 MiB，单行 128 KiB，单方法最多 20,000 条指令。单个 dexdump 25 秒，总扫描内部 90 秒，外部 100 秒。超限必须报告缺口。原始 DEX 临时文件为私有目录，正常结束删除；取消时进程组被杀，极端中断可能留下私有临时目录。明文 dump 只在内存流中处理，诊断不进入报告。方法符号与偏移用于定位，完整秘密值不输出。

## 独立 REA 复核

`verify_android_finding(scan_id, finding_id)` 使用受控 MCP 客户端连接 REA，核对同一 APK 摘要，查找类和精确方法原型/重载，再恢复方法体。资源候选或只命中字符串池的候选没有方法定位，返回 not_applicable。

默认读取用户本机 `~/.app-security/rea.json`：

```json
{
  "command": "rea",
  "args": ["mcp"],
  "env": {
    "JAVA_HOME": "/absolute/jdk-home",
    "REA_JADX_MCP_JAR": "/absolute/jadx-headless-mcp-0.7.1-all.jar"
  }
}
```

这是启动结构示例，不表示 rea 已安装。可用 `APP_SECURITY_REA_CONFIG` 改配置文件路径，或用 `APP_SECURITY_REA_COMMAND`、`APP_SECURITY_REA_ARGS`（JSON 数组）覆盖命令并继承环境。缺配置/依赖返回 blocked，不能当作通过。插件不内置本机路径或自动安装 REA/JDK/JADX。本机开发环境已复用已有 REA 的启动信息写入私有配置，不修改 Codex 原 REA 配置。

结果保存在任务 `verifications[finding_id]`，含 Evidence ID、输入摘要、引擎身份、方法原型和源文本摘要；不保存明文方法体。`method_body_recovered` 只代表方法身份/方法体复核成功，`usage_confirmed=false`。它不是自动数据流验证，更不是漏洞确认。别名/重名无法精确匹配时停止复核。单次复核 150 秒、每个 MCP 进程最多一个。

## 验证

`npm test` 包含真实 javac + d8 编译的多 DEX 测试：字段、拼接、字节数组、密钥/IV 用途候选、分支与覆盖赋值负例、损坏 DEX、缺依赖和报告脱敏。测试使用 TEST_JAVA_HOME（默认本机 Android Studio JBR）及 SDK d8；依赖缺失明确 skip。

原 APK 仍是资源+DEX 的部分静态检查，不能用零候选推导安全。后续要补跨方法流、复杂常量还原和 Flutter/原生代码。
