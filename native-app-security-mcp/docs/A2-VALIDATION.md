# 异步任务与阶段报告验收

> 本文保留 0.2.0 的历史验收范围。当前 0.3.0 已增加代码索引与十四工具，状态及新增实测见 [IMPLEMENTATION.md](IMPLEMENTATION.md) 和 [B-CODE-INDEX-VALIDATION.md](B-CODE-INDEX-VALIDATION.md)。

日期：2026-11-11；版本：0.2.0。当前主机 macOS arm64、Python 3.12.16、MCP SDK 2.3.0。整体设计见 DESIGN.md，后续接续见 IMPLEMENTATION.md。

## 已验证的运行链路

导入 APK/IPA → start_analysis 立即返回编号 → 独立进程配置检查与可选本机 MobSF → 持久化事实/攻击面/候选/证据/覆盖 → 状态与分页 → 重验证据 → 导出 Markdown/JSON。

完整安全评估未完成：代码索引、完整数据流与 AI 调查未实现，真实 MobSF 未运行。没有执行目标、访问包内域名、修改客户端配置、发布或部署。

## 可重复命令与产物

```sh
.venv/bin/python scripts/acceptance.py
.venv/bin/python scripts/verify_android_manifest.py
```

第一项：43 tests，0 failures、0 errors、0 skipped。产物 runtime/validation/acceptance.json、acceptance.log。第二项实际使用 SDK aapt2 link 编译二进制 Manifest 正反例，经相同任务进程处理并导出报告。产物 runtime/android-manifest-verification/summary.json、各任务的阶段报告和原始 aapt2 输出。

## 验收矩阵

| 能力 | 验证内容 | 边界 |
| --- | --- | --- |
| stdio MCP | 官方客户端启动真实服务子进程，发现十工具，导入、提交、查询、分页、详情、证据和导出 | 未自动接入用户当前客户端配置 |
| 异步工作进程 | 真实 Popen 工作进程、SQLite 检查点及原子结果 | 非容器隔离，无内存/cgroup 配额 |
| 取消 | 排队任务取消、运行任务进程组终止、迟到结果不覆盖取消 | MobSF 服务端可能继续 |
| 超时 | 真实阻塞 HTTP 场景触发 1 秒总预算，保留已有证据 | 无静态代码工具超时的全面穷举 |
| 重启 | 关闭时运行 interrupted、排队保留；新控制器恢复队列 | 运行中的引擎阶段不自动续算 |
| 控制器所有权 | 每目录 flock、不能夺取活控制器、旧 owner 发布拒绝 | POSIX，仅本机数据目录 |
| 队列与分页 | 16 项队列上限、revision 变化要求重读 | 未引入分布式服务 |
| 证据 | 跨包身份拒绝、来源篡改拒绝、导出前重验快照 | 不覆盖同账户管理员全部竞态 |
| 报告 | 默认脱敏、非秘密布尔/计数/scheme 可读、原值权限 600、HTML/Markdown 转义 | 阶段报告，非完整漏洞确认 |
| MobSF | 上传/摘要/错误/重定向/响应上限/候选投影/secure 反例 | 受控 HTTP，不计真实 MobSF 能力 |
| Android 配置 | 真实 aapt2 2.20-13193326；正例两规则、反例零命中 | 只有编译配置，无业务 DEX |
| iOS 配置 | 二进制 plist、ATS、scheme、Framework ATS 反例 | 无 ObjC/Swift 函数和实际应用运行 |

## 原生配置规则范围

- AND-CONFIG-001：application 显式 debuggable=true。
- AND-CONFIG-002：application 显式 usesCleartextTraffic=true。
- IOS-CONFIG-001/002：App/Extension 的 ATS 宽松配置声明。
- 导出组件、URL scheme、备份和文件共享为观察/攻击面，不直接判成漏洞。

Android 配置资源引用无法恢复时标记 partial；aapt2 缺失、输出失败单列。iOS 损坏、超预算、类型错误和数量限制单列；Framework 的 ATS 不提升成宿主风险。

提供方仅支持明确识别的 code_analysis.findings、binary_analysis.findings、manifest_analysis.manifest_findings。缺字段不按零漏洞处理；info/secure 保留观察；其他条目仍需独立代码复核。结果投影上限和完整源报告覆盖分开。

## 下一阶段

准备隔离 JDK/JADX/Ghidra 运行环境、编译原生业务正反例，建立真实方法和函数索引。真实 MobSF 与提供方出网隔离需要单独验收。与 REA 的报告质量比较尚未执行。
