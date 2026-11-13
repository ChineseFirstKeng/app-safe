# App Security MCP

本地 APK/IPA 硬编码安全候选检查。插件一次安装 MCP 与三个 Skill，逐项给出内容、位置、风险依据、修复建议和覆盖缺口；支持包含捕获原值的本机核查报告。

当前插件版本 **0.36.0**，**23 个工具**。检查资源、SQLite、Android DEX/ELF 和 iOS Mach-O 的支持范围；独立 REA 可定点复核方法/函数。扫描通常为 `partial`，**0 候选不表示安全**。两平台 `static-deep` 会追加有界 REA 复核：DEX 方法默认最多 3 个，ELF/Mach-O 原始字面量默认最多 2 个，与原生引用/函数定位共用追加的 150 秒预算。读取 `deep_scan` 和 `effective_profile` 区分成功、无适用项与受阻。完整安全用途和一般数据流仍未实现。支持的 PEM/DER/OpenSSH 私钥采用结构解析与 Node/OpenSSL 校验，公钥/证书不作为私钥候选。ZIP 容器支持有预算的递归检测，证据保留归档摘要链。同一数据目录下，POSIX 静态工作进程合计限制为 2；Windows 准入和共享 REA 容量仍未实现。

完整进度：[实施与验收总账](docs/IMPLEMENTATION-STATUS.md)。原始目标：[扫描设计](docs/HARDCODING-SCAN-DESIGN.md)。整体方案仍有实质性未完成范围，见总账。

## 构建

需要 Node.js 22+、npm、Python 3。Android 二进制资源/DEX 解码需 Android SDK 中的 aapt2/dexdump。可调用 `get_analysis_capabilities` 检查依赖和限制。独立 REA/JADX/Ghidra 复核需另行配置本机引擎。

```sh
npm ci
npm run build:plugin
npm run test:acceptance
```

## Codex 安装与使用

在工程目录执行：

```sh
codex plugin marketplace add ./artifacts/plugin-marketplace
codex plugin add app-security@app-security-local
npm run check:plugin
```

新会话选择：

```text
$app-security:android:check-hardcoding 检查 /绝对路径/app.apk
$app-security:ios:check-hardcoding 检查 /绝对路径/app.ipa
$app-security:app-security 检查连接
```

无需单独安装 Skill，也无需本地 token。安装使用插件缓存副本；更新源码后重新执行 `build:plugin` 和 `codex plugin add`，再打开新会话。旧独立同名 MCP 如果仍存在，会与插件冲突，需先移除旧配置。

## Claude Code 安装与使用

同一个构建产物支持：

```sh
claude plugin marketplace add ./artifacts/plugin-marketplace
claude plugin install app-security@app-security-local
```

新会话在 `/` 菜单选择 app-security 的 android-check-hardcoding 或 ios-check-hardcoding，提供绝对包路径。Claude Code 使用自己的命令菜单格式；不使用 Codex 的 `$` 语法。

已验证 Claude Code 2.1.318 的隔离安装、三个 Skill/一个 MCP 组件发现和安装缓存 MCP 握手；未把模型实际执行 Skill 作为已通过的测试。[安装验收记录](docs/PLUGIN-CROSS-CLIENT.md)。

## 工具流程

1. `import_local_artifact` 导入用户指定包，取得 artifact_id。
2. `scan_android_hardcoding` 或 `scan_ios_hardcoding` 创建任务；`get_scan_status` 查询结束状态及覆盖。
3. `list_findings` 分页/筛选；`get_finding` 获取修复建议，`read_evidence` 获取脱敏证据。
   同时查看 `client_identifier_review`，零候选也可能有 Key 待核查。需要具体值时调用 `export_report({scan_id,format:"markdown",include_sensitive_values:true})`，工具返回含原值的本机文件路径（权限 600）；聊天默认脱敏。旧扫描未保存原值时复用 artifact_id 重扫。见 [内容报告验收](docs/CONTENT-REPORT-VALIDATION.md)。
4. 有适用方法/函数身份时使用对应 `verify_*_finding` 做独立复核；不将反编译成功认定为漏洞确认。
5. `export_report` 导出可读 Markdown 或 JSON；`compare_scans` 比较规则/配置/覆盖一致性，不把未再检出认定为已修复。
6. 用户要求清理时，`cancel_scan` 取消活动任务，`delete_scan` 删除已结束结果和关联报告，再用 `delete_imported_artifact` 清理无引用快照。原始安装包保留。

数据默认保存在 `~/.app-security/artifacts`，可通过 `APP_SECURITY_DATA_DIR` 指定。不得将真实包、秘密、私有证据或服务凭证提交 Git。异常退出留下的 artifact 锁会保守阻止操作，见[存储验收](docs/SCAN-STORAGE-VALIDATION.md)。

## 验收命令

```sh
npm run test:acceptance
npm run check:plugin
npm run check:clean-install
npm run check:claude-install
npm run check:worker-timeout
npm run check:deep-timeout
```

worker-timeout 需要约 100 秒，验证基础 worker 生产超时及 POSIX 后代清理；deep-timeout 需要约 152 秒，验证 150 秒自动复核预算和停滞提供方清理。其余安装测试使用隔离配置；不是完整新操作系统验收。

## 源码与部署

- `src/`：MCP 契约、任务、报告和 REA 适配。
- `workers/`：包解析和有界静态检测。
- `plugin/`：客户端清单、两个平台 Skill；`skills/app-security/` 为通用 Skill。
- `scripts/build-plugin.mjs`：构建白名单插件市场，不打包凭证或 node_modules。
- `docs/`：设计、分步验收和限制；`artifacts/` 为忽略提交的本机产物。

当前工作和验证均在本地，未恢复远程服务。远程 HTTP 入口仍是早期演示能力，不可当作完整扫描服务部署。后续按 [部署记录](deploy/SERVER.md) 通过 Git 部署，沿用已授权服务配置；本轮没有执行发布、推送或服务器操作。
