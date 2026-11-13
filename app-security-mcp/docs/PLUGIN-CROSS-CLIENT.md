# 双客户端安装与报告验收（0.29.0）

同一个 build:plugin 产物包含 Codex 与 Claude Code 的市场/插件清单，复用同一份打包 MCP 和三个 Skill。Claude Code 的 MCP 定义内联在 .claude-plugin/plugin.json，使用 CLAUDE_PLUGIN_ROOT；不让 Codex 的 mcp.json 发生冲突。

安装结构依据官方 [Claude Code manifest reference](https://code.claude.com/docs/en/plugins/manifest-reference) 和 [Create a marketplace](https://code.claude.com/docs/en/plugin-marketplaces)，并通过本机 CLI 验证。

## Claude Code

```sh
npm run build:plugin
claude plugin marketplace add ./artifacts/plugin-marketplace
claude plugin install app-security@app-security-local
```

在新会话的 `/` 菜单选 app-security 对应 Skill。2.1.318 的组件清单显示 android-check-hardcoding、app-security、ios-check-hardcoding 三个 Skill，以及 app-security MCP。它的客户端命令格式与 Codex 的 `$` 不同。

`npm run check:claude-install` 使用临时 HOME、CLAUDE_CONFIG_DIR 和插件缓存，不读取/复制用户认证。验证 manifest/marketplace、安装、组件清单、真实缓存位置；删除市场源后通过安装清单解析命令，SDK 握手并确认 23 个工具和 health_check。最后删除临时环境。结果在 artifacts/validation/claude-install-summary.json。

未发送模型请求，因此不把模型实际选择/执行 Skill 或交互菜单点击作为已验收项。当前没有向公共插件目录发布；目录发布的授权/许可证、图标等要求不是本地安装验收。

## 报告

Markdown 新增覆盖摘要、逐项观察、未知项、修复建议和复测步骤，并保留完整脱敏 JSON。包内路径/标题转义，不能注入 Markdown 链接、标题或破坏代码围栏。扫描持久化 effective_profile=static-basic，避免 deep 请求被误认为深度能力已完成。

测试：test/scan-report.test.mjs，加上原资源集成中的 JSON/Markdown 脱敏检查。

## 真实硬超时

`npm run check:worker-timeout` 独立执行生产 100 秒超时，用会休眠的 Python worker 和其子进程验证：100328 ms 后任务 failed/resource_scan_timeout，后代进程结束，结果可删除。记录 artifacts/validation/worker-timeout-summary.json。该测试不是缩短计时器的模拟，仅在本机 POSIX 验收。
