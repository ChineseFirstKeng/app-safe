> 当前状态（2026-11-10）：按用户要求已清除服务器旧 MCP 代码和公开安装包。
> 服务已停止并取消开机启动；两个旧 release 和 current 链接已删除。
> 保留 Node 运行时、固定 token、systemd/Nginx 配置、证书及服务配置备份。
> 当前公网 MCP 不可用，旧安装包下载不可用。后续本地验证通过、Git 推送后，由服务器拉取部署。
> 下方为历史记录，不代表当前运行状态。

# MCP + Skill 统一安装

## 已发布的 HTTPS 安装包

当前版本：**0.3.0**。不需要 npm 账号，只需本机 Node.js 22+ 和 npm。

用户在自己的终端执行：

```sh
npx -y https://www.hunluanshuihu.icu/mcp/install/app-security-mcp-0.3.0.tgz setup --client codex
```

首次安装按提示输入固定 token（不回显），已有同地址配置时自动复用。安装器验证 MCP 工具发现和 health_check 后，再写入：

- `${CODEX_HOME:-~/.codex}/config.toml` 中的 app-security MCP 配置。
- 同目录 `skills/app-security/` 中的 Skill 及 UI 元数据。
- 同目录 `backups/app-security/时间戳/` 中的原配置和原同名 Skill（如有）。

其他配置值保留；常见 TOML 格式的注释也保留。复杂 TOML 可能重新排版，原始版本始终备份。网络/鉴权验证失败不写入配置。原 Skill 会备份后更新，内容一致时重复安装不会反复修改。

完成后完全退出并重新打开 Codex、新建对话，输入：

```text
$app-security
检查连接，并运行全部演示工具。
```

它会调用 health_check、echo、add_numbers、text_sha256、inspect_package_filename。Skill 只负责指导调用，真正的工具逻辑在远程服务器。文件名识别只检查后缀，不是漏洞扫描。

## 诊断与预览

```sh
npx -y https://www.hunluanshuihu.icu/mcp/install/app-security-mcp-0.3.0.tgz doctor --client codex
npx -y https://www.hunluanshuihu.icu/mcp/install/app-security-mcp-0.3.0.tgz setup --client codex --dry-run
```

安装器默认连接 `https://www.hunluanshuihu.icu/mcp`。可用 `--url` 或 `MCP_URL` 覆盖地址；只有同地址才自动复用旧 token。非交互环境用 `MCP_AUTH_TOKEN` 提供 token，不支持把 token 直接放在命令行参数中。

`doctor` 证明配置文件、Skill 文件和协议链路正常，不代表旧对话已刷新。新会话仍需实际调用工具确认。

## 本次验证

2026-11-10：

- 6 项自动测试通过，覆盖连接器、stdio、HTTP、TOML 保留、安装备份、重复安装、错误凭证和无泄漏输出。
- 真实终端隐藏输入检查通过（测试使用无效假 token），字符不回显。
- 隔离 CODEX_HOME 首次安装、doctor、复用 token 的重复安装通过。
- 使用公开 HTTPS 安装命令完成本机安装，doctor 通过。
- 新启动的 Codex app-server 通过 skills/list 发现已启用的 app-security Skill，通过 mcpServerStatus/list 发现全部 5 个远程工具。
- 当前对话的工具/技能清单不会因安装自动重建，需要用户重启并新建对话。

## 包与托管路径

- 连接器及安装器：`packages/connector/bin/`。
- 配套 Skill：`packages/connector/skills/app-security/`。
- 打包：`npm pack ./packages/connector --pack-destination artifacts`。
- 包白名单：bin、skills、README.md、package.json；不含 token、服务器配置、私钥、测试数据或其他本地文件。
- 下载目录：`/var/www/app-security-mcp/install`。
- 版本 URL 不覆盖；更新时提供新的版本文件。
- 0.3.0 SHA-256：`2e2bde6b4e0bd77aad5c110a65ce8b7b383de68d66b9104fadbd22c50717875e`。
- 旧 0.1.0 安装包仍可作 stdio 连接器，但不含 setup 和 Skill。

## npm 发布状态

npm 包名尚未正式发布，不能使用 `npx app-security-mcp` 代替当前 HTTPS 命令。账号验证问题不影响 HTTPS 安装方式。将来发布到 npm 后，安装器参数不变，只将安装地址替换为包名即可。

本次仅发布静态安装包，服务器业务版本仍为 0.2.0。安装和业务版本独立更新。
