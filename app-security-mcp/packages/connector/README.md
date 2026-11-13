# App Security MCP + Skill

一个命令为 Codex 配置远程 MCP，同时安装 `$app-security` Skill。需要 Node.js 22+、npm，以及服务提供方给出的固定 token。不需要 npm 账号登录。

## 安装

在你自己的终端运行：

```sh
npx -y https://www.hunluanshuihu.icu/mcp/install/app-security-mcp-0.3.0.tgz setup --client codex
```

首次安装按提示输入 token，输入不回显。安装器先连接远程 MCP，验证工具发现和健康检查；成功后写入配置和 Skill。已存在同地址的有效配置时自动复用 token。也可以通过 `MCP_AUTH_TOKEN` 环境变量提供 token，不支持将 token 作为命令行参数。

默认写入：

- `~/.codex/config.toml`：`mcp_servers.app-security` 地址、固定请求头和超时。
- `~/.codex/skills/app-security/`：Skill 指令和界面元数据。
- `~/.codex/backups/app-security/时间戳/`：原配置和原同名 Skill（如存在）。

设置了 `CODEX_HOME` 时，所有路径改为其下对应目录，适合隔离测试。只修改 app-security MCP 配置，其余配置值保留。常见 TOML 写法保留其他注释；复杂写法可能重新排版，原始注释留在备份中。配置和备份按权限 600 保存（Windows 权限效果受系统 ACL 影响）。

已有同名 Skill 会先备份再更新；重复运行且内容一致时不修改。鉴权或网络验证失败不会写入配置。不支持 symlink 配置文件/技能目录，会明确报错。

## 使用

完全重启 Codex 并新建对话，然后输入：

```text
$app-security
检查连接，并运行全部演示工具。
```

当前提供 health_check、echo、add_numbers、text_sha256、inspect_package_filename。Skill 指导 AI 调用工具，实际计算在服务器执行。文件名识别只检查后缀，不代表 APK/IPA 已经过安全扫描。

服务器新增业务工具通常不需要重装连接配置；更新 Skill 流程时执行新版安装命令。

## 诊断和安装预览

```sh
npx -y https://www.hunluanshuihu.icu/mcp/install/app-security-mcp-0.3.0.tgz doctor --client codex
npx -y https://www.hunluanshuihu.icu/mcp/install/app-security-mcp-0.3.0.tgz setup --client codex --dry-run
```

`doctor` 检查配置、Skill 文件、远程工具发现和健康状态。它不代表当前已打开的 Codex 对话加载了新 Skill 或工具；仍需重启并新建对话。

`--dry-run` 仅显示计划，不写文件、不发送 token。网络验证失败可检查固定 token、网络和服务地址后重试，不要将 token 发到公开日志。

`--url` 或 `MCP_URL` 可指定其他兼容端点（远程必须 HTTPS）。只有地址相同时才会复用旧 token，避免把旧凭证自动发给其他服务器。

## 仍可作为 stdio 连接器

不带子命令启动时，仍将本地 stdio 工具调用转发给远程 MCP。设置 `MCP_AUTH_TOKEN`；`MCP_URL` 默认是 `https://www.hunluanshuihu.icu/mcp`。工具参数会发给服务端，连接器不自动读取或上传本地文件。

当前只转发工具，不转发 resources、prompts 或服务器通知。包内不包含共享凭证。npm 包名尚未发布，请使用上面的 HTTPS 安装地址。

## 回退

如需要恢复配置，退出 Codex 后将本次备份中的 config.toml 复制回原位置；备份目录中的 skill 是之前的同名技能。恢复整份配置前确认安装后没有新增其他配置，否则请只恢复 app-security 对应部分。备份可能包含凭证，勿上传或分享。
