> 当前状态（2026-11-10）：按用户要求已清除服务器旧 MCP 代码和公开安装包。
> 服务已停止并取消开机启动；两个旧 release 和 current 链接已删除。
> 保留 Node 运行时、固定 token、systemd/Nginx 配置、证书及服务配置备份。
> 当前公网 MCP 不可用，旧安装包下载不可用。后续本地验证通过、Git 推送后，由服务器拉取部署。
> 下方为历史记录，不代表当前运行状态。

# 当前服务器部署记录

## 本机连接配置

SSH 别名为 `app-security-prod`，准确地址、端口、用户名保存在本机 `~/.ssh/config`。使用密码认证，凭证保存在 macOS 钥匙串：account `root`，service `app-security-prod`。

`~/.ssh/app-security-askpass` 只在 SSH 密码提示时从钥匙串读取凭证，密码不写入源码、命令参数或日志。服务端主机密钥已保存到 `~/.ssh/known_hosts`；如果密钥发生变化，先核实原因，不跳过检查。

从项目目录运行：

```sh
sh scripts/remote-ssh.sh 'systemctl is-active app-security-mcp'
sh scripts/remote-ssh.sh 'journalctl -u app-security-mcp -n 30 --no-pager'
```

这些命令在新电脑上需要重新配置本机 SSH 别名、钥匙串凭证和 askpass 脚本，仓库中不携带密码。

## 服务端布局

- 系统：OpenCloudOS 9.2，使用 systemd；当前部署未使用 Docker。
- Node：复用服务器已安装的 v22.12.0，将可执行文件复制到 `/opt/app-security-mcp/runtime/node`，使独立服务用户可以执行。后续升级 Node 需同步更新这份运行时。
- 初始版本：`/opt/app-security-mcp/releases/20261109-initial`。
- 当前版本链接：`/opt/app-security-mcp/current`，指向 `/opt/app-security-mcp/releases/20261109-examples-0.2.0`。
- 独立运行用户：`app-security-mcp`，禁止交互登录。
- 配置与令牌：`/etc/app-security-mcp/service.env`，root 所有、权限 600。
- 服务：`/etc/systemd/system/app-security-mcp.service`，已启用开机启动和失败重启。
- 当前监听：`127.0.0.1:3000`；接口 `/mcp`，存活检查 `/healthz`。
- MCP 令牌在本机钥匙串也有备份：account `app-security-prod`，service `app-security-mcp-token`。不要直接执行读取命令将其输出到工具日志。

当前认证策略为用户指定的**固定共享 token**，不自动过期、不随服务重启或更新变化。各客户端配置一次后持续复用，仅在用户明确要求更换时同步更新服务端和客户端。实际值已填入 `examples/mcp-remote.local.json` 的 Authorization 请求头，无需每次生成或登录领取。

## 公网接入与验收

公网地址：`https://www.hunluanshuihu.icu/mcp`。2026-11-09 已从本机使用官方 MCP 客户端通过真实 HTTPS 验证初始化、工具发现及全部 5 个工具（health_check、echo、add_numbers、text_sha256、inspect_package_filename）；无令牌请求返回 401。

服务仅监听回环地址，由现有 Nginx HTTPS 虚拟主机转发。新增配置为 `/etc/nginx/snippets/app-security-mcp.conf`，在 `/etc/nginx/conf.d/shuihu.conf` 的 HTTPS server 内引入。已有 `/client/` 页面验收返回 200，原 API 根路径仍返回原来的 404。

本机完整客户端配置：`examples/mcp-remote.local.json`，含实际令牌、权限 600、Git 忽略。不要分享或提交该文件。无令牌模板为 `examples/mcp-remote.json`。客户端需支持 Streamable HTTP 和自定义 Authorization 请求头。

`MCP_PUBLIC_URL` 现为公网地址；本地回环及 SSH 隧道访问 `/mcp` 时必须发送公网域名 Host（`www.hunluanshuihu.icu`），否则会被 Host 校验拒绝。正常使用直接访问 HTTPS，不需要 SSH 隧道。

## 证书与自动续签

已将过期证书更新为 Let's Encrypt 证书，有效期至 **2027-02-07 01:06:21 UTC**。证书位置保持为 `/etc/nginx/ssl/www.hunluanshuihu.icu.pem`，私钥保持为同目录 `.key` 文件。

acme.sh 采用 `/var/www/acme` webroot 验证，HTTP server 增加 `/.well-known/acme-challenge/` 静态文件路由，其他 HTTP 路径仍跳转 HTTPS。现有 root cron 每天 22:04（服务器时区）执行续签检查，crond 已启用；续签成功执行 `nginx -t && systemctl reload nginx`。目前记录的下次续签时间为 2027-01-08 19:07:52 UTC，后续可能由 CA 的 ARI 建议更新。

本次变更前的 Nginx 配置、过期证书、ACME 域名配置及 MCP 环境文件备份在 `/root/app-security-mcp-backup-20261109-https`，目录权限 700。不要将该目录中的私钥或环境文件下载到仓库。回退业务路由时应保留有效的新证书及 ACME 验证路由。

## 更新与回退

后续更新先上传到新的 release 目录，在该目录安装锁定依赖、编译并测试，再切换 `current` 链接，执行 `systemctl restart app-security-mcp` 并运行实际 MCP 验收。保留上一版本，验收失败则将链接切回并重启。

不要把服务器 `service.env` 上传进仓库，不要覆盖现有令牌。当前版本保留开发依赖以便运行验收脚本；后续若裁剪依赖，需要为验收脚本保留独立运行环境。

## 本机 Codex 配置

`~/.codex/config.toml` 的 `mcp_servers.app-security` 已改为固定 `http_headers.Authorization`，取消 bearer token 环境变量依赖，权限 600。原配置备份为同目录 `config.toml.before-app-security-fixed-auth`。这两个文件均可能含凭证，不输出、不提交。已读取 Codex 解析后的配置，在不设置旧环境变量的情况下通过真实 HTTPS 验证 0.2.0 服务与新工具；当前对话需重启客户端并新建会话后才能获得新工具列表。

## 统一安装器 0.3.0

2026-11-10 已发布 `/mcp/install/app-security-mcp-0.3.0.tgz`，包含连接器、setup/doctor 和 app-security Skill。本机已通过公开命令完成安装，Skill 位于 `/Users/h1610/.codex/skills/app-security`；本次备份位于 `/Users/h1610/.codex/backups/app-security/2026-11-10T02-37-44-595Z-cad4482a`。

已通过真实 Codex app-server 发现启用的 Skill 和全部 5 个 MCP 工具。本次没有更新服务器业务代码或 token，业务仍为 0.2.0。详见 DISTRIBUTION.md。
