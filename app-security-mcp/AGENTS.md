# 当前内容报告要求（2026-11-11，优先于下方历史记录）

当前插件 0.36.0，3 个 Skill、23 个工具。用户要求逐条列出有安全问题嫌疑的实际硬编码内容、位置、用途线索、风险依据及修复建议，不要只报告覆盖统计。Key 待核查项即使候选为零也要展示。用户已授权在权限 600 的本机核查文件中保存捕获原值，export_report 的 include_sensitive_values=true 返回该文件路径；普通 MCP 结果、默认报告和聊天继续脱敏。旧扫描无原值时复扫已有 artifact_id。不得把 Key 存在或普通地址/path 自动认定为漏洞，不承诺未覆盖代码也已列全。

先完成此内容可核查性与用户 APK 验收；不要恢复 artifacts/deferred-rea-capacity 中未完成的容量试验。真实 APK 仍是 partial、0 候选、1 个 google_api_key 待核查，原值已在本机报告验证。见 docs/CONTENT-REPORT-VALIDATION.md；57/57 严格回归通过、零跳过；统计见 artifacts/validation/acceptance-summary.json。继续本地开发，不访问服务器，不要求逐步确认。

# 自主分步交付约定

当前插件 0.35.0（3 个 Skill、23 个工具）。本轮补齐有界嵌套归档扫描/身份链及原生重新提取（0.33.0）、OpenSSH Ed25519/RSA/ECDSA 无口令单密钥解析（0.34.0）、共享数据目录的 POSIX 静态工作进程容量与孤儿进程删除保护（0.35.0）。真实 Ghidra 嵌套 ELF/IPA 各恢复 1 个引用函数；ssh-keygen 10 例兼容验证通过；用户 APK/IPA 最新复扫 partial、0 候选，无适用嵌套归档。56 项严格回归通过、零失败/零跳过；结果在 artifacts/validation/acceptance-summary.json。分步记录见 docs/NESTED-ARCHIVE-VALIDATION.md、docs/OPENSSH-KEY-VALIDATION.md、docs/SHARED-STATIC-CAPACITY.md。不删除 _capacity 的内核锁文件来释放槽位；REA 共享容量、目录锁恢复、自动保留清理及完整安全用途/一般数据流仍未完成。继续自主推进，不请求逐步确认。

- 最新用户授权：按步骤自主实现，每步完成后自行检查、测试并留下验收记录；通过后直接进入下一步，不再等待用户确认。
- 每步记录实现范围、测试结果、真实样本结果（如有）、证据路径及未完成项；失败先修复再复验，不把部分覆盖说成全部完成。
- 下文历史记录中的“停止等待验收/确认”已被本次授权替代。原有本地开发、秘密脱敏及服务器部署范围约束继续适用。
- 实施范围和验收基线见 docs/HARDCODING-SCAN-DESIGN.md。
- 第 3 步已实现两个平台插件 Skill 和持久化任务/取消/报告接口，插件 0.3.0。检测器尚未实现，任务最终 blocked、规则 not_run。必须等待用户验收后再进入第 4 步。

# 当前插件模式（优先于后续历史记录）

- 用户已选择插件方案：一次安装同时提供 MCP 和 Skill，允许 Skill 随插件落到插件缓存，不再另装到 ~/.codex/skills。
- 本机已安装 app-security@app-security-local；Skill 名为 app-security:app-security，独立 mcp_servers.app-security 已移除。
- npm run build:plugin 生成 artifacts/plugin-marketplace，npm run check:plugin 验证 Codex 的实际插件发现。
- 插件源在 plugin/，Skill 唯一源在 skills/；构建只复制白名单内容，禁止打包 token 或本地配置。
- 修改后需重新构建并更新插件缓存；不要运行旧 install:local 来恢复独立 MCP 配置。
- 暂不部署服务器，后续通过 Git 拉取部署。服务器仍为停止状态。

# 当前开发模式（优先于下方历史记录）

- 用户要求所有开发和验证先在本目录完成，仅在用户明确要求时操作远程服务器；本次用户已授权清除旧 MCP 代码，暂不部署新代码。
- 本机 Codex 使用本目录 dist/index.js 的 stdio MCP；用 npm run install:local 构建和配置。
- 不安装客户端本地 Skill。skills/app-security/SKILL.md 由 MCP Skills 扩展发布，get_workflow 提供普通 MCP 工具入口。
- 旧远程连接和客户端 Skill 已由本地安装脚本备份并移除；不要恢复旧安装器的 Skill 复制流程。
- 后续部署通过 Git 提交/推送，再由服务器拉取部署；当前未发布版本，不覆盖已发布的历史安装包。

# 当前服务器状态

- 2026-11-10 按用户要求已停止并禁用 app-security-mcp，删除两个旧 release、current 链接及公开的 0.1.0/0.3.0 安装包。
- 保留 runtime/node、service.env（固定 token）、systemd 单元、Nginx、证书和服务配置备份。公网 MCP 暂不可用。
- 待本地完成并通过 Git 推送后，服务器拉取同一套代码、构建、设置 current，再 enable --now；不要从历史包恢复。

# 远程部署约定（以下含历史记录，以当前状态为准）

- 先阅读 `deploy/SERVER.md`，使用已经配置好的 SSH 别名 `app-security-prod`，不要重新猜测用户名、大小写或认证方式。
- 用户指定密码认证；连接使用 `sh scripts/remote-ssh.sh '<远程命令>'`。密码由本机钥匙串经 askpass 读取，禁止写进代码、日志、提交或聊天。
- 当前实际部署为 systemd + Node，路径 `/opt/app-security-mcp`。仓库里的 Docker Compose 是另一种部署方案，不能直接在当前服务器运行以抢占现有 80/443。
- 操作前检查真实服务状态；更新采用新 release、编译测试、切换链接、重启和 MCP 协议验收。
- 不打印 `/etc/app-security-mcp/service.env` 或钥匙串内容。需要令牌时，在进程内捕获并传入子进程环境，输出仅限验证结果。
- 用户已选择复用现有域名。公网接口为 `https://www.hunluanshuihu.icu/mcp`，已通过 HTTPS 实际调用验收。Nginx 通过 `/etc/nginx/snippets/app-security-mcp.conf` 接入，修改后必须先 `nginx -t` 再 reload。
- HTTPS 使用 acme.sh + Let's Encrypt，webroot 为 `/var/www/acme`，每日 cron 检查续签并验证 Nginx 配置后 reload；不要删除 HTTP 的 `/.well-known/acme-challenge/` 路由。
- `examples/mcp-remote.local.json` 是本机生成的含令牌客户端配置，权限 600、已被 Git 忽略；禁止输出、提交或打包该文件。
- 分发安装包位于 `packages/connector`，与 private 服务端工程分离。查看 `deploy/DISTRIBUTION.md` 确认发布状态；当前 npm 包名尚未发布，不能宣称已支持仅凭 npm 包名安装。
- 安装包和源码中不得内置共享访问令牌。公开安装与匿名访问是独立决策，修改远程鉴权前须确认用户已选择匿名开放。
- 用户已选择当前阶段使用固定共享 token。复用服务器 `/etc/app-security-mcp/service.env` 的现有值；重启、部署更新和客户端接入不重新生成 token，只有用户明确要求更换时才轮换并同步客户端配置。

- 本机 Codex 的 app-security 已使用固定 `http_headers.Authorization`，不再依赖 token 环境变量。读取 config/get JSON 时捕获并脱敏，不直接输出凭证。当前服务版本 0.2.0，包含 5 个工具，运维记录见 SERVER.md。

- 统一安装器 0.3.0 已通过 HTTPS 发布，包含 setup/doctor 和 app-security Skill，npm 包名仍未发布。安装入口及验收记录见 `deploy/DISTRIBUTION.md`。
- 用户的本机 Skill 已安装到 `~/.codex/skills/app-security`。新启动的 Codex 已验证可发现该 Skill 和 MCP 工具；当前旧对话仍需重启刷新，不能冒称在旧会话中已直接调用新工具。
