# Codex 隔离配置安装验收

验证版本：插件 0.22.0。本步仅新增验收脚本和说明，未修改检测器或升级插件。

执行 `npm run check:clean-install`。命令构建本地市场包，在独立临时目录创建空 Codex 配置和扫描存储，用已安装的 Codex CLI 注册临时市场、安装插件，再通过 Codex app-server 验证 3 个 Skill 与 21 个 MCP 工具。最终摘要写入 artifacts/validation/clean-install-summary.json，临时配置、安装缓存与样本存储随后清理。

脚本不复制现有 Codex 配置或认证文件，不继承凭证和 app-security 配置变量。保留当前主机 PATH/HOME；CODEX_HOME 和扫描存储仅在子进程环境指向临时目录。比较原 Codex config.toml 的前后摘要，不输出其内容。

## 已验证

- 插件安装路径实际位于临时 Codex 缓存；修正 macOS /var 与 /private/var 的路径规范化差异后检查。
- Codex 实际发现两个平台 Skill、通用 Skill 和 21 个工具，使用临时安装路径。
- 删除临时市场源目录后，安装缓存无需旁边的 node_modules 即可启动 MCP、导入样本、扫描并导出报告。
- Android/iOS 两个受控归档各包含一个合成密码配置；各产生 1 个 HC-001 候选，总状态 partial，导出报告不包含合成密码。
- 显式禁用 AAPT2/dexdump/REA 配置后，能力接口正确报告缺口；Android DEX 处理返回 dex_decoder_unavailable，不将依赖缺失解释为未发现问题。
- 另起进程指定不存在的 Python，能力接口 execution_verified=false。
- 原 Codex 主配置内容未改变。

Android 归档中的 DEX 是通过当前头部完整性校验的最小探针，只用于到达缺解码器分支，不是可安装运行的应用。两个平台样本均只验证安装后的资源扫描链路，不替代真实编译样本回归。

## 验收边界

这是同一 macOS 主机上的干净 Codex 配置验收，不是全新操作系统/新系统用户。继续使用已有 Node、Python、Codex 与 PATH；其他用户级目录或系统依赖未完全隔离，不声称完全空白主机可直接运行。未测试 Claude Code、Linux/Windows、公开市场下载、远程部署、首次引擎安装或自动安装依赖。

该专项单独运行，不计入现有 34 项确定性测试；实际执行结果 passed=true。两平台各 1 个候选是合成样本结果，本步未复扫用户 APK/IPA。
