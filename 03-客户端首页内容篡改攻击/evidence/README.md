# 运行时证据目录

本目录不预置账号、密码、Token、Cookie 或完整日志。执行 `verify`、`verify-landing` 后才会生成脱敏证据：

- `ui-*.txt`：只保存自定义首页的 UI 标记；旧版脚本产生的 `ui-*.xml` 也是筛选后的文本，并非完整 XML；
- `activity-*.txt`：只保存相关 Activity 行；
- `logcat-*.txt`：只保存覆盖逻辑、崩溃和显示进程相关行；
- `landing.log`：记录本机测试落地页收到的路径；
- `apk-sha256.txt`：记录被验证 APK 的哈希。
- `verify-*.txt`、`reopen-*.txt`、`landing-verify-*.txt`、`restore-*.txt`：新版脚本生成的设备哈希、重启、点击与恢复结果摘要。

目录为空表示尚未完成运行验证。测试结束后使用主流程的 `restore-original`，并人工确认测试账号和本机服务状态已清理。
