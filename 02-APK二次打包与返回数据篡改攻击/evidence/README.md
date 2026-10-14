# 运行时证据目录

本目录不预置账号、密码、Token、Cookie 或完整请求/响应。执行 `mock`、`verify` 后才会生成：

- `mock-events.log`：仅记录 Mock 收到目标路径的标记；
- `verify-*.xml`：仅保存与篡改标记相关的 UI 片段；
- `apk-sha256.txt`：记录被验证 APK 的哈希。

目录中的证据必须来自本次授权测试设备和本机 Mock。`restore-original` 只负责恢复原始 APK、校验签名并检查原始页面，不会自动删除服务端测试业务数据。
