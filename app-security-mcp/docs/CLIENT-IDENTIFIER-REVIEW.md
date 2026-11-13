# HC-012 标识清点与权限复核入口（0.13.0）

本步实现 HC-012 的前置清点，不实现服务端权限/误用确认。通过已支持的 JSON/plist 字段、文本赋值、XML string 字段、Android 解码资源和 DEX 字段上下文识别白名单标识；原生字符串仅在包含支持的字段赋值文本时可清点。

client_identifier 分类来自 client_id/oauth_client_id/google_client_id 字段；api_key_role_unknown 来自 api_key/google_api_key/firebase_api_key/android_api_key/ios_api_key 等字段。字段名只提供线索，不证明提供方、实际用途、公开性或秘密性。没有对任意长字符串猜测归属，不发送网络请求、不使用这些值验证权限。

## 结果读取

使用 get_scan_status 或 export_report 的 client_identifier_review：

- status=partial、misuse_assessment=not_evaluated。
- items 包含固定分类、位置、成员摘要、脱敏值和复核操作，不保留标识原值。
- permissions/application_restrictions/provider 为 unknown，misuse_confirmed=false。
- 最多 100 项，超出时 items_truncated=true。按证据位置去重，条数不代表不同凭证数量。

这些是清点记录，不计入 finding_count/list_findings，也不参与 compare_scans 候选分组。因此候选为零仍可能有标识待核查，不能宣称没有 API Key 或无需复核。

复核需要调用方提供可信的配置证据：服务提供方、使用的 API、应用绑定、允许权限、配额和服务端授权。不能仅凭客户端 ID 存在就要求轮换，也不能假定名为 api_key 的值可以公开。只有确认秘密或配置问题后才能给出针对性的限制/迁移/轮换结论。

## 本机验收（2026-11-10）

- 两平台合成资源各 5 个清点项、0 个漏洞候选；占位值、未解析资源引用、数字类型、注释和不相关字段反例通过。
- 每平台 105 个记录仅保留 100 个，截断标记通过；JSON/Markdown 报告不含原值。
- 实际编译 DEX 的客户端字段、四 ABI ELF 字符串赋值清点断言通过。
- 已安装插件 0.13.0：27 项测试通过、零跳过；Codex 发现 3 个 Skill、20 个工具。
- 用户原 APK：1 项 API Key 用途未知；Homewoo.ipa：2 项 API Key 用途未知、3 项客户端标识。两次未截断，常规候选均为 0，扫描 partial。这不构成泄露或误用结论。
- 本机机器记录：artifacts/validation/identifiers-real-android.json、identifiers-real-ios.json。

## 未完成

HC-012 的权限、应用限制及误用验证仍未实现；动态生成/混淆的标识、任意平台 Key 格式、跨函数用途和跨版本标识清点对比未覆盖。HC-009 仍无检测实现。其他规则仍部分覆盖，干净环境安装与服务器部署未完成。本步没有执行目标 App、联网验证标识或推送 Git。
