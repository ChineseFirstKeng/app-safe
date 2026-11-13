# Homewoo Android APK 静态攻击面与危害评估

> 分析前提：**只拿到一个 APK**，不接触后端、不登录账号、不连接设备、不执行 APK。
> 本文所有结论均来自静态分析；标注为“待验证”的条目需要在获得授权的测试环境中动态确认。

---

## 0. 文档信息

| 项目 | 内容 |
|---|---|
| 分析对象 | `homewoo_1.0.0_202610191500_arm64.apk` |
| 文件大小 | 73,873,810 字节（约 70.5 MiB） |
| SHA-256 | `798cbb98d716e7cdb198b23c1c8162889e4dfaa6528babe0e8602102acac6172` |
| 包名 | `com.sdmc.homewoo` |
| 版本 | 1.0.0（versionCode 10193500） |
| 架构 | 仅 `arm64-v8a` |
| minSdk / targetSdk | 24 / 36 |
| 应用框架 | Flutter（`libapp.so` 14,615,432 字节，`libflutter.so` 11,747,864 字节） |
| 签名证书 | `C=CN, ST=Guangdong, L=Shenzhen, O=SDMC, OU=SDMC, CN=homewoo`；RSA 2048；SHA-256 指纹 `ba5a88384efa67b266332354677c121ffcf2354a701a09ef292ec09d7450ec41`；有效期 2026-07-13 至 2053-11-28 |
| 分析日期 | 2026-10-21 |
| 分析工具 | REA MCP（JADX headless、apktool、Flutter build identification、Ghidra、原始字符串扫描）、OpenSSL |
| 分析方式 | 纯静态；APK 未执行；未访问任何线上/测试服务 |

---

## 1. 执行摘要

### 1.1 一句话结论

**只凭一个 APK，拿不到后端数据库里的其他用户数据；但可以拿到一份相当完整的“攻击蓝图”。**

这份蓝图包括：

- 生产、开发、测试、UAT 四套后端地址；
- 70+ 条接口路径和完整的业务模块划分；
- OAuth 授权与回调的完整链路；
- MQTT 主题族和实时同步协议；
- 支付下单、Google 回调、补单回调接口；
- AI 语音助手的 WebSocket/TTS/历史存储设计；
- Firebase 项目、Storage bucket、Google API Key；
- AES-256/ECDH/RSA 的加密设计线索；
- release 包中保留的环境切换、Mock、Fake 代码。

### 1.2 最值得关注的五个点

| # | 风险点 | 为什么值得关注 |
|---|---|---|
| 1 | **OAuth 自定义 scheme 回调暴露** | `homewoo://calendar/google/complete` 可被同设备应用抢注；`MainActivity` 导出且会把回调 URI 原样转发给 Flutter。服务端 attempt 绑定是否严格，决定能否劫持账号绑定。 |
| 2 | **完整 API 面暴露 + 客户端无证明能力** | 74 条接口/路由字面量可直接恢复；未发现 Play Integrity / App Check / 应用层证书 pinning。脚本或改包可以直接调用生产 API。 |
| 3 | **MQTT 主题族完整暴露** | `awp.family.*`、`awp.device.*`、`awp.task.*` 等主题可读；若 broker ACL 未按家庭隔离，存在跨家庭窃听/伪造事件风险。 |
| 4 | **release 包保留测试/环境切换能力** | `Switch environment`、`CalendarMockHttpClient`、`FakeAppDatabase`、`mock-oauth-attempt-`、内部测试包名 `com.sdmc.onehome.sdmctest.app` 均在包内。 |
| 5 | **本地 AI 历史明文存储** | `cedar_history.db` 的 payload 直接存 JSON；`allowBackup` 未关闭，root/备份/改包场景下 AI 对话与家庭数据可被读取。 |

### 1.3 危害定性

对企业的实际危害不是“APK 泄露了数据库”，而是：

- **降低攻击成本**：攻击者不需要逆向业务，接口、参数、协议、环境已经摆在面前；
- **扩大攻击面**：客户端承担了本应由服务端承担的信任（环境选择、限流、会员权益、事件来源）；
- **放大现有缺陷**：一旦服务端存在 IDOR、限流缺失、OAuth 绑定不严、MQTT ACL 过宽，APK 就是现成的利用说明书；
- **品牌与合规风险**：家庭、儿童、日历、照片、语音数据都属于高敏感数据。

---

## 2. 分析手段与证据链

| REA 手段 | 实际产出 | 证据 ID |
|---|---|---|
| `inspect_android_package` | 包名、版本、SDK、权限、组件数量、类/资源计数 | `ev_a612b349f5d88ad632c600841e01b8af0ba152907236895460c805d3ad30daa8` |
| `decode_android_resources` | 完整可读 Manifest、深链、Firebase 配置、Google Key、字符串资源 | `ev_10f7d9a4a6a3016fe0056bcdc206359d51c9c956ed5f0dbc11b3dc1b4d17bda4` |
| `search_android_classes` | 自有 Java 类只有 `MainActivity` 和 `R`；业务逻辑全在 Dart | `ev_55eba370eff5ff5642c8b1dcf78ac545d169b9b6598f24a2adc477a55c79bb90` |
| `inspect_android_class` / `inspect_android_method` | `MainActivity.onNewIntent` 把 OAuth 回调 URI 转发给 Flutter；`m()` 对 OAuth intent 返回 `/calendar` | `ev_bab73570580a19d0a7fe4bbb35364bcf5923940f05b5384c48dd821a8edbed96`、`ev_7dfa69705de679f5451ade7f5069058cbc244bfce24e814edc4036d78d68a88b` |
| `identify_flutter_build` | `libapp.so` 快照哈希 `0451907c2eaa8467e848c0067bfe8ed4`；AOT 已 stripped | `ev_e73aa5f5641f28e33a157f4f7933d5c2d73a4103be087ec79f25edc0b28e8427` |
| 原始字符串扫描（`strings` + Python 过滤） | 434 个 `package:homewoo/src/...` 源文件路径、91 个第三方包、74 条接口/路由、MQTT 主题、SQLite 表结构、加密线索 | 见附录 A/B |
| 手工解析 APK v2 签名块 + OpenSSL | 签名证书主体、公钥算法、有效期、指纹 | 见第 0 节 |

### 2.1 关于 Dart AOT 的说明

- `libapp.so` 是 stripped ELF，`inspect_dart_aot` 因 `_kDartVmSnapshotData` 等动态符号缺失而无法解析；
- `identify_flutter_build` 只发现 1 个 snapshot section（正常 AOT 通常为 2 个），说明该库被裁剪或使用了非标准构建；
- 但 **Dart 侧没有做混淆**：434 个 `package:homewoo/src/...` 路径、类名、方法名、接口路径、MQTT 主题全部可读；
- 因此本次用原始字符串池还原了大部分应用结构。攻击者若使用 Blutter/reFlutter 等 Dart AOT 工具，可以进一步恢复伪代码。

---

## 3. 从 APK 获取的信息

### 3.1 应用画像

- 包名：`com.sdmc.homewoo`
- 版本：1.0.0（10193500）
- 框架：Flutter，`MainActivity` 继承 FlutterActivity
- 权限：

| 权限 | 用途推断 |
|---|---|
| `INTERNET`、`ACCESS_NETWORK_STATE` | 网络 |
| `CAMERA` | 扫码添加设备、Cedar 拍照 |
| `RECORD_AUDIO` | Cedar 语音助手 |
| `POST_NOTIFICATIONS` | 本地/推送通知 |
| `READ_EXTERNAL_STORAGE`、`WRITE_EXTERNAL_STORAGE`（maxSdk 28） | 相册/图片选择 |
| `WAKE_LOCK` | 后台同步/推送 |
| `com.android.vending.BILLING` | Google Play 订阅 |
| `com.google.android.c2dm.permission.RECEIVE` | FCM |
| `USE_BIOMETRIC`、`USE_FINGERPRINT` | 本地认证/家长锁 |
| `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` | AndroidX 动态接收器保护 |

- 导出的组件：
  - `com.sdmc.homewoo.MainActivity`：`exported=true`，带 `homewoo://calendar/google/complete` 深链；
  - `FlutterFirebaseMessagingReceiver`、`FirebaseInstanceIdReceiver`：受 `com.google.android.c2dm.permission.SEND` 保护；
  - `RevocationBoundService`：受签名级 `REVOCATION_NOTIFICATION` 权限保护；
  - `ProfileInstallReceiver`：受 `android.permission.DUMP` 保护。
- Manifest 未声明：
  - `android:allowBackup="false"`
  - `android:dataExtractionRules`
  - `android:fullBackupContent`
  - `android:networkSecurityConfig`
  - `android:debuggable`

> 结论：只有 `MainActivity` 是“无权限保护且导出”的组件；其余导出组件均有系统/签名权限保护。`allowBackup` 未关闭，默认允许备份。

### 3.2 后端与 API 面

#### 3.2.1 后端地址

生产：

- `https://cloud-api.sdmc.tv/cloud/v5.0/`
- 支付服务：`/aihome/cloud-api/payment-server/`

开发/测试/UAT（硬编码在 `libapp.so` 字符串池）：

- `https://xhome-dev.sdmc.tv:18443/aihome/cloud-api/cloud/v5.0/`
- `https://xhome-test.sdmc.tv:18443/cloud-api/cloud/v5.0/`
- `https://xhome-uat.sdmc.tv:18443/XHome-dev/cloud/v5.0/`
- `https://xhome-dev.sdmc.tv:18443/H5-Help_Support.html`

配置项字符串：

- `XHOME_API_BASE_URL`
- `XHOME_PAYMENT_API_BASE_URL`
- `XHOME_CLIENT_ID`
- `XHOME_SECRET_KEY`（要求 32 字符 ASCII，用于 AES-256）

#### 3.2.2 接口清单（从字符串池恢复）

> 以下为相对路径字面量；实际请求会拼接 `XHOME_API_BASE_URL` 或支付专用 base URL。
> 完整清单见附录 A。

账号与用户：

- `user/login`
- `user/register`
- `user/thirdAuth/login`
- `user/logout`
- `user/account/delete`
- `user/data/export/create`
- `profile/create`

家庭与成员：

- `family/create`
- `family/update`
- `family/delete`
- `family/info`
- `family/list`
- `family/member/list`
- `family/member/remove`
- `family/member/leave`
- `family/member/profile/save`
- `family/member/profile/update`
- `family/member/home-tags/options`
- `family/member/home-tags/custom/add|update|delete`
- `family/member/info/color/used/list`
- `family/invitation/join/code/generate`
- `family/invitation/join/code/preview`
- `family/invitation/join/code/apply`
- `family/invitation/join/approve`
- `family/invitation/join/detail`
- `family/invitation/join/pending/list`
- `family/data/export/create`
- `family/data/export/verification-code/send`

日历：

- `calendar/event/create`
- `calendar/event/update`
- `calendar/event/delete`
- `calendar/event/list`
- `calendar/event/detail`
- `calendar/event/detail/by-event-id`
- `calendar/event/check-conflict`
- `calendar/external-connection/list`
- `calendar/external-connection/disconnect`
- `calendar/google/oauth-attempt/create`
- `calendar/google/oauth-attempt/detail`

任务与清单：

- `task/definition/create`
- `task/definition/update`
- `task/definition/delete`
- `task/definition/detail`
- `task/definition/detail/by-task-id`
- `task/definition/claim`
- `task/definition/reassign-claimant`
- `task/instance/complete`
- `task/instance/undo-status`
- `task/query/all`
- `task/query/range`
- `v5.0/list/ai/query`

设备与配对：

- `device/list`
- `device/update`
- `device/delete`
- `device/pairing/code/bind`
- `device/pairing/qrCode/bind`
- `awp/device/detail`
- `awp/sub-device/member/bind`
- `awp/app/notification/setting/detail|save`
- `awp/app/reminder/setting/detail|save`

家长控制：

- `permission/pin/config`
- `permission/pin/save`
- `permission/pin/disable`
- `permission/pin/forgot`

支付：

- `v1/order/checkout`
- `v1/payment/google/callback`
- `v1/payment/google/repair/callback`
- `store/account/subscriptions`（另一处字符串）

AI / 语音：

- `aichat/getWSToken`
- `aichat/agentapp/config/query`
- `ai/chat/group/add`
- `ai/chat/group/query`
- `ai/chat/history/list`

实时通道：

- `common/mqtt/info`

主页：

- `home/count`

### 3.3 认证与 OAuth

#### 3.3.1 登录方式

- 邮箱 6 位验证码登录/注册（`user/login`、`user/register`）；
- Google / Apple 第三方登录：`user/thirdAuth/login`；
- 部分账号支持密码找回，但字符串提示“该账号不支持密码验证，请使用邮箱验证码”；
- 客户端存在验证码重发、5 分钟锁定、10 分钟配对锁定等**客户端侧**限制。

#### 3.3.2 日历 Google OAuth 链路

1. App 调 `calendar/google/oauth-attempt/create`，服务端创建 OAuth attempt；
2. 服务端返回 `authorizationUrl`（Google OAuth 授权地址）；
3. 用户在浏览器完成授权，Google 重定向到 `homewoo://calendar/google/complete?...`；
4. Android 把该 URI 交给导出的 `MainActivity`；
5. `MainActivity.onNewIntent` 判断为 OAuth 回调后，将完整 `intent.getDataString()` 通过 `oauthCallback` 转发给 Flutter；
6. Flutter 调 `calendar/google/oauth-attempt/detail` 完成绑定。

关键代码事实（JADX 反编译）：

```java
public final void onNewIntent(Intent intent) {
    ...
    if (!x.a(intent)) { ... notificationTapped ... return; }
    setIntent(intent);
    e eVar = this.f7841y;
    if (eVar != null) {
        String dataString = x.a(intent) ? intent.getDataString() : null;
        if (dataString == null) return;
        eVar.f8114t = dataString;
        ((B) eVar.f8113s).C("oauthCallback", dataString, new p(eVar, dataString));
    }
}
```

风险点：

- 自定义 scheme `homewoo://` **不是 Android App Links**，同设备其他应用可以注册同名 scheme；
- `MainActivity` 导出，任意应用可以向已运行的 HomeWoo 发送伪造的 `homewoo://calendar/google/complete?...`；
- 客户端字符串中**没有发现** `code_challenge` / `code_verifier` 的构造；PKCE 是否由服务端在 `authorizationUrl` 中实现，需要抓包确认；
- 最终是否可劫持账号绑定，取决于服务端是否把 attempt 与发起账号、state、一次性使用严格绑定。

结论：**回调暴露是已证实的；可利用性待动态验证**。这正是仓库 `04-外部链接与OAuth回调伪造验证` 目录所针对的方向。

### 3.4 MQTT 实时通道

恢复出的主题族（节选）：

- 家庭：
  - `awp.family.member.created`
  - `awp.family.member.deleted`
  - `awp.family.member.left`
  - `awp.family.member.updated`
  - `awp.family.owner.transferred`
  - `awp.family.join.applied`
  - `awp.family.join.approved`
  - `awp.family.updated`
  - `awp.family.deleted`
  - `awp.family.address.updated`
- 设备：
  - `awp.device.reset`
  - `awp.device.unbound`
  - `awp.pocket.device.created|deleted|updated`
  - `awp.pocket.reminder.setting.updated`
- 任务：
  - `awp.task.create`
  - `awp.task.update`
  - `awp.task.delete`
  - `awp.task.reminder.due`
  - `awp.task.sync.changed`
- 清单：
  - `awp.lists.list.created|deleted|updated`
  - `awp.lists.item.created|deleted|updated`
  - `awp.lists.section.created|deleted|updated`
- 日历：
  - `awp.calendar.event.created|updated|deleted`
  - `awp.calendar.reminder.start`
  - `awp.calendarevents` / `awp.calendarEvents`
- 家长锁：
  - `awp.parent.pin.enabled`
  - `awp.parent.pin.disabled`

连接信息：

- 通过 `common/mqtt/info` 下发；
- 字符串中存在 `Unable to decrypt or parse XHome MQTT URL`，说明 MQTT URL 是加密下发的；
- 配置项包括 `XHome MQTT host`、`XHome MQTT port`、`XHome MQTT mqttUrl`。

风险点：

- 主题命名、事件类型、payload 模型（`CalendarMqttEnvelope`、`FamilyMqttEnvelope`、`TaskMqttEnvelope` 等）全部可从包内还原；
- 若 broker ACL 仅校验“已登录客户端”而不校验“该家庭/该用户是否拥有该主题”，则存在跨家庭订阅/发布风险；
- 若客户端仅凭 topic 信任事件来源，伪造 `awp.device.unbound`、`awp.family.member.deleted`、`awp.task.*` 可能导致设备解绑、数据错乱、骚扰通知。

### 3.5 本地数据与加密

#### 3.5.1 本地存储

| 存储 | 内容 | 保护 |
|---|---|---|
| `flutter_secure_storage` | Token、部分安全偏好 | Android `EncryptedSharedPreferences`（Keystore） |
| `cedar_history.db` | AI 会话历史 | 明文 SQLite |
| `wall_planner_privacy_agreement.json` | 隐私同意状态 | 明文文件 |
| SharedPreferences | 语言、推送、环境等 | 普通 XML |

AI 历史表结构（字符串池可读）：

```sql
CREATE TABLE cedar_history_archives (
  scope ...,
  conversation_id TEXT ...,
  payload ...,
  PRIMARY KEY (scope, conversation_id)
);
CREATE TABLE cedar_history_messages (...);
CREATE TABLE cedar_history_scopes (...);
INSERT INTO cedar_history_archives(scope, conversation_id, payload) VALUES (?, ?, ?);
ON CONFLICT(scope, conversation_id) DO UPDATE SET payload = excluded.payload;
```

风险点：

- `payload` 直接存 JSON，未见 SQLCipher/字段加密；
- `allowBackup` 未显式关闭，且没有 data extraction rules；在 root、备份提取、改包场景下可读取；
- AI 历史可能包含家庭地址、日程、成员信息、语音转写等敏感内容。

#### 3.5.2 加密设计线索

字符串中可读：

- `XHOME_SECRET_KEY must be 32 ASCII characters for XHome AES-256.`
- `Missing XHOME_SECRET_KEY. Provide it with --dart-define or a local env file.`
- `AES-256`
- `AES/CBC/PKCS7`
- `AES_GCM_NoPadding`
- `ECDHKeyDerivator`
- `RSA_ECB_OAEPwithSHA_256andMGF1Padding`
- `RSA signing with digest`
- `_encryptEventBody` / `_decryptEvent` / `_encryptField` / `_decryptPage` / `_decryptAddressText`

判断：

- 应用存在请求/响应字段级加密（日历事件体、地址、分页数据等）；
- `XHOME_SECRET_KEY` 是 32 字符 ASCII 的全局对称密钥；
- 本次静态扫描**没有直接命中**这个 32 字符字面量，说明它可能来自构建注入、运行时派生或编码；
- 但“客户端内置全局对称密钥”这个设计本身，应视为可被提取；具体密钥值需要动态分析确认。

### 3.6 云配置

| 配置 | 值 |
|---|---|
| Firebase 项目 | `homewoo-530e0` |
| Google App ID | `1:178660147794:android:92bf7c0eb436a086ef958b` |
| FCM Sender ID | `178660147794` |
| Storage bucket | `homewoo-530e0.firebasestorage.app` |
| Google API Key | `AIzaSyBwv…`（资源中可读） |
| Google Maps API Key | `AIzaSyCvA…`（资源中可读） |
| OAuth Web Client ID | `178660147794-q4534ns2qfuk7qp7ka2qnkrtmg6vj48g.apps.googleusercontent.com` |

说明：

- 客户端内置 Google API Key 本身不是“泄密”，Google 也按此设计；
- 但如果 Key 没有限制包名 + SHA-1 + API 范围，攻击者可以刷 Maps 配额、滥用 Identity Toolkit、或在 Firebase 规则过宽时访问 Storage；
- Firebase Storage 中可能存有家庭照片等敏感数据，规则必须在控制台侧验证。

### 3.7 调试 / 测试残留

包内保留的字符串与类名：

- `Switch environment`
- `auth-environment-sheet`
- `auth-environment-option-`
- `handleEnvironmentUnlockTap`
- `homewoo_environment.xml`
- `CalendarMockHttpClient`
- `MockCalendarRepository`
- `FakeAppDatabase`
- `mock-oauth-attempt-`
- `mock-google-oauth-`
- `https://accounts.google.com/o/oauth2/v2/auth?mockAttempt=`
- `com.sdmc.onehome.sdmctest.app`（内部测试包名）

判断：

- release 包中保留了环境切换 UI、环境持久化逻辑、Mock OAuth、Mock Calendar、Fake 数据库；
- 环境切换的具体解锁手势/入口属于运行时逻辑，静态无法完全确认是否可达；
- 即使不可达，这些代码也泄露了内部环境命名、测试包名和测试协议，降低了攻击者理解系统的成本。

### 3.8 客户端防护现状

未发现以下能力的字符串/配置证据：

- Firebase App Check
- Google Play Integrity
- SafetyNet / 设备证明
- root / Frida / Xposed 检测
- 应用层证书 pinning（TLS pinning）
- Dart 代码混淆（源码路径、类名、方法名可读）
- 服务端可验证的客户端签名（请求签名/attestation）

注意：

- “未发现”是静态字符串层面的证据，不排除 native 层实现；
- 但结合 Flutter 默认网络栈、无 pinning 配置、无 App Check 依赖来看，**服务端很难区分“官方客户端”和“脚本/改包客户端”**。

---

## 4. 攻击面 → 危害映射

| # | 危害场景 | 前提条件 | 可能影响 | 证据/成熟度 |
|---|---|---|---|---|
| 1 | **二次打包 / 仿冒分发** | 能把改包发到第三方商店、群聊、钓鱼页 | 窃取邮箱验证码、Google/Apple 令牌、录音/相机/相册、日历；伪造支付页；绕过本地会员 entitlement；品牌诈骗 | 仓库 `02-APK二次打包与返回数据篡改攻击` 已有改包产物；本 APK 无完整性校验、无混淆，成本低 |
| 2 | **OAuth 回调劫持 / 账号绑定劫持** | 恶意 App 抢注 `homewoo://`，或向已运行的 App 发送伪造回调；服务端 attempt 未严格绑定账号/state | 受害者 Google 日历被绑定到攻击者账号，或攻击者获得受害者日历数据；日历注入/隐私泄露 | Manifest + `MainActivity.onNewIntent` 已证实回调暴露；服务端绑定待动态验证（仓库 `04-外部链接与OAuth回调伪造验证`） |
| 3 | **接口越权 / IDOR + 自动化** | 任意普通账号 + 服务端对象级鉴权缺失 | 跨家庭读取日历、成员资料、儿童生日、任务/清单、设备信息；批量导出；账号接管 | 74 条接口路径暴露；`family/member/*`、`settings/devices/:id`、`calendar/event/detail` 等是重点测试对象 |
| 4 | **设备配对码 / 验证码暴力破解** | 服务端限流不严，仅依赖客户端 5/10 分钟锁定 | 抢先绑定设备、解绑设备、账号接管、家庭邀请码爆破 | 客户端锁定字符串存在；客户端锁可被脚本绕过；服务端限流待验证 |
| 5 | **MQTT 越权订阅 / 伪造事件** | 任意账号 + broker ACL 未按家庭隔离 | 跨家庭窃听成员/设备/任务事件；伪造 `awp.device.unbound`、`awp.family.member.deleted` 等造成设备解绑、数据错乱、骚扰通知 | 主题族完整暴露；`common/mqtt/info` 下发连接信息；ACL 待验证 |
| 6 | **全局 AES 密钥提取 / 协议伪造** | 动态分析拿到 `XHOME_SECRET_KEY` 或派生密钥 | 解密/伪造 XHome 协议 payload、冒充客户端、绕过应用层校验 | 设计要求 32 字符全局 AES-256 密钥；静态未命中，需动态确认 |
| 7 | **支付回调 / 订阅绕过** | 服务端 purchaseToken、订单号、用户绑定、防重放校验不严 | 白嫖会员、伪造购买回调、重复使用 purchaseToken，收入损失 | `v1/order/checkout`、`v1/payment/google/callback`、`repair/callback` 暴露；SKU `com.sdmc.homewoo.premium`、`.lifetime` 可读 |
| 8 | **云资源滥用 / 数据泄露** | Google Key 未限制、Firebase Storage 规则过宽 | Maps 配额/账单被刷、Identity Toolkit 被枚举/批量注册、家庭照片 bucket 被读 | Key、项目号、bucket 均暴露；规则需在云控制台验证 |
| 9 | **本地隐私数据泄露** | root、备份提取、或恶意改包 | AI 对话、家庭地址、日历、儿童/家庭成员信息、语音转写被读 | `cedar_history.db` 明文 payload；`allowBackup` 未关闭 |
| 10 | **测试环境暴露** | 环境切换在 release 可达 | 攻击 dev/test/UAT，测试账号/测试数据泄露；预发环境通常防护更弱 | 三套环境地址 + 环境切换 UI/持久化逻辑在包内；可达性待验证 |
| 11 | **信息泄露 / 竞争情报** | 无 | 完整 API、模块划分、产品路线、供应商栈被获取 | 已证实 |

### 4.1 对企业的影响维度

- **资金**：云资源账单、支付欺诈、会员绕过、AI/语音算力滥用、应急响应成本；
- **品牌**：仿冒 App、钓鱼、用户数据泄露导致的信任损失；
- **合规**：家庭/儿童数据、语音、照片、日历、地址等敏感信息，涉及 GDPR/PIPL/COPPA 等合规要求；
- **运营**：MQTT 伪造事件导致设备解绑、数据错乱、客服压力；
- **竞争**：完整 API 和产品功能图被竞争对手获取；
- **供应链**：91 个第三方包、测试环境、内部包名暴露，扩大后续攻击面。

---

## 5. 典型风险场景（概念级描述）

> 以下仅描述风险路径，不包含可直接执行的利用代码或攻击步骤；实际验证应在获得授权的测试环境中进行。

### 5.1 仿冒客户端

攻击者以官方 APK 为基础，修改 UI/注入代码后自签名分发。由于包内没有完整性校验、没有 App Check、Dart 未混淆，改包成本很低。用户看到的是熟悉的 HomeWoo 界面，但输入的邮箱验证码、Google/Apple 令牌、家庭数据、录音/照片可能被上传到攻击者服务器。

### 5.2 OAuth 回调劫持

攻击者注册 `homewoo://` scheme，或在受害者设备上向已运行的 HomeWoo 发送伪造的 `homewoo://calendar/google/complete?...`。如果服务端没有把 OAuth attempt 与发起账号、state、一次性使用严格绑定，攻击者可能完成受害者 Google 日历与攻击者账号的绑定，或反过来把攻击者日历塞进受害者账号。

### 5.3 接口 / MQTT 越权

攻击者用普通账号登录，拿着包内恢复的接口清单，批量测试 `family/member/*`、`settings/devices/:id`、`calendar/event/detail` 等对象级接口；同时订阅 `awp.family.*`、`awp.device.*` 主题。如果服务端只校验“已登录”而不校验“是否属于该家庭/设备”，就能跨家庭读取或伪造事件。

### 5.4 云资源与支付滥用

攻击者从包内提取 Google Key、Firebase 项目号、Storage bucket，测试 Key 限制与 Storage 规则；同时分析 `v1/payment/google/callback` 的校验逻辑，测试 purchaseToken 重放、订单号篡改、回调伪造。前者造成账单/数据风险，后者造成收入损失。

---

## 6. 边界与不确定性

### 6.1 APK 单独做不到什么

- **拿不到其他用户的真实数据**：APK 是客户端，不含后端数据库；需要账号、设备或服务端漏洞；
- **伪造官方签名**：没有 SDMC 的签名私钥，无法让改包通过官方升级校验；但可以自签后走侧载/第三方渠道；
- **直接解密生产 TLS**：targetSdk 36 默认不信任用户 CA，且未发现应用层 pinning；没有 root/Frida/改包，抓不到明文；
- **证明服务端一定存在越权/限流缺陷**：静态分析只能证明“接口和协议暴露”，IDOR、MQTT ACL、OAuth 绑定、支付校验都必须动态验证；
- **完整还原 Dart 源码**：本次只能做到字符串级结构还原；Blutter/reFlutter 可以进一步反编译，但需要额外工具和时间。

### 6.2 待动态验证的关键项

| 待验证项 | 验证目标 |
|---|---|
| OAuth attempt 绑定 | attempt 是否绑定发起账号、state 是否一次性、PKCE 是否由服务端实现 |
| 接口对象级鉴权 | 跨家庭 IDOR、设备/日历/任务/清单/导出接口 |
| 配对码/验证码限流 | 6 位配对码、邮箱验证码、邀请码是否有服务端限流 |
| MQTT ACL | 是否能跨家庭订阅/发布、事件是否签名 |
| `XHOME_SECRET_KEY` | 是否可从运行时提取、是否全局复用 |
| 支付回调 | purchaseToken 校验、订单绑定、防重放 |
| Firebase Storage | bucket 是否可列目录/公开读 |
| 环境切换 | release 中是否可达、dev/test/UAT 是否暴露测试数据 |

---

## 7. 修复建议（按投入产出排序）

1. **OAuth 改为 Android App Links（HTTPS）+ PKCE + 一次性 state，并严格绑定发起账号与 attempt**；release 包移除 mock OAuth。
2. **服务端补齐对象级鉴权**：家庭、设备、日历、任务、清单、导出接口全部按“当前用户是否属于该家庭/拥有该设备”校验；配对码、验证码、邀请码做服务端限流。
3. **加 Play Integrity / Firebase App Check + 服务端签名校验**，让改包和脚本不能直接调用生产 API；不要依赖客户端锁定。
4. **移除 release 包里的 dev/test/UAT 地址、环境切换、Mock/Fake 代码**；构建时做环境白名单。
5. **不要内置全局 AES 密钥**：改为每用户/每设备密钥、服务端签名或 Keystore；轮换已暴露的 Google Key，限制包名 + SHA-1 + API 范围，收紧 Firebase Storage 规则。
6. **加密 `cedar_history.db`，关闭或排除敏感数据的备份**；对儿童/家庭/语音数据做最小化采集与合规评估。
7. **MQTT 按家庭/用户做 ACL，消息签名并校验来源**；不要只凭 topic 信任事件。
8. **支付回调做 purchaseToken 服务端校验、订单/用户绑定、防重放**；会员权益以服务端为准。
9. **增加改包监测与签名校验**：服务端校验客户端签名/完整性，监控异常 API/MQTT 调用模式，监测第三方渠道的仿冒包。
10. **Dart 代码混淆与符号裁剪**：至少开启 `--obfuscate --split-debug-info`，降低源码结构和接口语义的暴露程度；但不要把混淆当作安全边界。

---

## 附录 A：恢复出的接口/路由字面量

> 来源：`libapp.so` 字符串池。以下为相对路径，实际请求会拼接 base URL。
> 仅用于授权安全测试与修复，不作为对外攻击清单。

```text
common/mqtt/info
family/member/home-tags/custom/delete
family/member/home-tags/options
awp/app/reminder/setting/detail
family/list
calendar/external-connection/list
family/member/info/color/used/list
permission/pin/save
user/logout
ai/chat/group/query
family/member/home-tags/custom/update
task/definition/update
family/invitation/join/pending/list
calendar/event/delete
v1/payment/google/callback
calendar/google/oauth-attempt/create
family/delete
family/invitation/join/detail
user/login
awp/device/detail
family/info
task/query/all
permission/pin/config
v1/order/checkout
ai/chat/history/list
task/definition/delete
awp/app/notification/setting/save
calendar/event/list
device/delete
family/invitation/join/code/apply
permission/pin/forgot
v1/payment/google/repair/callback
aichat/agentapp/config/query
aichat/getWSToken
calendar/event/detail/by-event-id
device/list
task/instance/undo-status
home/count
task/query/range
device/update
family/update
calendar/external-connection/disconnect
family/create
awp/sub-device/member/bind
device/pairing/code/bind
task/definition/reassign-claimant
profile/create
family/invitation/join/code/generate
task/definition/detail
family/member/profile/save
permission/pin/disable
user/register
family/invitation/join/approve
family/member/list
task/definition/detail/by-task-id
family/member/home-tags/custom/add
family/member/profile/update
task/definition/create
user/data/export/create
awp/app/notification/setting/detail
user/account/delete
awp/app/reminder/setting/save
calendar/event/detail
family/data/export/create
family/member/remove
family/member/leave
task/definition/claim
family/data/export/verification-code/send
calendar/event/check-conflict
calendar/google/oauth-attempt/detail
calendar/event/update
family/invitation/join/code/preview
v5.0/list/ai/query
device/pairing/qrCode/bind
ai/chat/group/add
user/thirdAuth/login
calendar/event/create
```

### 说明

- 另有大量 `/calendar`、`/family`、`/tasks`、`/lists`、`/settings/...` 等 Flutter 路由字面量，属于前端页面路由，不是后端接口；
- 生产接口前缀为 `cloud/v5.0/`，支付接口前缀为 `payment-server/v1/`；
- `v5.0/list/ai/query` 与 `ai/chat/*` 属于 AI/Cedar 模块，具体 base URL 可能不同，需要动态确认。

---

## 附录 B：恢复出的 MQTT 主题字面量（节选）

```text
awp.calendar.event.created
awp.calendar.event.deleted
awp.calendar.event.updated
awp.calendar.reminder.start
awp.calendarEvents
awp.calendarevents
awp.checklists
awp.device.reset
awp.device.unbound
awp.family.address.updated
awp.family.deleted
awp.family.join.applied
awp.family.join.approved
awp.family.member.created
awp.family.member.deleted
awp.family.member.left
awp.family.member.updated
awp.family.owner.transferred
awp.family.updated
awp.lists.
awp.lists.item.created
awp.lists.item.deleted
awp.lists.item.updated
awp.lists.list.created
awp.lists.list.deleted
awp.lists.list.updated
awp.lists.section.created
awp.lists.section.deleted
awp.lists.section.updated
awp.parent.pin.disabled
awp.parent.pin.enabled
awp.planner
awp.planner.choice.multiple
awp.planner@1.
awp.planner@1.choice
awp.pocket.device.created
awp.pocket.device.deleted
awp.pocket.device.updated
awp.pocket.reminder.setting.updated
awp.proposal
awp.proposal@2
awp.task.create
awp.task.delete
awp.task.reminder.due
awp.task.sync.changed
awp.task.update
awp.todoTasks
awp.todotasks
awp/app/notification/setting/detail
awp/app/notification/setting/save
awp/app/reminder/setting/detail
awp/app/reminder/setting/save
awp/device/detail
awp/sub-device/member/bind
```

### 说明

- 主题中可能包含家庭 ID、用户 ID、设备 ID 等动态段；
- 具体 topic 订阅/发布格式由 `XHomeMqttTopics` 类生成；
- broker ACL、消息签名、事件来源校验是决定风险高低的关键。

---

## 附录 C：关键证据速查

| 证据 | 值 |
|---|---|
| APK SHA-256 | `798cbb98d716e7cdb198b23c1c8162889e4dfaa6528babe0e8602102acac6172` |
| Flutter 快照哈希 | `0451907c2eaa8467e848c0067bfe8ed4` |
| 签名证书 SHA-256 | `ba5a88384efa67b266332354677c121ffcf2354a701a09ef292ec09d7450ec41` |
| 签名证书主体 | `C=CN, ST=Guangdong, L=Shenzhen, O=SDMC, OU=SDMC, CN=homewoo` |
| 自有 Java 类 | `com.sdmc.homewoo.MainActivity`、`com.sdmc.homewoo.R` |
| OAuth 深链 | `homewoo://calendar/google/complete` |
| OAuth 回调通道 | `com.sdmc.homewoo/calendar_google_oauth_callback` |
| 本地 AI 数据库 | `cedar_history.db` |
| 本地环境配置 | `homewoo_environment.xml` |
| Firebase 项目 | `homewoo-530e0` |
| Storage bucket | `homewoo-530e0.firebasestorage.app` |
| 内部测试包名 | `com.sdmc.onehome.sdmctest.app` |

---

## 附录 D：REA 证据 ID

| 操作 | Evidence ID |
|---|---|
| `inspect_android_package` | `ev_a612b349f5d88ad632c600841e01b8af0ba152907236895460c805d3ad30daa8` |
| `decode_android_resources` | `ev_10f7d9a4a6a3016fe0056bcdc206359d51c9c956ed5f0dbc11b3dc1b4d17bda4` |
| `search_android_classes`（com.sdmc） | `ev_55eba370eff5ff5642c8b1dcf78ac545d169b9b6598f24a2adc477a55c79bb90` |
| `identify_flutter_build` | `ev_e73aa5f5641f28e33a157f4f7933d5c2d73a4103be087ec79f25edc0b28e8427` |
| `inspect_android_class`（MainActivity） | `ev_35d98c05e47f5c71cbe18b2d66a23512245685f6c658e8bd8850ccc86985735d` |
| `inspect_android_method`（onNewIntent） | `ev_bab73570580a19d0a7fe4bbb35364bcf5923940f05b5384c48dd821a8edbed96` |
| `inspect_android_method`（m） | `ev_7dfa69705de679f5451ade7f5069058cbc244bfce24e814edc4036d78d68a88b` |

---

> 本文为授权安全评估材料，仅用于 Homewoo/SDMC 内部安全改进与演示。
> 所有“待验证”结论必须在获得授权的测试环境中确认，不得直接用于生产环境攻击。
