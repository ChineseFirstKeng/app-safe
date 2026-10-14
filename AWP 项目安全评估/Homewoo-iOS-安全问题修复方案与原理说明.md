# Homewoo iOS 安全问题修复方案与原理说明

**适用对象**：`com.sdmc.wallplanner.ios` iOS 应用及其后端、Google/Firebase 云配置  
**编写日期**：2026-10-13  
**依据**：[Homewoo iOS IPA 安全静态评估报告](Homewoo-iOS-IPA安全静态评估报告.md)中的 8 项风险  
**前提**：为制定可执行方案，以下按“每项风险对应的最不利利用条件确实成立”设计修复；这**不是**对现有 IPA 新增的漏洞验证结论。正式实施前应由 iOS、Flutter、后端和云平台负责人核对实际代码、运行行为与配置。

## 如何理解“修复有效”

iOS 签名和沙盒能保护正常安装、正常运行的 App，但客户端二进制与配置仍交付到用户设备。攻击者可以读取 IPA、在受控设备上观察进程、制作另一个签名的仿冒 App，或绕过被修改客户端内部的判断。因此，**账号、对象权限、环境隔离和长期秘密必须由服务器最终保证**。本文对每项问题都区分三层：

1. **消除根因**：让造成风险的路径不再存在，例如正式版不产生日志中的凭证、不打包测试 OAuth 实现、不再依赖全体客户端共享密钥。
2. **服务端强制**：即使客户端被改写，服务器仍拒绝越权、跨环境、过期、重放或伪造的请求。
3. **验收和防复发**：在最终签名 IPA、生产配置和攻击反例测试中同时留下证据。

“保证不再出现”只能针对**明确的故障模式、受控系统和验收条件**作出。例如“服务器拒绝错误 `state` 的日历授权回调”可以自动验证；“任何未来攻击都不可能成功”不能由一次修复证明。下文每节的“完成判据”就是可核验的保证边界。

| 序号 | 假设成立的问题 | 必须阻断的结果 | 主要责任方 |
|---|---|---|---|
| 1 | 正式版日志实际含敏感报文 | 令牌/个人信息进入设备或诊断日志 | iOS/Flutter、后端、运维 |
| 2 | 自定义 Scheme 回调可被注入或串绑 | 未发起的授权被接受、账号/日历绑错人 | iOS、认证后端 |
| 3 | 正式包可切环境且环境身份混用 | 生产凭证流向非生产环境或被跨环境接受 | iOS/Flutter、网关、认证后端 |
| 4 | 全体客户端共用可提取的 AES 秘密 | 提取一份 IPA 即可伪造所有客户端材料 | iOS/Flutter、协议/后端 |
| 5 | 全局 ATS 例外导致弱传输可用 | 业务数据通过明文或不符合要求的连接发送 | iOS/Flutter、网络/后端 |
| 6 | 发布版调试/测试框架或模拟 OAuth 可触发 | 测试路径改变代理、认证或生产行为 | iOS/Flutter、认证后端 |
| 7 | Google Key 限制或 Firebase 规则不足 | 未授权 API 消耗或云数据访问 | Google Cloud/Firebase 管理员 |
| 8 | 本地秘密可迁移/备份，或缺少有效客户端证明 | 凭证复制、仿冒客户端高风险请求被接受 | iOS、后端、风控 |

## 1. 正式版 API 日志泄露请求、响应和凭证

### 问题原理

假设 Flutter 的 `_logApiRequest`、`_logApiExchange` 在正式版输出认证头、请求体或响应体。一次登录、刷新令牌、日历同步或设备绑定，会把原本只应在业务链路短暂存在的秘密复制到系统日志、应用文件、崩溃平台或客服诊断导出。被复制的数据不再受原业务接口的权限控制。iOS 沙盒限制其他普通 App 直接读取本 App 日志，但拥有设备诊断权限、解锁设备、运维后台或导出文件的人仍可能接触这些副本。Apple 建议对动态敏感值使用日志隐私标记，并尽量只记录可预测的静态信息。[Apple OSLogPrivacy](https://developer.apple.com/documentation/os/oslogprivacy)、[Apple 日志生成指南](https://developer.apple.com/documentation/os/generating-log-messages-from-your-code)

### 解决方案

1. **在产生日志前切断数据**：正式构建的网络拦截器不读取、拼接或输出 `Authorization`、Cookie、签名、密码、验证码以及完整请求/响应体；只记录接口模板、状态码、耗时、错误类别和随机请求 ID。异常对象的 `description`、第三方 HTTP 客户端调试输出也要纳入检查。
2. **用固定字段生成诊断事件**：为每种事件定义允许字段清单，新字段默认不能进入日志。Flutter 的 `print`/`debugPrint`、原生 `NSLog`、`os_log`/`Logger`、Crashlytics 等上报分别核查；原生日志必要的动态值使用 `.private` 或 `.sensitive`，但不把隐私标记当作允许记录完整凭证的理由。
3. **隔离开发诊断能力**：开发/测试构建可使用独立日志开关和测试账号；正式包没有远程打开完整报文日志的隐藏开关。后端、网关、APM 和客服导出执行同一字段清单。
4. **处置历史泄露**：若已有真实令牌进入日志，限制或删除历史副本，按影响范围撤销令牌并检查异常使用。令牌短时、可撤销，高风险写操作设置幂等键或一次性挑战。

### 为什么有效

在日志入口就不生成敏感副本，能直接消除这条泄露路径；字段白名单使未来接口新增字段不会自动进入诊断系统。原生日志隐私标记降低动态值在日志中显示的机会，但 Flutter/第三方自建日志未必使用 Apple 的隐私机制，因此必须逐链路检查。令牌撤销限制已泄露凭证的使用时间，**不能替代停止记录凭证**。

### 完成判据与边界

- 用专用测试账号走登录、刷新令牌、日历读写、设备绑定、支付及异常流程；设备日志、应用日志、崩溃/诊断平台和服务端日志中均检索不到测试令牌、认证头、密码、签名、完整个人数据或完整报文。
- 发布流程检查网络日志实现与事件字段；新增 SDK、接口或导出功能时复查。
- 该判据覆盖受测试的日志路径；用户主动截图、复制、分享以及未来新增的第三方 SDK 上报仍需另外管理。

## 2. 自定义 URL Scheme 与日历 OAuth 回调可被注入或串绑

### 问题原理

`Info.plist` 注册的 `homewoo:` 和 Google 登录回调 Scheme 可被外部触发。Apple 说明其他 App 也可注册同一自定义 Scheme，普通 URL 分发时目标 App 不一定唯一。若 `SceneDelegate` 接到 URI 后直接交给 Flutter/服务端，而没有核对这是否属于当前用户**亲自发起且尚未完成**的日历授权，攻击者可能提交自己的授权结果，让受害者账号绑定到错误的日历。仅截获授权码能否兑换还取决于 PKCE 和所用浏览器会话：Apple 的 `ASWebAuthenticationSession` 对其自身会话的回调有保护，不能一概推断同 Scheme App 一定可截获。[Apple 自定义 URL Scheme](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app)、[ASWebAuthenticationSession](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)

### 解决方案

1. **把每个 URI 当作不可信输入**：分别为 `homewoo:` 日历回调、Google SDK Scheme 定义预期 Scheme、Host、Path、参数名、长度和编码规则。`SceneDelegate`/原生桥接先解析并拒绝未知或畸形 URI，Flutter 层再次核对预期回调类型。不要把 URI 中的账号 ID、跳转 URL 或授权结果直接当成最终事实。
2. **将 OAuth 变成一次性事务**：发起授权时生成高熵 `state` 和 PKCE `code_verifier`；服务器保存当前用户、环境、授权提供方、待绑定对象、预期回调地址与时效。回调时服务器原子地核对并消费 `state`，使用 `code_verifier` 兑换授权码，验证返回的提供方账号归属及本次绑定对象；过期、重复、跨账号和跨环境回调都拒绝。RFC 8252 要求原生 OAuth 公共客户端使用 PKCE，并建议用 `state` 关联请求与回调。[RFC 8252](https://www.rfc-editor.org/info/rfc8252/)
3. **核对回调分发方式**：Google 登录 SDK 的既有 Scheme 不应在未完成兼容设计前直接删除。日历 OAuth 可优先评估 `ASWebAuthenticationSession` 的回调会话保护和受域名控制的 Universal Links；若迁移到 Universal Links，需要 App 的 Associated Domains Entitlement、域名上的关联文件及 OAuth 提供方允许的重定向 URI 同步配置。即使用 Universal Links，仍要保留 `state`、PKCE 与服务端对象授权。[Apple Universal Links](https://developer.apple.com/documentation/Xcode/allowing-apps-and-websites-to-link-to-your-content)
4. **封闭最终业务操作**：日历绑定、取消绑定、读取和同步接口都按当前登录用户与日历对象独立授权；客户端导航成功不代表绑定成功。

### 为什么有效

URI 白名单阻止任意参数进入授权流程；`state` 将回调与**某次真实发起的请求**绑定；PKCE 使只持有被截获授权码的人无法完成兑换；服务器原子消费阻止同一结果再次绑定。`ASWebAuthenticationSession` 或 Universal Links 可以降低部分回调被其他 App 抢占的风险，但真正防止账号串绑的是服务器验证用户、授权尝试和对象关系。

### 完成判据与边界

- 在测试设备发送未知路径、畸形参数、错误 `state`、错误 PKCE、过期授权、重复回调，以及另一测试账号发起的回调；客户端和服务器均拒绝，账号/日历绑定关系不变化。
- 安装同 Scheme 竞争 App，核对所用授权会话与回调分发的实际行为；Google 登录和日历授权分别测试。
- 迁移回调方式要考虑已发出的授权请求、旧版客户端和 OAuth 提供方配置；更换 Scheme 本身不能关闭服务端校验缺陷。

## 3. 非生产环境和环境切换进入正式包

### 问题原理

假设正式版可触发 `homewoo_xhome_environment` 或隐藏的 `Switch environment`，把 API 目标改成开发、测试或预发域名。请求拦截器可能仍附加生产令牌，导致真实身份材料送入防护较弱的环境；若环境共用令牌签名密钥、发行者或受众，测试服务甚至可能接受生产令牌。删除 IPA 中的地址能减少误操作，却不能阻止攻击者修改客户端，因此环境隔离不能依赖本地开关。

### 解决方案

1. **分别构建正式与测试产物**：Xcode/Flutter 的 Release 生产配置只包含生产 API、生产 OAuth 客户端和正式证书策略；开发/测试使用独立 Build Configuration、Bundle ID、配置文件和分发渠道。正式 IPA 中移除环境菜单、持久化环境键、测试域名和开发证书。`--dart-define` 注入的内容会进入可分发产物，不可作为秘密保护机制。
2. **发布前检查最终 IPA**：扫描 `Runner.app/Info.plist`、Flutter AOT、资源和内嵌配置中的 `xhome-dev/test/uat`、环境切换符号及测试回调地址；只看 Xcode 项目配置或源码分支不足以保证实际归档正确。
3. **后端硬隔离**：各环境分别使用用户库或严格分区、令牌发行者 `iss`、受众 `aud`、签名密钥、API Key、OAuth 客户端和回调地址。网关验证签名后继续检查 `iss`、`aud`、有效期和环境归属；生产网关拒绝测试令牌，测试网关拒绝生产令牌。非生产系统不得接收真实用户敏感数据。
4. **处理历史混用**：如已发生生产令牌流向测试环境或密钥复用，检查日志、撤销相关令牌、轮换共享密钥并清理测试数据。

### 为什么有效

拆分产物使正常用户和运维不能在正式版误切环境；CI 检查最终 IPA 防止构建时又把地址带回。独立的服务器密钥、发行者和受众，使攻击者即便修改 IPA 中的目标域名，也无法让另一环境认可原令牌。**只有客户端删字符串而服务器仍共用身份体系，根因并未消除。**

### 完成判据与边界

- 最终签名 IPA 中无开发/测试/预发地址、环境切换入口和持久化键；实际正式流程只访问经批准的生产业务域名及必需第三方域名。
- 生产和测试令牌交叉请求均被拒；OAuth 回调、用户 ID 和设备注册不能跨环境串用。
- 新增环境、灰度域名或紧急切流必须进入同一发布与网关审查流程。

## 4. 全体安装包共享对称密钥

### 问题原理

假设 `XHOME_SECRET_KEY` 的同一 AES 值随所有 IPA 发布，且服务器把“能使用此密钥加密或签名”当作可信客户端证明。只要一份 IPA 或运行时内存泄露密钥，攻击者就可制作与合法客户端相同形式的材料。把值藏在 `--dart-define`、拆分字符串或混淆二进制，只能增加提取成本，**不能把客户端共享值变成服务端秘密**。如果密钥仅用于本地数据加密，全体设备共用同一值仍会扩大单点泄露范围。[OWASP MASWE-0003](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0003/)

### 解决方案

1. **先列清用途与旧协议窗口**：确认密钥用于传输保密、本地存储、请求签名还是业务数据解密；查清服务器接受范围和旧版客户端兼容期。按潜在泄露制定轮换、停用旧密钥、用户升级和异常请求排查方案。
2. **传输用 TLS，授权靠会话**：业务数据传输使用经验证的 HTTPS；服务器按用户、会话、设备注册状态和对象权限授权，不认可“知道全局 AES 值”作为身份。长期服务端密钥留在服务端密钥管理系统。
3. **本地加密用设备/用户级密钥**：小型秘密或本地加密密钥存入 Keychain，并根据前后台使用选择 `kSecAttrAccessible` 类别；不需跨设备迁移的凭证使用合适的 `ThisDeviceOnly` 类别。若采用 Secure Enclave 做设备级非对称签名，需按设备注册公钥、绑定用户、支持撤销/轮换；Secure Enclave 私钥不能被直接导出，但受控设备仍可能调用签名能力。Apple 说明 Keychain 是管理小型秘密的适当位置，`ThisDeviceOnly` 项不会迁移到新设备。[Apple Keychain](https://developer.apple.com/documentation/security/using-the-keychain-to-manage-user-secrets)、[Keychain 可访问级别](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
4. **确需证明官方 App 实例时用专门机制**：高风险操作可结合 App Attest 的设备实例密钥、服务器挑战与断言，见第 8 节；它也不能替代用户和对象授权。

### 为什么有效

协议不再接受全体客户端共用的秘密后，提取任意一份 IPA 不会得到可通用的服务端认证材料。设备/用户级 Keychain 密钥缩小泄露半径；服务器的一次性挑战和撤销能力使旧材料无法无限复用。**服务器若继续接受旧共享密钥，仅发布新版本并未真正关闭问题。**

### 完成判据与边界

- 最终 IPA、构建配置和资源中没有服务器认可的全局共享 AES/HMAC 密钥；服务器在约定截止日后拒绝旧协议和旧密钥。
- 不同设备不能互用设备级材料；错误签名、重复挑战、改写请求和已撤销设备的操作均被拒。
- Keychain/Secure Enclave 保护密钥提取，不能单独证明屏幕前的人是合法用户；越狱或被控制的设备仍可能代用户发起操作，服务端授权必须保持。

## 5. 全局放宽 App Transport Security

### 问题原理

当前 `Info.plist` 的 `NSAllowsArbitraryLoads=true` 已确认。假设实际业务或 WebView 因此使用了 HTTP，或接受低于默认 ATS 要求的 TLS，网络路径上的攻击者可能读取或篡改数据。Apple 说明该键对未单独配置的域关闭 ATS 约束，并允许不安全 HTTP；但**HTTPS 仍需正常服务器证书信任校验**，关闭 ATS 不等于所有 HTTPS 可被任意解密。ATS 对具体请求的影响还取决于所用网络 API，因此不能只凭修改 Plist 推断 Flutter/Dart、WKWebView 和第三方 SDK 的所有流量都已安全。[Apple NSAllowsArbitraryLoads](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads)

### 解决方案

1. **从正式 `Info.plist` 删除全局例外**：让系统默认 ATS 规则恢复；先升级不满足要求的自控服务。若个别不可升级的外部资源确需例外，限定到确切域名或用途，写明负责人、原因和到期时间，不保留 `NSAllowsArbitraryLoads` 全局开关。Apple 建议把例外范围降到最小。[Apple 安全网络连接指南](https://developer.apple.com/documentation/security/preventing-insecure-network-connections)
2. **在业务网络层限制目的地**：所有认证、日历、设备、支付和上传接口仅允许 HTTPS 及经批准域名；重定向后再次检查 Scheme 与 Host；WKWebView 的导航和外部链接分别限制。检查第三方 SDK、Flutter `dart:io`、原生 `URLSession`/`WKWebView` 的实际流量，不能把 ATS 当成覆盖所有网络实现的唯一保护。
3. **保持正确的证书校验**：删除接受任意证书、跳过主机名验证和生产版信任测试 CA 的逻辑；若某个高价值自控域名使用 Pinning，要配备用公钥、证书轮换和故障恢复方案，不为实现 Pinning 关闭系统信任校验。

### 为什么有效

去掉全局例外使受 ATS 管控的 API 回到系统默认的安全连接要求；业务层 HTTPS/域名约束可覆盖不受 ATS 统一约束的代码路径，并防止错误重定向把凭证送往 HTTP 或非预期域名。证书校验阻止网络中间人冒充服务端。三道控制的保护范围不同，组合后才能对**实际业务流程**给出可靠结论。

### 完成判据与边界

- 最终签名 IPA 的 `Info.plist` 不再包含全局 `NSAllowsArbitraryLoads=true`；所有必要例外均有明确域名/用途和到期时间。
- 测试账号完成登录、日历、地图、支付、帮助页面与媒体流程；流量中无凭证或个人数据经 HTTP 发出，无不受控跳转；错误主机名、过期证书和不受信任证书均导致生产业务连接失败。
- 平台配置只能约束其覆盖的网络 API；新的 Flutter 插件、原生 SDK 或自定义 Socket 必须进入同一流量测试。

## 6. 调试、集成测试及模拟 OAuth 代码进入发布包

### 问题原理

评估报告确认正式 IPA 链接了 `flutter_debug_kit.framework`、`integration_test.framework`，并带有 `mock-oauth-attempt-`、`mock-google-oauth-` 和 `mockAttempt=` 字符串。假设这些入口在生产运行时可达，攻击者可能激活代理调试、测试 Provider 或模拟授权逻辑；即使入口不可达，测试组件进入正式包也增加了代码与配置审查面。**仅有框架或字符串不能证明存在可直接调用的后门**，本方案按“可触发”情形处置。

### 解决方案

1. **隔离依赖和编译目标**：调试工具、集成测试插件、模拟 OAuth Provider 只进入开发/测试构建；Release 的 iOS Pod/插件注册、Flutter 依赖和 Dart 编译入口均不引用它们。只把按钮隐藏起来不够，Release 二进制仍可能包含可调用路径。
2. **在服务器端拒绝模拟身份**：模拟授权只连接隔离测试服务；生产 OAuth 交换必须由真实提供方结果、当前用户的 `state`、PKCE 和一次性事务证明。任何 `mockAttempt`、测试用户标识或测试签名都不能替代正式提供方验证。
3. **检查最终 IPA 而非仅看源码**：CI 对 `Runner` 的动态依赖、`Frameworks` 目录、插件注册符号、Flutter AOT 字符串和资源做发布阻断检查；包括 `flutter_debug_kit`、`integration_test`、`mock-oauth`、`mockAttempt` 和测试域名。正式发布确需诊断能力时，用单独受认证、最小字段的正式实现，不复用测试插件。
4. **核查历史使用**：如果模拟路径曾被生产服务器接受，审计相关账号绑定和令牌，撤销异常状态并修复服务端规则。

### 为什么有效

从 Release 构建中移除测试代码，消除普通用户或攻击者触发这条路径的前提；CI 检查最终 IPA 防止构建配置回退。服务端拒绝模拟授权材料，即使某个旧版或改包客户端继续提交测试结果，也无法获得正式账号权限。

### 完成判据与边界

- 最终签名 IPA 不含上述测试框架、插件通道、模拟 OAuth 路径和测试 URL；正式业务流程功能正常。
- 使用旧版、改包或手工请求提交模拟授权材料，生产服务器均拒绝，账号/日历绑定不变化。
- 如果业务上必须保留某个诊断能力，应以独立安全设计和验收记录明确例外，不能把测试插件当作正式功能直接发布。

## 7. Google/Firebase Key 可被滥用

### 问题原理

`Info.plist` 的 Maps Key 和 `GoogleService-Info.plist` 的 Firebase Key 必须让相应客户端 SDK 读取，因此攻击者可从 IPA 提取。**Key 可提取不是可修复的秘密泄露本身**；假设风险成立，真正的问题是它能调用不应开放的 Google API、消耗额度，或 Firebase Security Rules 允许未授权用户读写资源。Firebase 官方说明这类 Key 主要用于识别项目，授权仍依赖 Security Rules、IAM 和 App Check。[Firebase API Key 说明](https://firebase.google.com/docs/projects/api-keys)

### 解决方案

1. **拆分用途**：Maps SDK for iOS 使用独立的客户端 Key；Firebase 使用只允许所需 Firebase API 的 Key；服务器端 Web Service/API Key 或服务账号凭据留在服务器，不放进 IPA。不要让一个公开客户端 Key 同时调用高成本或管理类 API。
2. **配置云端限制**：Maps iOS Key 设为 iOS 应用限制，绑定实际 Bundle ID `com.sdmc.wallplanner.ios`，再限定所需 Maps/Places 等 API；不同 Bundle ID 的开发版使用独立 Key。对通过 REST 调用的 Google API，确认其是否真正执行 iOS 应用限制；不能可靠限制时改为受认证的服务端代理。Google 明确建议应用限制与 API 限制并用。[Google Maps Platform Key 安全指南](https://developers.google.com/maps/api-security-best-practices)
3. **收紧 Firebase 数据权限**：Firestore/Realtime Database/Storage 逐资源写默认拒绝、按登录身份及对象归属授权的 Security Rules；支持的服务启用 App Check 并在观察正常流量后强制执行。App Check 提供应用来源信号，不能代替用户和对象授权。[Firebase Security Rules](https://firebase.google.com/docs/rules/)
4. **控制损失与历史暴露**：设置配额、预算告警、异常来源监控；审计过去调用。确认新限制不会影响正式用户后再轮换不再需要的 Key，旧 Key 应撤销。

### 为什么有效

应用限制将 Maps SDK 的可接受调用收窄到指定 Bundle ID，API 限制使同一字符串不能用于其他已启用服务；服务器代理把高权限 Key 留在服务器。Firebase Security Rules 在服务端执行，即使有人从 IPA 复制配置，也必须满足身份与对象授权条件。

### 完成判据与边界

- 每个 Key 在云平台均有匹配用途的应用/API 限制；错误 Bundle ID、非允许 API、旧 Key 的测试调用被拒，正式版 Maps/Firebase 功能正常。
- Firebase 权限测试覆盖未登录、其他用户、越权写入和管理员路径，均按规则拒绝；配额和预算告警可触发。
- Bundle ID 限制的实际强度取决于具体 Google API；对无法可靠执行 iOS 应用限制的 REST API，必须走服务端代理和独立授权。

## 8. 网络身份绑定及本地敏感数据保护不足

### 问题原理

这一项按两类实际缺陷都成立设计：其一，访问令牌、设备凭据或家庭/日历缓存被写到保护不足的 SQLite、文件或可迁移备份，换机或设备被控制后可能被复制；其二，仿冒/重签的 App 能让服务器误以为请求来自正式客户端。Keychain、文件数据保护和 App Attest 分别处理**秘密存放、设备静止数据、客户端实例来源**，不能互相替代。没有配置 `NSPinnedDomains` 本身不等于 TLS 失效；Pinning 是经风险评估后可选择的附加连接控制。

### 解决方案

1. **清点实际持久化数据**：审计 `flutter_secure_storage_darwin`、`sqflite_darwin`、SharedPreferences、缓存、WebView 存储、SQLite 主文件及 WAL/SHM 文件，列出令牌、密钥、家庭/日历数据的保存位置、保存期限、退出登录清除行为和备份路径。不能由“引入了 Keychain 插件”推断所有秘密都已安全存储。
2. **为秘密选择 Keychain 属性**：访问令牌、刷新令牌和小型密钥放 Keychain；前台专用凭证可选 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` 等合适类别，确需后台刷新/推送处理的凭证评估 `AfterFirstUnlockThisDeviceOnly` 等类别及更小权限。`ThisDeviceOnly` 类别不迁移到新设备，换机应重新登录/注册；退出登录时删除本地项目并在服务器撤销会话。Apple 文档明确说明不同可访问类别对设备解锁和迁移行为的影响。[Apple Keychain 可访问级别](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
3. **保护文件与备份**：敏感 SQLite/文件按前后台需求设置 iOS Data Protection 类别；不需要备份的缓存和支持文件使用 `isExcludedFromBackupKey`，并在每次覆盖保存后核对属性，因为某些文件操作会重置排除标记。对可从服务器重建的个人数据只保留必要时长；换机恢复时令牌不能自动成为有效会话。[Apple 文件数据保护](https://developer.apple.com/documentation/uikit/encrypting-your-app-s-files)、[备份排除属性](https://developer.apple.com/documentation/foundation/urlresourcekey/isexcludedfrombackupkey)
4. **高风险接口核验 App 实例**：按支持情况评估 Apple App Attest。客户端生成实例密钥，服务器用一次性挑战验证 Attestation，并在设备/用户注册记录中保存公钥及状态；敏感请求附带覆盖操作内容和新挑战的 Assertion，服务器验签、校验计数器、挑战及对象权限。对不支持或暂时不可用的设备制定明确的降级/风控策略。Apple 强调自我校验的客户端结果可被篡改，App Attest 的关键校验应在服务器完成。[Apple App Attest 实施](https://developer.apple.com/documentation/DeviceCheck/establishing-your-app-s-integrity)、[服务端验证](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
5. **按风险评估证书绑定**：若高价值自控域名需要 Pinning，按实际 `URLSession`、Flutter 和第三方网络栈分别实现/验证，配置当前与备用公钥及轮换演练；保留系统正常证书校验。它提高特定中间人攻击门槛，不解决本地数据复制或改包问题。[Apple ATS 与证书绑定](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity)

### 为什么有效

Keychain 和合适的 Data Protection 类别收窄设备端秘密的可读取时机；`ThisDeviceOnly` 与备份排除减少换机复制路径。App Attest 的服务端挑战和断言把高风险请求绑定到经 Apple 证明的 App 实例与具体操作，降低重签或仿冒客户端直接冒充正式实例的机会。服务器仍按用户、会话和对象授权，确保完整性信号被绕过时也不能自动越权。

### 完成判据与边界

- 真机检查 Keychain 项的可访问级别、应用容器文件保护类和备份样本；跨设备恢复后无可用旧会话，退出登录和服务器撤销后旧令牌失效。
- 高风险接口对错误 App ID/Team ID、无效 Attestation、错误挑战、重放/改写 Assertion 及已撤销实例拒绝；合法正式版正常使用，不支持 App Attest 的设备按记录的降级策略处理。
- App Attest 证明 App 实例来源，**不证明操作人身份或业务授权**；受控设备仍可能通过真实 App 发起恶意操作。Pinning 也不阻止攻击者修改自己的客户端，必须保留服务端权限和风控。

## 实施顺序与发布门槛

| 阶段 | 先做什么 | 原因 | 放行条件 |
|---|---|---|---|
| 紧急控制 | 停止敏感日志；核查/撤销已暴露令牌；收紧 Google Key；去掉 ATS 全局例外并找出受影响连接 | 先切断持续泄露、额度消耗和明显的传输配置风险 | 新日志无秘密，Key 用途受限，业务连接符合 HTTPS/证书要求 |
| 身份边界 | 修复 OAuth 事务与对象授权；隔离环境令牌；淘汰共享密钥；让生产服务器拒绝模拟 OAuth | 这些问题一旦成立会直接影响账号和业务数据 | 伪造/重放/跨账号/跨环境及模拟授权请求均被服务端拒绝 |
| 产物与设备 | Release 移除调试/测试框架；完善 Keychain、文件保护、备份和 App Attest 策略 | 降低本地复制、改包及测试路径误入生产的风险 | 最终 IPA、备份恢复和改包反例测试通过 |
| 每次发布 | 检查签名 IPA、Entitlements、`Info.plist`、框架、AOT 字符串、云端 Key 和服务器拒绝规则 | 防止修复只存在于源码分支或文档中 | 自动检查与人工复核均有结果、负责人和例外到期时间 |

**最重要的验收原则**：只看“代码已提交”不足以关闭问题。每项都要在**最终签名 IPA**、相应服务器/云平台配置以及攻击反例测试中同时得到证据。若旧版客户端或旧协议仍可使用，须记录停用日期和灰度策略；服务器在停用日期后继续接受旧的不安全行为，就不能认定该问题已消除。
