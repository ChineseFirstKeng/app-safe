# 动态攻击分析（dynamic-analysis）

本目录与 `static-analysis/` 并列，用于存放运行时动态分析与取证脚本。

| 目录 | 视角 | 回答的问题 |
| --- | --- | --- |
| `static-analysis/` | 离线静态 | 包里"有没有"某个配置、密钥、组件、防护特征 |
| `dynamic-analysis/` | 运行时动态 | 运行中"能不能触发"、"实际返回什么"、"攻击是否真正生效" |
| `01-` ~ `04-` | 攻击链复现 | 某一条攻击链的完整步骤、证据与恢复路径 |

静态分析给出"入口存在"，动态分析验证"入口可达"和真实业务影响。两类结论分开记录，不相互代替。

## 适用范围

仅用于已授权的测试 APK / IPA、测试设备、测试账号与测试环境。默认不连接生产接口、不读取真实用户数据、不持久化凭证。所有测试行为应在证据中明确标注为 lab/test。

## 目录约定

- Shell 脚本按 `NN-<name>.sh` 编号；需要结构化输出的工具使用 `NN-<name>.py`。
- 每个脚本可独立执行，支持 `--help`，不依赖其他脚本的执行顺序。
- 输出同时包含人类可读结论与机器可读 `KEY=VALUE`（或 JSON）。
- 证据写入 `evidence/`，命名 `<脚本名>-<时间戳>.log|json`；默认脱敏，不落盘完整 Token / Cookie / 密码 / 私钥。
- 退出码统一：`0` 完成且判定通过 / 入口可达（具体语义在各脚本头部声明）；`1` 发现风险、验证失败或环境检查未通过；`2` 参数、依赖或输入错误。
- 默认只读。任何修改设备或应用状态的脚本，必须提供显式的子命令或参数，并说明恢复路径。

## 脚本清单

### P0：最小可用集

| 编号 | 脚本 | 作用 | 状态 |
| --- | --- | --- | --- |
| 01 | `01-preflight-env.sh` | 检查 adb / 设备 / Root / frida / mitmproxy / 时间同步 / 包哈希 | 已实现 |
| 02 | `02-device-posture.sh` | 设备与安装包运行时基线：Root、模拟器、debuggable、allowBackup、签名、哈希 | 已实现 |
| 03 | `03-install-launch.sh` | 干净安装、启动、前台 Activity、崩溃 / ANR 检查 | 已实现 |
| 04 | `04-logcat-audit.py` | 运行日志采集与敏感信息命中 | 已实现 |
| 05 | `05-traffic-capture.sh` | 代理抓包，区分"抓不到"与"没请求"，检查证书绑定 / 明文传输 | 已实现 |
| 06 | `06-storage-audit.py` | 应用私有目录、SharedPreferences、数据库敏感数据检查 | 已实现 |
| 07 | `07-component-runtime.py` | 导出组件、深链、Provider 的运行时可达性验证 | 已实现 |
| 13 | `13-evidence-manifest.py` | 汇总证据，生成可校验的 manifest.json | 已实现 |
| 14 | `14-restore-cleanup.sh` | 恢复原包、清理代理 / 反向隧道 / 测试数据并复核 | 已实现 |

### P1 / P2：增强集

| 编号 | 脚本 | 作用 | 优先级 | 状态 |
| --- | --- | --- | --- | --- |
| 08 | `08-integrity-runtime.py` | 原包 vs 改包的完整性检测与对抗行为对比 | P1 | 已实现 |
| 09 | `09-frida-hook.py` | Frida 运行时 Hook 模板（SSL / HTTP / 日志 / 加密） | P1 | 已实现 |
| 10 | `10-replay-runtime.py` | 请求重放与业务前后对比（优先复用 01 攻击链脚本） | P1 | 已实现 |
| 11 | `11-memory-secret-audit.py` | 进程内存敏感字符串扫描 | P2 | 已实现 |
| 12 | `12-ios-runtime.sh` | simctl 安装 / 启动 / openurl / 日志 / 容器检查 | P1 | 已实现 |

> 14 个脚本均已实现。05 需要 mitmproxy，09/11 需要 frida + frida-server，12 需要 macOS Xcode 工具链；缺少依赖时脚本会明确提示并以 exit 2 退出。
>
> 规划会随攻击链与演示需求调整；新增脚本必须先写清前置条件、成功判据、脱敏规则和恢复路径。

## 静态 → 动态对应关系

| 静态结论 | 动态要补的那一步 | 对应脚本 |
| --- | --- | --- |
| 04/06：包里有签名、有 exported 组件 | 设备上装的是不是这个包？组件真的能被外部调起吗？ | 02 / 07 |
| 07/08：代码里有 Log 调用和敏感字符串 | 运行时日志真的输出了 Token / 请求体吗？ | 04 |
| 10：允许明文流量、信任用户 CA | 实际请求是否明文？装代理后能不能解密？是否证书绑定？ | 05 |
| 10/18：有备份规则、有高熵密钥 | 运行时是否落盘？内存里是否有明文？ | 06 / 11 |
| 15/19：有 Root / Frida / 完整性检测特征 | 检测逻辑真的触发了吗，还是只是死代码？ | 08 |
| 12/16：iOS 只有静态结论 | `simctl openurl` 等运行时入口是否可达？ | 12 |

## 快速使用

以下命令均在本目录执行，APK 路径按实际样本调整：

```bash
# 1. 环境预检
./01-preflight-env.sh \
  --package com.sdmc.homewoo \
  --apk ../app-arm64-v8a-release.apk \
  --require-root

# 2. 设备与安装包基线
./02-device-posture.sh \
  --package com.sdmc.homewoo \
  --apk ../app-arm64-v8a-release.apk

# 3. 安装并启动，记录前台 Activity / PID / 崩溃
./03-install-launch.sh install \
  --apk ../app-arm64-v8a-release.apk \
  --package com.sdmc.homewoo --clean-install
./03-install-launch.sh launch --package com.sdmc.homewoo

# 4. 采集 10 秒日志并审计敏感信息（不保存原始日志）
./04-logcat-audit.py capture --package com.sdmc.homewoo --seconds 10 --clear

# 5. 验证深链入口（只证明入口可达，不证明漏洞）
./07-component-runtime.py deeplink \
  --uri 'homewoo://calendar/google/complete?code=lab-invalid-code&state=lab-invalid-state'

# 6. 受控重放（必须声明授权测试主机）
./10-replay-runtime.py replay \
  --request-file evidence/request.json \
  --allow-host xhome-dev.sdmc.tv

# 7. 抓包与 TLS 行为（需要 mitmproxy）
./05-traffic-capture.sh capture --package com.sdmc.homewoo --seconds 30

# 8. 私有存储与落盘敏感数据
./06-storage-audit.py audit --package com.sdmc.homewoo --max-files 100

# 9. 原包 vs 改包完整性行为（先看计划）
./08-integrity-runtime.py compare \
  --package com.sdmc.homewoo \
  --original ../app-arm64-v8a-release.apk \
  --test ../03-客户端首页内容篡改攻击/artifacts/homewoo-custom-home-repackaged-v8.apk \
  --dry-run

# 10. Frida 预检（需要 frida + frida-server）
./09-frida-hook.py preflight --package com.sdmc.homewoo

# 11. iOS 模拟器运行时
./12-ios-runtime.sh preflight
./12-ios-runtime.sh sim-openurl --url 'homewoo://calendar/google/complete?code=lab-invalid'

# 12. 内存 dump 扫描
./11-memory-secret-audit.py scan --file /path/to/memory.dump

# 13. 采集证据并生成 manifest
./13-evidence-manifest.py \
  --input evidence \
  --output evidence/manifest.json \
  --device

# 14. 复核证据未被改动
./13-evidence-manifest.py --verify evidence/manifest.json

# 15. 恢复原包并清理代理
./14-restore-cleanup.sh restore \
  --package com.sdmc.homewoo \
  --apk ../app-arm64-v8a-release.apk \
  --clear-proxy --clear-reverse
```

## 与攻击链目录的关系

`01-` ~ `04-` 目录保存各自攻击链的完整复现流程；`dynamic-analysis/` 提供可复用的运行时检查与证据采集能力。攻击链脚本可以调用本目录脚本，但本目录脚本不反向依赖某一条攻击链，以保证可单独运行。
