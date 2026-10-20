#!/usr/bin/env bash
#
# 14-sdk-inventory.sh —— 通用静态分析：第三方 SDK / 组件清单
#
# 用途：
#   1. 从 APK 的 DEX 与 resources.arsc 字符串中识别常见第三方 SDK/库
#      （推送、统计、支付、地图、广告、崩溃、网络、跨端框架等）。
#   2. 输出命中的 SDK、命中次数与首条证据，便于后续核对版本和合规清单。
#   3. 不覆盖：SDK 精确版本（需要解析依赖/资源版本号）、CVE 比对、
#      实际运行行为、隐私合规结论。
#
# 参数：
#   <APK>          必填
#                  格式：存在且可读的 APK 文件路径；ZIP 根目录必须包含 AndroidManifest.xml
#                  示例：./app.apk
#                  说明：AAB/APKS/IPA/JAR/普通 ZIP 会被识别并提示不适用，exit 2
#
#   --max N        可选
#                  格式：非负整数（^[0-9]+$）
#                  默认：60
#                  示例：--max 100
#                  说明：最多列出 N 个命中的 SDK
#
# 依赖：
#   unzip、strings、grep、awk、sort、tr
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./14-sdk-inventory.sh <APK>
#   ./14-sdk-inventory.sh <APK> --max 100
#   ./14-sdk-inventory.sh --help
#
# 输出：
#   输入类型、扫描规模、SDK 命中表（名称/次数/证据）、【结论】。
#   临时文件放在 mktemp 目录，脚本退出时删除。
#
# 退出码：
#   0 = 扫描完成且至少识别到一个 SDK/库
#   1 = 扫描完成但未识别到已知 SDK/库
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

MAX=60
TARGET=""

usage() {
  cat <<'EOF'
用法: ./14-sdk-inventory.sh <APK> [--max N]

参数:
  <APK>     必填。格式: APK 文件路径（ZIP 根目录含 AndroidManifest.xml）。
  --max N   可选。格式: 非负整数。默认: 60。示例: --max 100
  -h, --help 显示本帮助。

退出码:
  0 = 扫描完成且识别到 SDK/库
  1 = 未识别到已知 SDK/库
  2 = 参数、依赖或输入错误
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max)
      if [[ -z "${2:-}" || ! "${2:-}" =~ ^[0-9]+$ ]]; then
        echo "[FAIL] --max 的值 \"${2:-}\" 不合法：要求非负整数。" >&2
        usage >&2
        exit 2
      fi
      MAX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "[FAIL] 未知参数: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$TARGET" ]]; then
        echo "[FAIL] 只能指定一个输入文件。" >&2
        usage >&2
        exit 2
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[FAIL] 缺少必填参数 <APK>。" >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$TARGET" || ! -r "$TARGET" ]]; then
  echo "[FAIL] 文件不存在或不可读: $TARGET" >&2
  exit 2
fi

need_tool() {
  local tool="$1"
  local hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[FAIL] 缺少工具: $tool" >&2
    echo "       安装提示: $hint" >&2
    exit 2
  fi
}

need_tool unzip   "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"
need_tool strings "macOS: xcode-select --install；Linux: sudo apt install binutils"
need_tool grep    "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk     "macOS 通常自带；Linux: sudo apt install gawk / mawk"
need_tool sort    "macOS 通常自带；Linux: sudo apt install coreutils"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sdk-inventory.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[loading] 正在读取 ZIP 条目..."
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
ENTRY_COUNT="$(printf '%s\n' "$ENTRIES" | grep -c . || true)"
echo "[done] 条目读取完成：$ENTRY_COUNT 个"

if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  echo "[FAIL] 输入不是有效的 ZIP/APK，或文件已损坏。" >&2
  exit 2
fi
if ! grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  if grep -qx 'BundleConfig.pb' <<<"$ENTRIES" || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
    echo "[FAIL] 输入是 AAB，不是 APK。" >&2
    echo "       请先用 bundletool 生成 APK，再运行本脚本。" >&2
  elif grep -qx 'toc.pb' <<<"$ENTRIES"; then
    echo "[FAIL] 输入是 APKS。" >&2
    echo "       请先解出 base.apk / split APK，再对 APK 运行本脚本。" >&2
  else
    echo "[FAIL] 输入不是 APK（ZIP 根目录缺少 AndroidManifest.xml）。" >&2
  fi
  exit 2
fi

DEX_COUNT="$(printf '%s\n' "$ENTRIES" | grep -cE '^classes([0-9]+)?\.dex$' || true)"
ARSC_EXISTS="否"
grep -qx 'resources.arsc' <<<"$ENTRIES" && ARSC_EXISTS="是"

echo "============================================================"
echo "静态分析 14：第三方 SDK / 组件清单"
echo "目标：$TARGET"
echo "输入类型：APK"
echo "条目数：$ENTRY_COUNT"
echo "DEX 数量：$DEX_COUNT"
echo "resources.arsc：$ARSC_EXISTS"
echo "参数：max=$MAX"
echo "============================================================"

# ---------- 提取字符串 ----------
: > "$TMP_DIR/raw.txt"
scanned=0
echo "[loading] 正在提取 DEX/resources.arsc 字符串（大包可能需要几十秒到数分钟）..."
while IFS= read -r entry; do
  case "$entry" in
    classes*.dex|resources.arsc)
      unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 6 >> "$TMP_DIR/raw.txt" || true
      scanned=$((scanned + 1))
      ;;
  esac
done <<< "$ENTRIES"
RAW_LINES="$(grep -c . "$TMP_DIR/raw.txt" 2>/dev/null || true)"
echo "[done] 字符串提取完成：扫描 $scanned 个条目，$RAW_LINES 行"

# 统一把 JVM 描述符中的 / 归一化为 .，便于匹配包名
echo "[loading] 正在归一化并匹配 SDK 特征..."
tr '/' '.' < "$TMP_DIR/raw.txt" > "$TMP_DIR/norm.txt"

cat > "$TMP_DIR/sdks.txt" <<'EOF'
Google Firebase|com.google.firebase
Google Play Services|com.google.android.gms
Google Maps|com.google.android.maps
Google Gson|com.google.gson
Facebook SDK|com.facebook.appevents
Facebook Login|com.facebook.login
Facebook React Native|com.facebook.react
Flutter|io.flutter
Cordova|org.apache.cordova
Unity|com.unity3d.player
Tencent Bugly|com.tencent.bugly
Tencent MM/WeChat SDK|com.tencent.mm.opensdk
Tencent OpenSDK|com.tencent.open
Tencent GDT Ads|com.qq.e
Alipay SDK|com.alipay.sdk
Alipay Core|com.alipay.android
Alibaba SecurityGuard|com.alibaba.security
AMap|com.amap.api
Baidu Map|com.baidu.mapapi
Baidu Push|com.baidu.android.push
JPush/Jiguang|cn.jpush
Jiguang|cn.jiguang
Getui/个推|com.igexin
Huawei HMS|com.huawei.hms
Huawei AGConnect|com.huawei.agconnect
Xiaomi Push|com.xiaomi.push
OPPO Push|com.heytap.msp
Vivo Push|com.vivo.push
Meizu Push|com.meizu.cloud.pushsdk
Umeng/友盟|com.umeng
ByteDance SDK|com.bytedance
Sensors Analytics/神策|com.sensorsdata
GrowingIO|com.growingio
TalkingData|com.tendcloud
Adjust|com.adjust.sdk
AppsFlyer|com.appsflyer
Branch|io.branch
Crashlytics|com.crashlytics
Sentry|io.sentry
New Relic|com.newrelic
Datadog|com.datadog
Amplitude|com.amplitude
Mixpanel|com.mixpanel
OneSignal|com.onesignal
Mapbox|com.mapbox
OkHttp|okhttp3
Retrofit|retrofit2
RxJava|io.reactivex
Glide|com.bumptech.glide
Coil|coil.request
Dagger/Hilt|dagger.internal|dagger.hilt
Kotlin|kotlin
PayPal|com.paypal
Stripe|com.stripe
Braintree|com.braintreepayments
Adyen|com.adyen
UnionPay/银联|com.unionpay
Weibo SDK|com.sina.weibo
DingTalk|com.alibaba.android.dingtalk
WeChat Pay|com.tencent.mm.opensdk.openapi
EOF

cut -d'|' -f2- "$TMP_DIR/sdks.txt" > "$TMP_DIR/tokens.txt"
grep -F -f "$TMP_DIR/tokens.txt" "$TMP_DIR/norm.txt" > "$TMP_DIR/matched.txt" 2>/dev/null || true
echo "[done] 特征匹配完成：$(grep -c . "$TMP_DIR/matched.txt" 2>/dev/null || true) 行命中"

: > "$TMP_DIR/results.txt"
found=0
while IFS='|' read -r name token; do
  [[ -n "$name" && -n "$token" ]] || continue
  cnt="$(grep -Fc -- "$token" "$TMP_DIR/matched.txt" 2>/dev/null || true)"
  if [[ "$cnt" -gt 0 ]]; then
    evidence="$(grep -Fm1 -- "$token" "$TMP_DIR/matched.txt" 2>/dev/null | cut -c1-140 || true)"
    printf '%s|%s|%s\n' "$name" "$cnt" "$evidence" >> "$TMP_DIR/results.txt"
    found=$((found + 1))
  fi
done < "$TMP_DIR/sdks.txt"

echo "------------------------------------------------------------"
if [[ "$found" -eq 0 ]]; then
  echo "SDK/库命中：0 个"
else
  echo "SDK/库命中：$found 个（按命中次数排序）"
  sort -t'|' -k2,2nr "$TMP_DIR/results.txt" | awk -v max="$MAX" 'NR <= max' \
    | awk -F'|' '{printf "  - %-26s 命中 %-6s 证据: %s\n", $1, $2, $3}'
  if [[ "$found" -gt "$MAX" ]]; then
    echo "  ...（其余 $((found - MAX)) 个已省略）"
  fi
fi

echo "------------------------------------------------------------"
echo "【结论】"
if [[ "$found" -gt 0 ]]; then
  echo "  - 共识别出 $found 个已知 SDK/库特征，说明应用集成了对应的第三方组件。"
  echo "  - 命中基于包名/类名/字符串特征，不能据此确定 SDK 的具体版本或是否启用。"
  echo "  - 清单可作为隐私合规、供应链和攻击面梳理的输入；未做 CVE/版本漏洞比对。"
  echo "  - 建议人工核对：实际初始化调用、隐私政策披露、数据出境与权限使用。"
  exit 0
fi
echo "  - 未识别到内置特征库中的 SDK/库。"
echo "  - 可能原因：代码高度混淆/加固、SDK 被裁剪、使用未收录的自研或小众库。"
echo "  说明：本脚本只做字符串/包名启发式识别，不证明应用没有集成某 SDK。"
exit 1
