#!/usr/bin/env bash
#
# 12-ios-ipa.sh —— 通用静态分析：iOS IPA 审计（可选）
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   - 识别 IPA 结构：Payload/*.app、可执行文件、Frameworks、PlugIns
#   - 读取 Info.plist：Bundle ID、版本、最低系统版本、URL Schemes、
#     ATS（App Transport Security）、文件共享开关
#   - 读取代码签名：Authority、TeamIdentifier、Entitlements
#   - 检查 Mach-O 是否加密（LC_ENCRYPTION_INFO / cryptid）
#   - 读取 embedded.mobileprovision（名称、Team ID、过期时间、设备数）
#   - 如果是 Flutter：扫描 Frameworks/App.framework/App 中的 URL/密钥线索
#
#   说明：
#     plutil / codesign / otool 是 macOS 工具，因此本脚本只能在 macOS 上运行。
#     IPA 内可执行文件若 cryptid=1，表示仍处于 App Store 加密状态，
#     不能直接做字符串/反汇编分析；需要已解密的 IPA 或设备侧 dump。
#
# 参数：
#   <IPA>       必填
#                格式：存在且可读的 IPA 文件路径；ZIP 内必须包含 Payload/*.app/Info.plist
#                示例：./app.ipa
#                说明：APK/AAB/APKS/JAR/普通 ZIP 会被识别并提示不是 IPA，exit 2
#   --max N     可选
#                格式：非负整数（^[0-9]+$）
#                默认：30
#                示例：--max 80
#                说明：每个列表最多显示 N 行
#   --keep      可选
#                格式：布尔开关，不带值
#                默认：关闭（退出时删除临时目录）
#                示例：--keep
#                说明：保留解压后的临时目录，便于手工继续分析
#
# 依赖：
#   unzip、plutil、codesign、otool、strings、file、find、grep、awk，
#   shasum/openssl 之一。
#   security 可选（用于解码 embedded.mobileprovision）。
#   缺少必需工具时明确提示安装方式并退出，不会静默跳过。
#   仅支持 macOS（plutil / codesign / otool 是 macOS 工具）。
#
# 用法：
#   ./12-ios-ipa.sh <IPA>
#   ./12-ios-ipa.sh <IPA> --max 80
#   ./12-ios-ipa.sh <IPA> --keep
#   ./12-ios-ipa.sh --help
#
#   错误输入示例：
#     ./12-ios-ipa.sh app.apk
#       → 识别为 APK，提示不是 IPA，exit 2
#     ./12-ios-ipa.sh missing.ipa
#       → 文件不存在，exit 2
#
# 输出：
#   .app 结构、Info.plist、代码签名/Entitlements、Mach-O 加密状态、
#   Frameworks/PlugIns、Flutter 字符串线索、mobileprovision、【结论】。
#   默认不写文件；--keep 时保留临时目录。
#
# 退出码：
#   0 = 分析完成（无论是否发现风险）
#   1 = 保留给“分析不完整/有差异”等业务语义，本脚本当前不返回
#   2 = 参数/依赖/平台/输入错误（不是 IPA、找不到 .app、解压失败）
#
set -euo pipefail
export LC_ALL=C

MAX_LINES=30
KEEP=false
TARGET=""

usage() {
  cat <<'EOF'
用法:
  ./12-ios-ipa.sh <IPA>
  ./12-ios-ipa.sh <IPA> --max 80
  ./12-ios-ipa.sh <IPA> --keep
  ./12-ios-ipa.sh --help

参数:
  <IPA>     必填。格式: 存在且可读的 IPA 文件路径。示例: ./app.ipa
  --max N   可选。格式: 非负整数。默认: 30。示例: --max 80
  --keep    可选。布尔开关。默认: 关闭。示例: --keep

输出:
  .app 结构、Info.plist、签名/Entitlements、Mach-O 加密状态、Flutter 线索、描述文件、【结论】。

退出码:
  0 = 分析完成（无论是否发现风险）
  1 = 保留给“分析不完整/有差异”等业务语义，本脚本当前不返回
  2 = 参数/依赖/平台/输入错误（不是 IPA、找不到 .app、解压失败）
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max)
      if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
        echo "[FAIL] --max 需要一个非负整数" >&2
        exit 2
      fi
      MAX_LINES="$2"
      shift 2
      ;;
    --keep)
      KEEP=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "[FAIL] 未知参数: $1" >&2
      exit 2
      ;;
    *)
      if [[ -n "$TARGET" ]]; then
        echo "[FAIL] 只能指定一个 IPA" >&2
        exit 2
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[FAIL] 缺少必填参数 <IPA>。" >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] 文件不存在: $TARGET" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[FAIL] 本脚本依赖 macOS 的 plutil / codesign / otool。" >&2
  echo "       请在 macOS 上运行；Linux 可改用 unzip + plistutil + 其他签名工具，" >&2
  echo "       但本脚本不提供跨平台替代实现。" >&2
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

need_tool unzip   "macOS 通常自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool plutil  "macOS 自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool codesign "macOS 自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool otool   "macOS 自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool strings "macOS: xcode-select --install"
need_tool file    "macOS 自带；Linux: sudo apt install file"
need_tool find    "macOS 通常自带；Linux: sudo apt install findutils"
need_tool grep    "macOS 通常自带"
need_tool awk     "macOS 通常自带"

HASH_TOOL=""
if command -v shasum >/dev/null 2>&1; then
  HASH_TOOL="shasum"
elif command -v openssl >/dev/null 2>&1; then
  HASH_TOOL="openssl"
else
  echo "[FAIL] 缺少 SHA-256 工具（shasum 或 openssl）。" >&2
  echo "       macOS 通常自带 shasum；如缺失请安装 Xcode Command Line Tools。" >&2
  exit 2
fi

sha256_file() {
  local f="$1"
  if [[ "$HASH_TOOL" == "shasum" ]]; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    openssl dgst -sha256 "$f" | awk '{print $NF}'
  fi
}

# ---------- 1. 预检 ----------
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
if ! grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
  echo "============================================================"
  echo "静态分析 12：iOS IPA 审计"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  if [[ -n "$ENTRIES" ]]; then
    if grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
      echo "这是 APK，不是 IPA。请使用 Android 静态分析脚本。"
    elif grep -qx 'BundleConfig.pb' <<<"$ENTRIES" || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
      echo "这是 AAB，不是 IPA。"
    elif grep -qx 'toc.pb' <<<"$ENTRIES"; then
      echo "这是 APKS，不是 IPA。"
    else
      echo "这不是 IPA：ZIP 内没有 Payload/*.app/Info.plist。"
    fi
  else
    echo "输入不是有效的 ZIP/IPA。"
  fi
  exit 2
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ios-ipa.XXXXXX")"
trap 'if [[ "$KEEP" != true ]]; then rm -rf "$TMP_DIR"; fi' EXIT

echo "[loading] 正在解压 IPA（文件较大时可能需要几十秒）..."
if ! unzip -oq "$TARGET" -d "$TMP_DIR" 2> "$TMP_DIR/unzip.err"; then
  echo "[done] 解压结束：失败"
  echo "[FAIL] 解压失败：" >&2
  tail -10 "$TMP_DIR/unzip.err" | sed 's/^/       /' >&2
  exit 2
fi
echo "[done] 解压完成"

# 标准 IPA 只有一个 .app；如果有多个，取第一个并提示。
APP_DIR="$(find "$TMP_DIR/Payload" -maxdepth 1 -type d -name '*.app' 2>/dev/null | sort | awk 'NR == 1')"
APP_COUNT="$(find "$TMP_DIR/Payload" -maxdepth 1 -type d -name '*.app' 2>/dev/null | wc -l | tr -d ' ' || true)"

if [[ -z "$APP_DIR" || ! -d "$APP_DIR" ]]; then
  echo "[FAIL] Payload 下找不到 .app。" >&2
  exit 2
fi

INFO="$APP_DIR/Info.plist"
if [[ ! -f "$INFO" ]]; then
  echo "[FAIL] .app 内找不到 Info.plist：$APP_DIR" >&2
  exit 2
fi

plist_raw() {
  local key="$1"
  local val
  val="$(plutil -extract "$key" raw -o - "$INFO" 2>/dev/null || true)"
  if [[ -z "$val" ]]; then
    echo "(未设置)"
  else
    echo "$val"
  fi
}

BUNDLE_ID="$(plist_raw CFBundleIdentifier)"
SHORT_VERSION="$(plist_raw CFBundleShortVersionString)"
BUILD_VERSION="$(plist_raw CFBundleVersion)"
MIN_OS="$(plist_raw MinimumOSVersion)"
DISPLAY_NAME="$(plist_raw CFBundleDisplayName)"
EXEC_NAME="$(plist_raw CFBundleExecutable)"
FILE_SHARING="$(plist_raw UIFileSharingEnabled)"
OPEN_IN_PLACE="$(plist_raw LSSupportsOpeningDocumentsInPlace)"
NON_EXEMPT_CRYPTO="$(plist_raw ITSAppUsesNonExemptEncryption)"

if [[ "$EXEC_NAME" == "(未设置)" ]]; then
  EXEC_NAME="$(basename "$APP_DIR" .app)"
fi
EXEC_PATH="$APP_DIR/$EXEC_NAME"

# URL Schemes / ATS
URL_JSON="$(plutil -extract CFBundleURLTypes json -o - "$INFO" 2>/dev/null || true)"
URL_SCHEMES="$(printf '%s\n' "$URL_JSON" \
  | grep -oE '"CFBundleURLSchemes"[^]]*' \
  | grep -oE '"[^"]+"' \
  | grep -v 'CFBundleURLSchemes' \
  | tr -d '"' \
  | sort -u || true)"
URL_SCHEME_COUNT="$(printf '%s\n' "$URL_SCHEMES" | grep -c . || true)"

ATS_JSON="$(plutil -extract NSAppTransportSecurity json -o - "$INFO" 2>/dev/null || true)"

# ---------- 2. 基本信息 ----------
echo "============================================================"
echo "静态分析 12：iOS IPA 审计"
echo "目标：$TARGET"
echo "App bundle：${APP_DIR#"$TMP_DIR"/}（共 $APP_COUNT 个 .app）"
echo "Bundle ID：$BUNDLE_ID"
echo "显示名称：$DISPLAY_NAME"
echo "版本：$SHORT_VERSION（build $BUILD_VERSION）"
echo "MinimumOSVersion：$MIN_OS"
echo "可执行文件：$EXEC_NAME"
echo "============================================================"

if [[ -f "$EXEC_PATH" ]]; then
  EXEC_SIZE="$(wc -c < "$EXEC_PATH" | tr -d ' ')"
  EXEC_SHA="$(sha256_file "$EXEC_PATH")"
  echo "可执行文件信息："
  echo "  大小: $EXEC_SIZE 字节"
  echo "  SHA-256: $EXEC_SHA"
  echo "  架构/类型: $(file -b "$EXEC_PATH")"
else
  echo "⚠ 找不到可执行文件：$EXEC_PATH"
fi

# ---------- 3. Info.plist 配置 ----------
echo "------------------------------------------------------------"
echo "Info.plist 配置："
echo "  URL Schemes（$URL_SCHEME_COUNT 个）："
if [[ "$URL_SCHEME_COUNT" -gt 0 ]]; then
  printf '%s\n' "$URL_SCHEMES" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/    - /'
else
  echo "    (无)"
fi

echo "  文件共享：UIFileSharingEnabled=$FILE_SHARING，LSSupportsOpeningDocumentsInPlace=$OPEN_IN_PLACE"
echo "  ITSAppUsesNonExemptEncryption：$NON_EXEMPT_CRYPTO"

echo "  ATS（App Transport Security）："
if [[ -z "$ATS_JSON" ]]; then
  echo "    (未配置 NSAppTransportSecurity，使用系统默认)"
else
  printf '%s\n' "$ATS_JSON" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/    /'
  if grep -qE '"NSAllowsArbitraryLoads"[[:space:]]*:[[:space:]]*true' <<<"$ATS_JSON"; then
    echo "    ⚠ NSAllowsArbitraryLoads=true：允许任意明文 HTTP 连接。"
  fi
  if grep -qE '"NSAllowsArbitraryLoadsInWebContent"[[:space:]]*:[[:space:]]*true' <<<"$ATS_JSON"; then
    echo "    ⚠ NSAllowsArbitraryLoadsInWebContent=true：WebView 内容允许任意明文连接。"
  fi
  if grep -q '"NSExceptionDomains"' <<<"$ATS_JSON"; then
    echo "    - 存在 NSExceptionDomains：需确认例外域名和是否允许明文。"
  fi
fi

# ---------- 4. 代码签名与 Entitlements ----------
echo "------------------------------------------------------------"
echo "代码签名："
echo "[loading] 正在读取代码签名与 Entitlements..."
CS_LOG="$TMP_DIR/codesign.txt"
SIGNED=false
if codesign -dv --verbose=4 "$APP_DIR" > "$CS_LOG" 2>&1; then
  SIGNED=true
  grep -E '^(Identifier|Format|Executable|CodeDirectory|Signature|Authority|TeamIdentifier|Timestamp|CandidateCDHash|CDHash|Runtime Version|flags)=' "$CS_LOG" \
    | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  /' || true
else
  echo "  ⚠ codesign 无法读取签名信息（可能未签名或结构异常）："
  tail -10 "$CS_LOG" | sed 's/^/    /'
fi

echo "------------------------------------------------------------"
echo "Entitlements："
ENT_LOG="$TMP_DIR/entitlements.txt"
codesign -d --entitlements :- "$APP_DIR" > "$ENT_LOG" 2>&1 || true

# codesign 可能在 XML 前打印 Executable=/warning: 行；只取 XML 部分。
ENT_PLIST="$TMP_DIR/entitlements.plist"
sed -n '/<?xml/,$p' "$ENT_LOG" > "$ENT_PLIST" 2>/dev/null || true
if [[ ! -s "$ENT_PLIST" ]]; then
  sed -n '/<plist/,$p' "$ENT_LOG" > "$ENT_PLIST" 2>/dev/null || true
fi

GET_TASK_ALLOW=false
ENT_FLAT="$(tr -d '[:space:]' < "$ENT_PLIST" 2>/dev/null || true)"
if [[ "$ENT_FLAT" == *'<key>get-task-allow</key><true/>'* ]]; then
  GET_TASK_ALLOW=true
fi

if [[ -s "$ENT_PLIST" ]] && plutil -lint "$ENT_PLIST" >/dev/null 2>&1; then
  plutil -p "$ENT_PLIST" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  /'
  if [[ "$(plutil -p "$ENT_PLIST" | wc -l | tr -d ' ')" -gt "$MAX_LINES" ]]; then
    echo "  ...（已截断）"
  fi
  echo "  关键项："
  if [[ "$GET_TASK_ALLOW" == true ]]; then
    echo "    ⚠ get-task-allow=true：允许调试器附加，发布包不应出现。"
  else
    echo "    get-task-allow：false 或未设置"
  fi
  APS_ENV="$(printf '%s\n' "$ENT_FLAT" \
    | sed -nE 's#.*<key>aps-environment</key><string>([^<]+)</string>.*#\1#p' \
    | sed -n '1p' || true)"
  APP_ID="$(printf '%s\n' "$ENT_FLAT" \
    | sed -nE 's#.*<key>application-identifier</key><string>([^<]+)</string>.*#\1#p' \
    | sed -n '1p' || true)"
  if [[ -n "$APS_ENV" ]]; then
    echo "    aps-environment：$APS_ENV"
  fi
  if [[ -n "$APP_ID" ]]; then
    echo "    application-identifier：$APP_ID"
  fi
else
  echo "  (无 Entitlements，或 codesign 输出不是 XML)"
  if [[ -s "$ENT_LOG" ]]; then
    tail -5 "$ENT_LOG" | sed 's/^/    /'
  fi
fi
echo "[done] 签名信息读取完成"

# ---------- 5. Mach-O 加密状态 ----------
echo "------------------------------------------------------------"
echo "Mach-O 加密状态："
ENCRYPTED=false
CRYPT_VALUES=""
if [[ -f "$EXEC_PATH" ]]; then
  echo "[loading] 正在检查 Mach-O 加密状态（otool -l）..."
  OTOOL_LOG="$TMP_DIR/otool-l.txt"
  otool -l "$EXEC_PATH" > "$OTOOL_LOG" 2>&1 || true

  CRYPT_VALUES="$(awk '/cryptid[[:space:]]+[0-9]+/ {print $2}' "$OTOOL_LOG" | sort -u | paste -sd, - 2>/dev/null || true)"
  CRYPT_LINES="$(grep -E 'LC_ENCRYPTION_INFO|cryptid' "$OTOOL_LOG" || true)"

  if [[ -n "$CRYPT_LINES" ]]; then
    printf '%s\n' "$CRYPT_LINES" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  /'
  else
    echo "  (未找到 LC_ENCRYPTION_INFO，可能是模拟器包或非标准 Mach-O)"
  fi

  if [[ -n "$CRYPT_VALUES" ]]; then
    echo "  cryptid 值：$CRYPT_VALUES"
    if printf '%s\n' "$CRYPT_VALUES" | tr ',' '\n' | grep -qx '1'; then
      ENCRYPTED=true
      echo "  ⚠ 存在 cryptid=1：可执行文件仍被 App Store 加密，无法直接静态分析。"
      echo "    需要已解密的 IPA，或在测试设备上 dump 后再分析。"
    else
      echo "  cryptid=0：可执行文件未加密，可继续做 strings/反汇编。"
    fi
  fi
  echo "[done] 加密状态检查完成"
else
  echo "  (可执行文件不存在，跳过)"
fi

# ---------- 6. Frameworks / PlugIns ----------
echo "------------------------------------------------------------"
echo "Frameworks / PlugIns："
if [[ -d "$APP_DIR/Frameworks" ]]; then
  FRAMEWORKS="$(find "$APP_DIR/Frameworks" -maxdepth 1 -type d -name '*.framework' 2>/dev/null | sort || true)"
  FRAMEWORK_COUNT="$(printf '%s\n' "$FRAMEWORKS" | grep -c . || true)"
  echo "  Frameworks（$FRAMEWORK_COUNT 个）："
  if [[ "$FRAMEWORK_COUNT" -gt 0 ]]; then
    printf '%s\n' "$FRAMEWORKS" | sed "s#^$APP_DIR/##" \
      | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/    - /'
    if [[ "$FRAMEWORK_COUNT" -gt "$MAX_LINES" ]]; then
      echo "    ...（其余 $((FRAMEWORK_COUNT - MAX_LINES)) 个已省略）"
    fi
  else
    echo "    (无)"
  fi
else
  echo "  Frameworks：(目录不存在)"
fi

if [[ -d "$APP_DIR/PlugIns" ]]; then
  PLUGINS="$(find "$APP_DIR/PlugIns" -maxdepth 1 -type d -name '*.appex' 2>/dev/null | sort || true)"
  PLUGIN_COUNT="$(printf '%s\n' "$PLUGINS" | grep -c . || true)"
  echo "  PlugIns（$PLUGIN_COUNT 个）："
  if [[ "$PLUGIN_COUNT" -gt 0 ]]; then
    printf '%s\n' "$PLUGINS" | sed "s#^$APP_DIR/##" \
      | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/    - /'
  else
    echo "    (无)"
  fi
else
  echo "  PlugIns：(目录不存在)"
fi

# ---------- 7. Flutter 检测与字符串线索 ----------
echo "------------------------------------------------------------"
FLUTTER_BIN="$APP_DIR/Frameworks/App.framework/App"
FLUTTER_RUNTIME="$APP_DIR/Frameworks/Flutter.framework/Flutter"

if [[ -f "$FLUTTER_BIN" ]]; then
  echo "Flutter：检测到 Frameworks/App.framework/App（Dart AOT 业务代码）。"
  if [[ -f "$FLUTTER_RUNTIME" ]]; then
    echo "  同时检测到 Frameworks/Flutter.framework/Flutter（Flutter 运行时）。"
  fi

  FL_STR="$TMP_DIR/flutter-strings.txt"
  echo "[loading] 正在扫描 Flutter 可执行文件中的字符串（文件较大时可能需要一段时间）..."
  strings -a -n 6 "$FLUTTER_BIN" > "$FL_STR" 2>/dev/null || true
  echo "[done] Flutter 字符串扫描完成"

  FL_URLS="$(grep -Eo '(https?)://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$FL_STR" \
    | sed -E 's/[]>,.;:)]+$//' \
    | awk -F/ '
        {
          host = $3
          sub(/^.*@/, "", host)
          sub(/:[0-9]+$/, "", host)
          if (host ~ /\./ || host == "localhost" || host ~ /^[0-9]+(\.[0-9]+){3}$/) print
        }' \
    | grep -Ev '^https?://(www\.w3\.org|ns\.adobe\.com|schemas\.android\.com|xmlpull\.org|java\.sun\.com|www\.unicode\.org)/' \
    | sort -u || true)"
  FL_URL_COUNT="$(printf '%s\n' "$FL_URLS" | grep -c . || true)"

  FL_KEYS="$(grep -Eo 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY' "$FL_STR" \
    | sort -u || true)"
  FL_KEY_COUNT="$(printf '%s\n' "$FL_KEYS" | grep -c . || true)"

  FL_ENV="$(printf '%s\n' "$FL_URLS" \
    | grep -Ei '([.-]|://)(dev|develop|development|test|testing|uat|staging|stage|preprod|sandbox)([.-]|:|/|$)' \
    | grep -Ev '^https?://([^/]*\.)?(flutter\.dev|dart\.dev|pub\.dev)/' || true)"
  FL_ENV_COUNT="$(printf '%s\n' "$FL_ENV" | grep -c . || true)"

  echo "  URL（$FL_URL_COUNT 个，去重）："
  if [[ "$FL_URL_COUNT" -gt 0 ]]; then
    printf '%s\n' "$FL_URLS" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/    - /'
    if [[ "$FL_URL_COUNT" -gt "$MAX_LINES" ]]; then
      echo "    ...（其余 $((FL_URL_COUNT - MAX_LINES)) 个已省略）"
    fi
  else
    echo "    (无)"
  fi

  echo "  测试/开发环境地址（$FL_ENV_COUNT 条）："
  if [[ "$FL_ENV_COUNT" -gt 0 ]]; then
    printf '%s\n' "$FL_ENV" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/    - /'
  else
    echo "    (无)"
  fi

  echo "  高置信密钥形态（$FL_KEY_COUNT 条）："
  if [[ "$FL_KEY_COUNT" -gt 0 ]]; then
    printf '%s\n' "$FL_KEYS" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/    - /'
  else
    echo "    (无)"
  fi
  echo "  说明：iOS Flutter 的 Dart 业务逻辑在 App.framework/App 中，jadx/DEX 分析不适用。"
else
  echo "Flutter：未检测到 Frameworks/App.framework/App。"
fi

# ---------- 8. embedded.mobileprovision ----------
echo "------------------------------------------------------------"
echo "embedded.mobileprovision："
PROFILE="$APP_DIR/embedded.mobileprovision"
if [[ -f "$PROFILE" ]]; then
  echo "  文件存在：$(( $(wc -c < "$PROFILE" | tr -d ' ') )) 字节"
  if command -v security >/dev/null 2>&1; then
    echo "[loading] 正在解码 embedded.mobileprovision..."
    PROFILE_PLIST="$TMP_DIR/profile.plist"
    if security cms -D -i "$PROFILE" > "$PROFILE_PLIST" 2> "$TMP_DIR/security.err" \
       && [[ -s "$PROFILE_PLIST" ]]; then
      PROFILE_NAME="$(plutil -extract Name raw -o - "$PROFILE_PLIST" 2>/dev/null || true)"
      PROFILE_TEAM="$(plutil -extract TeamIdentifier.0 raw -o - "$PROFILE_PLIST" 2>/dev/null || true)"
      PROFILE_EXPIRE="$(plutil -extract ExpirationDate raw -o - "$PROFILE_PLIST" 2>/dev/null || true)"
      PROFILE_ALL_DEVICES="$(plutil -extract ProvisionsAllDevices raw -o - "$PROFILE_PLIST" 2>/dev/null || true)"
      PROFILE_DEVICE_COUNT="$(plutil -extract ProvisionedDevices xml1 -o - "$PROFILE_PLIST" 2>/dev/null \
        | grep -c '<string>' || true)"

      echo "  Name：${PROFILE_NAME:-（未知）}"
      echo "  TeamIdentifier：${PROFILE_TEAM:-（未知）}"
      echo "  ExpirationDate：${PROFILE_EXPIRE:-（未知）}"
      echo "  ProvisionsAllDevices：${PROFILE_ALL_DEVICES:-（未设置）}"
      echo "  ProvisionedDevices：${PROFILE_DEVICE_COUNT:-0} 个"
      if [[ "${PROFILE_ALL_DEVICES:-}" == "true" ]]; then
        echo "  - 企业/全设备描述文件：不是 App Store 分发。"
      fi
    else
      echo "  ⚠ security cms -D 解码失败："
      tail -5 "$TMP_DIR/security.err" | sed 's/^/    /'
    fi
    echo "[done] 描述文件解码结束"
  else
    echo "  ⚠ 找到描述文件，但缺少 security 命令（macOS 自带）。"
    echo "    安装 Xcode Command Line Tools: xcode-select --install"
  fi
else
  echo "  (未找到 embedded.mobileprovision)"
fi

# ---------- 9. 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

RISK=false

if [[ "$SIGNED" != true ]]; then
  echo "  ⚠ 未读取到有效代码签名：需确认 IPA 是否被重签或结构是否完整。"
  RISK=true
else
  echo "  - 代码签名信息已读取；请核对 Authority / TeamIdentifier 是否与发布方一致。"
fi

if [[ "$ENCRYPTED" == true ]]; then
  echo "  ⚠ 可执行文件仍被 App Store 加密（cryptid=1）：静态分析不完整。"
  RISK=true
fi

if [[ "$FILE_SHARING" == "true" || "$OPEN_IN_PLACE" == "true" ]]; then
  echo "  ⚠ 开启了文件共享/iTunes 文件访问：需确认 Documents 中是否包含敏感数据。"
  RISK=true
fi

if [[ "$GET_TASK_ALLOW" == true ]]; then
  echo "  ⚠ Entitlements 含 get-task-allow=true：发布包不应允许调试器附加。"
  RISK=true
fi

if [[ -n "$ATS_JSON" ]] && \
   grep -qE '"NSAllowsArbitraryLoads"[[:space:]]*:[[:space:]]*true' <<<"$ATS_JSON"; then
  echo "  ⚠ ATS 允许任意明文 HTTP：需确认是否传输敏感数据。"
  RISK=true
fi

if [[ "$URL_SCHEME_COUNT" -gt 0 ]]; then
  echo "  - 存在 $URL_SCHEME_COUNT 个 URL Scheme：需审计 deeplink 参数校验和跳转逻辑。"
fi

if [[ -f "$FLUTTER_BIN" ]]; then
  echo "  - 这是 Flutter iOS 包：Dart AOT 逻辑需单独分析，不能只依赖 Mach-O 字符串。"
fi

if [[ "$RISK" == true ]]; then
  echo "  以上为静态结构信号，需结合签名、描述文件、运行环境和业务逻辑确认。"
else
  echo "  未发现上述明显风险项；这不等于应用安全，仍需做动态和业务逻辑测试。"
fi

if [[ "$KEEP" == true ]]; then
  echo "------------------------------------------------------------"
  echo "临时目录已保留：$TMP_DIR"
fi

exit 0
