#!/usr/bin/env bash
#
# 16-ios-macho-audit.sh —— 通用静态分析：iOS IPA / Mach-O 深度审计
#
# 用途：
#   1. 读取 IPA 结构、Info.plist、URL Scheme、ATS、隐私用途描述、
#      PrivacyInfo.xcprivacy、代码签名与 Entitlements、mobileprovision。
#   2. 检查 Mach-O：架构、LC_ENCRYPTION_INFO(cryptid)、链接的动态库、
#      可疑注入库、Swift 符号线索、ObjC 类（可选 class-dump）。
#   3. 对可执行文件/Flutter App.framework 做 URL、密钥形态、测试环境字符串提取。
#   4. 不覆盖：Mach-O 反汇编控制流、Swift/ObjC 伪代码还原、动态验证。
#
# 参数：
#   <IPA>           必填
#                   格式：存在且可读的 IPA 文件路径（ZIP + Payload/*.app/Info.plist）
#                   示例：./app.ipa
#                   说明：非 IPA 输入会提示不适用，exit 2
#
#   --max N         可选
#                   格式：非负整数（^[0-9]+$）
#                   默认：25
#                   示例：--max 50
#                   说明：每个列表最多显示 N 行
#
# 依赖：
#   unzip、plutil、codesign、otool、file、strings、grep、awk、find
#   class-dump、nm、lipo、security 为可选：缺失时说明未分析，不中断。
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./16-ios-macho-audit.sh <IPA>
#   ./16-ios-macho-audit.sh <IPA> --max 50
#   ./16-ios-macho-audit.sh --help
#
# 输出：
#   IPA/Info.plist 摘要、Mach-O 信息、签名与描述文件、字符串线索、
#   可疑项列表、【结论】。临时文件放在 mktemp 目录，退出时删除。
#
# 退出码：
#   0 = 审计完成
#   1 = 审计不完整（例如 Mach-O 仍加密、缺少可执行文件）
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

MAX=25
TARGET=""

usage() {
  cat <<'EOF'
用法: ./16-ios-macho-audit.sh <IPA> [--max N]

参数:
  <IPA>     必填。格式: IPA 文件路径（ZIP 内含 Payload/*.app/Info.plist）。
  --max N   可选。格式: 非负整数。默认: 25。示例: --max 50
  -h, --help 显示本帮助。

退出码:
  0 = 审计完成
  1 = 审计不完整（Mach-O 加密或缺少可执行文件）
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
  echo "[FAIL] 缺少必填参数 <IPA>。" >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$TARGET" || ! -r "$TARGET" ]]; then
  echo "[FAIL] 文件不存在或不可读: $TARGET" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[FAIL] 本脚本依赖 plutil/codesign/otool，只能在 macOS 上运行。" >&2
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

need_tool unzip    "macOS 通常自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool plutil   "macOS 自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool codesign "macOS 自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool otool    "macOS 自带；如缺失请安装 Xcode Command Line Tools: xcode-select --install"
need_tool file     "macOS 通常自带"
need_tool strings  "macOS: xcode-select --install"
need_tool grep     "macOS 通常自带"
need_tool awk      "macOS 通常自带"
need_tool find     "macOS 通常自带"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ios-audit.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

report_hits() {
  local label="$1" file="$2" total
  total="$(grep -c . "$file" 2>/dev/null || true)"
  echo "$label（$total 处）："
  if [[ "$total" -eq 0 ]]; then
    echo "  (无)"
  else
    awk -v max="$MAX" 'NR <= max' "$file" | sed 's/^/  - /'
    if [[ "$total" -gt "$MAX" ]]; then
      echo "  ...（其余 $((total - MAX)) 处已省略）"
    fi
  fi
}

echo "[loading] 正在读取 IPA 条目..."
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
ENTRY_COUNT="$(printf '%s\n' "$ENTRIES" | grep -c . || true)"
echo "[done] 条目读取完成：$ENTRY_COUNT 个"

if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  echo "[FAIL] 输入不是有效的 ZIP/IPA，或文件已损坏。" >&2
  exit 2
fi
if ! grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
  if grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
    echo "[FAIL] 输入是 Android APK，不是 IPA。" >&2
  else
    echo "[FAIL] 输入不是 IPA（未找到 Payload/*.app/Info.plist）。" >&2
  fi
  exit 2
fi

echo "============================================================"
echo "静态分析 16：iOS IPA / Mach-O 深度审计"
echo "目标：$TARGET"
echo "输入类型：IPA"
echo "条目数：$ENTRY_COUNT"
echo "参数：max=$MAX"
echo "============================================================"

echo "[loading] 正在解压 IPA（文件较大时可能需要几十秒）..."
unzip -oq "$TARGET" -d "$TMP_DIR/extract" 2>/dev/null
echo "[done] 解压完成"

APP_DIR="$(find "$TMP_DIR/extract/Payload" -maxdepth 1 -name '*.app' -type d 2>/dev/null | awk 'NR == 1' || true)"
if [[ -z "$APP_DIR" || ! -d "$APP_DIR" ]]; then
  echo "[FAIL] 未找到 .app 目录。" >&2
  exit 1
fi
INFO="$APP_DIR/Info.plist"
APP_NAME="$(basename "$APP_DIR" .app)"

plist_get() {
  plutil -extract "$1" raw -o - "$INFO" 2>/dev/null || true
}

BUNDLE_ID="$(plist_get CFBundleIdentifier)"
VERSION="$(plist_get CFBundleShortVersionString)"
BUILD="$(plist_get CFBundleVersion)"
MIN_OS="$(plist_get MinimumOSVersion)"
EXEC_NAME="$(plist_get CFBundleExecutable)"
EXEC="$APP_DIR/$EXEC_NAME"

echo "------------------------------------------------------------"
echo "应用信息："
echo "  App bundle：$APP_NAME.app"
echo "  Bundle ID：${BUNDLE_ID:-未知}"
echo "  版本：${VERSION:-未知} (${BUILD:-未知})"
echo "  MinimumOSVersion：${MIN_OS:-未知}"
echo "  可执行文件：${EXEC_NAME:-未知}"

URL_SCHEMES="$(plutil -p "$INFO" 2>/dev/null | awk '
  /"CFBundleURLSchemes"/ { inarr = 1; next }
  inarr {
    if ($0 ~ /\]/) { inarr = 0; next }
    if (match($0, /"[^"]+"/)) print substr($0, RSTART + 1, RLENGTH - 2)
  }
' | sort -u || true)"
echo "  URL Schemes："
if [[ -z "$URL_SCHEMES" ]]; then
  echo "    (未发现)"
else
  printf '%s\n' "$URL_SCHEMES" | awk -v max="$MAX" 'NR <= max' | sed 's/^/    - /'
fi

echo "  ATS（NSAppTransportSecurity）："
ATS_JSON="$(plutil -extract NSAppTransportSecurity json -o - "$INFO" 2>/dev/null || true)"
if [[ -z "$ATS_JSON" ]]; then
  echo "    (未配置)"
else
  printf '%s\n' "$ATS_JSON" | awk -v max="$MAX" 'NR <= max' | sed 's/^/    /'
fi

echo "  隐私用途描述（UsageDescription）："
PRIV_KEYS="$(plutil -p "$INFO" 2>/dev/null | grep -oE '"[A-Za-z]+UsageDescription"' | tr -d '"' | sort -u || true)"
if [[ -z "$PRIV_KEYS" ]]; then
  echo "    (未发现)"
else
  printf '%s\n' "$PRIV_KEYS" | awk -v max="$MAX" 'NR <= max' | sed 's/^/    - /'
fi

echo "  后台模式（UIBackgroundModes）："
BG="$(plutil -extract UIBackgroundModes json -o - "$INFO" 2>/dev/null || true)"
[[ -n "$BG" ]] && printf '%s\n' "$BG" | sed 's/^/    /' || echo "    (未配置)"

echo "  PrivacyInfo.xcprivacy："
PRIVACY_MANIFESTS="$(find "$APP_DIR" -name 'PrivacyInfo.xcprivacy' 2>/dev/null || true)"
if [[ -z "$PRIVACY_MANIFESTS" ]]; then
  echo "    (未发现)"
else
  printf '%s\n' "$PRIVACY_MANIFESTS" | sed "s|$APP_DIR/||" | awk -v max="$MAX" 'NR <= max' | sed 's/^/    - /'
fi

# ---------- Mach-O ----------
echo "------------------------------------------------------------"
echo "Mach-O / 动态库："
CRYPTID=""
EXEC_FOUND=false
if [[ -f "$EXEC" ]]; then
  EXEC_FOUND=true
  file "$EXEC" | sed 's/^/  /'
  if command -v lipo >/dev/null 2>&1; then
    lipo -info "$EXEC" 2>/dev/null | sed 's/^/  /' || true
  fi
  echo "[loading] 正在读取 Mach-O 头与加密信息..."
  CRYPTID="$(otool -l "$EXEC" 2>/dev/null | grep -A4 'cmd LC_ENCRYPTION_INFO' | grep 'cryptid' | awk '{print $2}' | awk 'NR == 1' || true)"
  if [[ -z "$CRYPTID" ]]; then
    echo "  cryptid：未找到 LC_ENCRYPTION_INFO（可能不是 Mach-O）"
  elif [[ "$CRYPTID" == "0" ]]; then
    echo "  cryptid=0：未加密，可继续做 strings/反汇编"
  else
    echo "  cryptid=$CRYPTID：仍处于 App Store 加密状态，不能直接做代码分析"
  fi
  echo "  链接的动态库（前 $MAX 个）："
  otool -L "$EXEC" 2>/dev/null | awk 'NR > 1 && $1 != "" {print $1}' | awk -v max="$MAX" 'NR <= max' | sed 's/^/    - /'
else
  echo "  [WARN] 未找到可执行文件：$EXEC"
fi

echo "  Frameworks（$(find "$APP_DIR/Frameworks" -maxdepth 1 -name '*.framework' -type d 2>/dev/null | wc -l | tr -d ' ') 个）："
find "$APP_DIR/Frameworks" -maxdepth 1 -name '*.framework' -type d 2>/dev/null \
  | sed 's|.*/||' | sort | awk -v max="$MAX" 'NR <= max' | sed 's/^/    - /' || true
FRAMEWORK_COUNT="$(find "$APP_DIR/Frameworks" -maxdepth 1 -name '*.framework' -type d 2>/dev/null | wc -l | tr -d ' ' || true)"
if [[ "$FRAMEWORK_COUNT" -gt "$MAX" ]]; then
  echo "    ...（其余 $((FRAMEWORK_COUNT - MAX)) 个已省略）"
fi

: > "$TMP_DIR/suspicious-dylib.txt"
find "$APP_DIR" -type f \( -name '*.dylib' -o -path '*/Frameworks/*' \) 2>/dev/null \
  | grep -Ei 'frida|substrate|substitute|libhooker|cycript|injection|libinject' \
  >> "$TMP_DIR/suspicious-dylib.txt" || true
echo "------------------------------------------------------------"
report_hits "可疑注入/调试相关库文件" "$TMP_DIR/suspicious-dylib.txt"

# ---------- 签名 / Entitlements / 描述文件 ----------
echo "------------------------------------------------------------"
echo "代码签名："
SIGN_INFO="$(codesign -dv --verbose=4 "$APP_DIR" 2>&1 || true)"
printf '%s\n' "$SIGN_INFO" | grep -E 'Identifier=|Authority=|TeamIdentifier=|CDHash=|Signature=' | awk -v max="$MAX" 'NR <= max' | sed 's/^/  /' || true

echo "  Entitlements："
ENTITLEMENTS="$(codesign -d --entitlements :- "$APP_DIR" 2>/dev/null || true)"
if [[ -z "$ENTITLEMENTS" ]]; then
  echo "    (未读取到)"
else
  printf '%s\n' "$ENTITLEMENTS" | awk -v max="$MAX" 'NR <= max' | sed 's/^/    /'
fi

echo "  embedded.mobileprovision："
PROV="$APP_DIR/embedded.mobileprovision"
if [[ -f "$PROV" ]] && command -v security >/dev/null 2>&1; then
  if security cms -D -i "$PROV" > "$TMP_DIR/prov.plist" 2>/dev/null; then
    plutil -p "$TMP_DIR/prov.plist" 2>/dev/null \
      | grep -E '"(Name|TeamIdentifier|ExpirationDate|ProvisionsAllDevices)"' \
      | awk -v max="$MAX" 'NR <= max' | sed 's/^/    /' || true
    DEV_CNT="$(plutil -extract ProvisionedDevices json -o - "$TMP_DIR/prov.plist" 2>/dev/null | grep -o '"' | wc -l | tr -d ' ' || true)"
    echo "    ProvisionedDevices：约 $((DEV_CNT / 2)) 个"
  else
    echo "    (解码失败)"
  fi
else
  echo "    (不存在或 security 工具不可用)"
fi

# ---------- ObjC / Swift ----------
echo "------------------------------------------------------------"
echo "符号/类信息："
if command -v class-dump >/dev/null 2>&1 && [[ -f "$EXEC" ]]; then
  CLASS_CNT="$(class-dump "$EXEC" 2>/dev/null | grep -c '^@interface' || true)"
  echo "  ObjC 类（class-dump）：$CLASS_CNT 个"
else
  echo "  ObjC 类：class-dump 未安装，此项未分析（brew install class-dump）"
fi
if command -v nm >/dev/null 2>&1 && [[ -f "$EXEC" ]]; then
  SWIFT_SYMS="$(nm -u "$EXEC" 2>/dev/null | grep -c '_\$s' || true)"
  echo "  Swift 符号（nm，启发式）：$SWIFT_SYMS 个"
else
  echo "  Swift 符号：nm 不可用，此项未分析"
fi

# ---------- 字符串线索 ----------
: > "$TMP_DIR/string-dump.txt"
SCAN_TARGETS=()
[[ -f "$EXEC" ]] && SCAN_TARGETS+=("$EXEC")
[[ -f "$APP_DIR/Frameworks/App.framework/App" ]] && SCAN_TARGETS+=("$APP_DIR/Frameworks/App.framework/App")
if [[ "${#SCAN_TARGETS[@]}" -gt 0 ]]; then
  echo "[loading] 正在扫描可执行文件字符串（大文件可能需要一段时间）..."
  for f in "${SCAN_TARGETS[@]}"; do
    strings -a -n 6 "$f" >> "$TMP_DIR/string-dump.txt" 2>/dev/null || true
  done
  echo "[done] 字符串扫描完成：$(grep -c . "$TMP_DIR/string-dump.txt" 2>/dev/null || true) 行"
fi

: > "$TMP_DIR/url.txt"
grep -aoE 'https?://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$TMP_DIR/string-dump.txt" 2>/dev/null | sort -u > "$TMP_DIR/url.txt" || true
: > "$TMP_DIR/secret.txt"
grep -aoE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----' "$TMP_DIR/string-dump.txt" 2>/dev/null | sort -u > "$TMP_DIR/secret.txt" || true
: > "$TMP_DIR/env.txt"
grep -aEi '(https?://[^ ]*(dev|test|uat|staging|sandbox)\.)|([a-z0-9-]+\.)+(dev|test|uat|staging|sandbox)\.' "$TMP_DIR/string-dump.txt" 2>/dev/null | sort -u | cut -c1-200 > "$TMP_DIR/env.txt" || true

echo "------------------------------------------------------------"
report_hits "URL" "$TMP_DIR/url.txt"
echo "------------------------------------------------------------"
report_hits "高置信密钥形态" "$TMP_DIR/secret.txt"
echo "------------------------------------------------------------"
report_hits "测试/开发环境线索" "$TMP_DIR/env.txt"

echo "------------------------------------------------------------"
echo "【结论】"
echo "  - 这是 iOS IPA：$APP_NAME.app，Bundle ID ${BUNDLE_ID:-未知}。"
if [[ "$EXEC_FOUND" != "true" ]]; then
  echo "  ⚠ 未找到可执行文件：Mach-O、符号、字符串和签名相关结论均不完整。"
fi
if [[ "$CRYPTID" != "0" && -n "$CRYPTID" ]]; then
  echo "  ⚠ cryptid=$CRYPTID：可执行文件仍加密，strings/符号分析结果不可信；需要已解密 IPA。"
fi
if [[ "$ATS_JSON" == *NSAllowsArbitraryLoads*true* ]]; then
  echo "  ⚠ ATS 配置包含 NSAllowsArbitraryLoads=true：允许任意明文 HTTP，需确认是否传输敏感数据。"
fi
if [[ -n "$URL_SCHEMES" ]]; then
  echo "  ⚠ 存在 URL Scheme：需审计 deeplink 参数校验与跳转逻辑。"
fi
if [[ -s "$TMP_DIR/suspicious-dylib.txt" ]]; then
  echo "  ⚠ 发现可疑注入/调试相关库文件，需确认是否为测试或越狱环境残留。"
fi
if [[ -s "$TMP_DIR/secret.txt" ]]; then
  echo "  ⚠ 发现高置信密钥形态：需人工确认是否为真实凭据。"
fi
if [[ -s "$TMP_DIR/env.txt" ]]; then
  echo "  ⚠ 发现测试/开发环境地址：确认生产包是否误带测试配置。"
fi
if [[ -z "$PRIVACY_MANIFESTS" ]]; then
  echo "  - 未发现 PrivacyInfo.xcprivacy：如使用被要求声明的 SDK，存在合规风险（需按 App Store 规则核对）。"
fi
echo "  说明：本脚本不做 Mach-O 反汇编和 Swift/ObjC 伪代码还原；cryptid=1 时字符串结论不可用。"
echo ""

if [[ "$EXEC_FOUND" != "true" ]]; then
  exit 1
fi
if [[ -n "$CRYPTID" && "$CRYPTID" != "0" ]]; then
  exit 1
fi
exit 0
