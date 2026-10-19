#!/usr/bin/env bash
#
# 10-resource-config.sh —— 通用静态分析：资源与配置审计
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   读取 APK 里的资源与配置，回答：
#     - res/xml/ 下有哪些配置（网络安全、备份规则、FileProvider 等）？
#     - 是否允许明文流量（cleartextTrafficPermitted=true）？
#     - 是否信任用户安装的 CA（src=user）？是否有 debug-overrides？
#     - 是否有备份/数据迁移规则？是否包含敏感目录？
#     - assets/ 和 res/raw/ 里是否内置了 URL、密钥、测试环境配置？
#
#   注意：
#     res/xml/*.xml 是编译后的二进制 XML，本脚本用 aapt2 转成可读树。
#     Manifest 里的 @ref 资源引用不一定能直接对应到文件名；
#     因此这里会 dump 全部 res/xml，而不是只按 Manifest 引用查找。
#
# 参数：
#   <APK>            必填
#                     格式：存在且可读的 APK 文件路径；ZIP 根目录必须包含 AndroidManifest.xml
#                     示例：./app.apk
#                     说明：AAB/APKS/IPA/JAR/普通 ZIP 会被识别并提示不适用，exit 2
#   --max-files N    可选
#                     格式：非负整数（^[0-9]+$）
#                     默认：30
#                     示例：--max-files 50
#                     说明：最多 dump 多少个 res/xml 文件
#   --max-lines N    可选
#                     格式：非负整数（^[0-9]+$）
#                     默认：120
#                     示例：--max-lines 200
#                     说明：每个 XML 最多显示多少行
#   --max-assets N   可选
#                     格式：非负整数（^[0-9]+$）
#                     默认：50
#                     示例：--max-assets 100
#                     说明：最多扫描多少个文本型 assets
#
# 依赖：
#   unzip、strings、grep、awk，以及 aapt2（Android SDK Build-Tools）。
#   缺少时明确提示安装方式并退出，不会静默跳过。
#
# 用法：
#   ./10-resource-config.sh <APK>
#   ./10-resource-config.sh <APK> --max-files 50 --max-lines 200
#   ./10-resource-config.sh --help
#
#   错误输入示例：
#     ./10-resource-config.sh app.ipa
#       → 识别为 iOS IPA，提示资源与配置流程不同，exit 2
#     ./10-resource-config.sh missing.apk
#       → 文件不存在，exit 2
#
# 输出：
#   Manifest 配置引用、res/xml 解析结果、assets/res/raw 线索、【结论】。
#   不修改输入；临时文件放在 mktemp 目录，退出时删除。
#
# 退出码：
#   0 = 分析完成，发现配置/资源层面的线索
#   1 = 分析完成，未发现可解析的配置或明显线索
#   2 = 参数/依赖/输入错误
#
set -euo pipefail
export LC_ALL=C

MAX_FILES=30
MAX_LINES=120
MAX_ASSETS=50
MAX_MATCHES=30
TARGET=""

usage() {
  cat <<'EOF'
用法:
  ./10-resource-config.sh <APK>
  ./10-resource-config.sh <APK> --max-files 50 --max-lines 200
  ./10-resource-config.sh --help

参数:
  <APK>             必填。格式: 存在且可读的 APK 文件路径。示例: ./app.apk
  --max-files N     可选。格式: 非负整数。默认: 30。示例: --max-files 50
  --max-lines N     可选。格式: 非负整数。默认: 120。示例: --max-lines 200
  --max-assets N    可选。格式: 非负整数。默认: 50。示例: --max-assets 100

输出:
  Manifest 配置引用、res/xml 解析结果、assets/res/raw 线索、【结论】。

退出码:
  0 = 发现配置/资源层面的线索
  1 = 未发现可解析的配置或明显线索
  2 = 参数/依赖/输入错误
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-files)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "[FAIL] --max-files 需要非负整数" >&2; exit 2; }
      MAX_FILES="$2"; shift 2 ;;
    --max-lines)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "[FAIL] --max-lines 需要非负整数" >&2; exit 2; }
      MAX_LINES="$2"; shift 2 ;;
    --max-assets)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "[FAIL] --max-assets 需要非负整数" >&2; exit 2; }
      MAX_ASSETS="$2"; shift 2 ;;
    -h|--help)
      usage
      exit 0 ;;
    -*)
      echo "[FAIL] 未知参数: $1" >&2; exit 2 ;;
    *)
      if [[ -n "$TARGET" ]]; then
        echo "[FAIL] 只能指定一个 APK" >&2; exit 2
      fi
      TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[FAIL] 缺少必填参数 <APK>。" >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] 文件不存在: $TARGET" >&2
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

need_tool unzip  "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"
need_tool strings "macOS: xcode-select --install；Linux: sudo apt install binutils"
need_tool grep   "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk    "macOS 通常自带；Linux: sudo apt install gawk / mawk"

find_android_tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi

  local roots=()
  [[ -n "${ANDROID_HOME:-}" ]] && roots+=("$ANDROID_HOME")
  [[ -n "${ANDROID_SDK_ROOT:-}" ]] && roots+=("$ANDROID_SDK_ROOT")
  roots+=("$HOME/Library/Android/sdk" "$HOME/Android/Sdk")

  local root ver candidate
  for root in "${roots[@]}"; do
    [[ -d "$root/build-tools" ]] || continue
    while IFS= read -r ver; do
      candidate="$root/build-tools/$ver/$name"
      if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return 0
      fi
    done < <(ls -1 "$root/build-tools" 2>/dev/null \
      | sort -t. -k1,1nr -k2,2nr -k3,3nr)
  done
  return 1
}

AAPT2="$(find_android_tool aapt2 || true)"
if [[ -z "$AAPT2" ]]; then
  echo "[FAIL] 找不到 aapt2。" >&2
  echo "       res/xml/*.xml 是二进制 XML，需要 aapt2 解析。" >&2
  echo "       安装方式：" >&2
  echo "         1) Android Studio → SDK Manager → SDK Tools → Android SDK Build-Tools" >&2
  echo "         2) 或 sdkmanager \"build-tools;34.0.0\"" >&2
  echo "         3) 安装后设置 ANDROID_HOME / ANDROID_SDK_ROOT，或把 build-tools/<版本> 加入 PATH" >&2
  exit 2
fi

# ---------- 1. 预检 ----------
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
if ! grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  echo "============================================================"
  echo "静态分析 10：资源与配置审计"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  if [[ -n "$ENTRIES" ]]; then
    if grep -qx 'BundleConfig.pb' <<<"$ENTRIES" || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
      echo "这是 AAB，不是 APK。请先用 bundletool 生成 APK。"
    elif grep -qx 'toc.pb' <<<"$ENTRIES"; then
      echo "这是 APKS，请先解出 base.apk / split APK。"
    elif grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
      echo "这是 iOS IPA，资源与配置审计流程不同。"
    else
      echo "这不是 APK：ZIP 根目录没有 AndroidManifest.xml。"
    fi
  else
    echo "输入不是有效的 ZIP/APK。"
  fi
  exit 2
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/resource-config.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
XML_DUMP_DIR="$TMP_DIR/xml-dumps"
ASSET_STRINGS="$TMP_DIR/asset-strings.txt"
RAW_STRINGS="$TMP_DIR/raw-strings.txt"
mkdir -p "$XML_DUMP_DIR"
: > "$ASSET_STRINGS"
: > "$RAW_STRINGS"

XML_ENTRIES="$(grep -E '^res/xml/.+\.xml$' <<<"$ENTRIES" | sort | awk -v max="$MAX_FILES" 'NR <= max' || true)"
XML_TOTAL="$(grep -cE '^res/xml/.+\.xml$' <<<"$ENTRIES" || true)"
ASSET_ENTRIES="$(grep -E '^assets/.+\.(json|xml|txt|ya?ml|properties|env|conf|ini|js|html?|css|csv|plist|strings|sql)$' <<<"$ENTRIES" | sort | awk -v max="$MAX_ASSETS" 'NR <= max' || true)"
ASSET_TOTAL="$(grep -cE '^assets/.+\.(json|xml|txt|ya?ml|properties|env|conf|ini|js|html?|css|csv|plist|strings|sql)$' <<<"$ENTRIES" || true)"
RAW_ENTRIES="$(grep -E '^res/raw/.+' <<<"$ENTRIES" | sort | awk 'NR <= 30' || true)"
RAW_TOTAL="$(grep -cE '^res/raw/.+' <<<"$ENTRIES" || true)"

# Manifest 里的配置引用（只做提示，具体内容看 res/xml dump）
MANIFEST_DUMP="$TMP_DIR/manifest.txt"
echo "[loading] 正在解析 AndroidManifest.xml（aapt2 dump）..."
"$AAPT2" dump xmltree --file AndroidManifest.xml "$TARGET" > "$MANIFEST_DUMP" 2>/dev/null || true
sed -E 's#A: http://schemas\.android\.com/apk/res/android:#A: android:#g' \
  "$MANIFEST_DUMP" > "$MANIFEST_DUMP.norm" 2>/dev/null || true
echo "[done] Manifest 解析完成"

# ---------- 2. 输出头 ----------
echo "============================================================"
echo "静态分析 10：资源与配置审计"
echo "目标：$TARGET"
echo "aapt2：$AAPT2"
echo "res/xml/*.xml：$XML_TOTAL 个（本次 dump 前 $MAX_FILES 个）"
echo "文本型 assets：$ASSET_TOTAL 个（本次扫描前 $MAX_ASSETS 个）"
echo "res/raw：$RAW_TOTAL 个（本次扫描前 30 个）"
echo "============================================================"

echo "Manifest 配置引用："
if grep -qE ':(networkSecurityConfig|fullBackupContent|dataExtractionRules|usesCleartextTraffic)\(' "$MANIFEST_DUMP.norm"; then
  grep -E ':(networkSecurityConfig|fullBackupContent|dataExtractionRules|usesCleartextTraffic)\(' "$MANIFEST_DUMP.norm" \
    | sed -E 's/^[[:space:]]*//' | sed 's/^/  /'
else
  echo "  (未发现 networkSecurityConfig / fullBackupContent / dataExtractionRules / usesCleartextTraffic)"
fi

# ---------- 3. dump res/xml ----------
echo "------------------------------------------------------------"
echo "res/xml 配置内容："
if [[ -z "$XML_ENTRIES" ]]; then
  echo "  (无 res/xml/*.xml)"
else
  echo "[loading] 正在解析 $XML_TOTAL 个 res/xml（本次 dump 前 $MAX_FILES 个）..."
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    safe_name="$(printf '%s' "$entry" | tr '/' '_')"
    dump="$XML_DUMP_DIR/$safe_name.txt"

    echo "--- $entry"
    if "$AAPT2" dump xmltree --file "$entry" "$TARGET" > "$dump" 2>/dev/null && [[ -s "$dump" ]]; then
      awk -v max="$MAX_LINES" 'NR <= max' "$dump" | sed 's/^/  /'
      if [[ "$(wc -l < "$dump" | tr -d ' ')" -gt "$MAX_LINES" ]]; then
        echo "  ...（已截断，完整内容在临时目录，脚本退出后删除）"
      fi
    else
      echo "  (aapt2 无法解析，按普通文本扫描)"
      unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 4 \
        | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  /' || true
    fi

    # 针对网络安全配置/备份规则的关键行
    if grep -qiE 'network-security-config|cleartextTrafficPermitted|trust-anchors|debug-overrides' "$dump" 2>/dev/null; then
      echo "  [网络安全配置关键行]"
      grep -inE 'network-security-config|cleartextTrafficPermitted|trust-anchors|certificates|debug-overrides|domain-config|base-config|src' "$dump" \
        | awk -v max="$MAX_MATCHES" 'NR <= max' | sed 's/^/    /' || true
    fi
    if grep -qiE 'full-backup-content|data-extraction-rules|<include|include\(|<exclude|exclude\(' "$dump" 2>/dev/null; then
      echo "  [备份/数据迁移规则关键行]"
      grep -inE 'full-backup-content|data-extraction-rules|include|exclude|domain|path' "$dump" \
        | awk -v max="$MAX_MATCHES" 'NR <= max' | sed 's/^/    /' || true
    fi
  done <<<"$XML_ENTRIES"
  echo "[done] res/xml 解析完成"
fi

# ---------- 4. 收集 assets / res/raw 字符串 ----------
if [[ -n "$ASSET_ENTRIES" || -n "$RAW_ENTRIES" ]]; then
  echo "[loading] 正在扫描 assets（$ASSET_TOTAL 个）和 res/raw（$RAW_TOTAL 个）..."
fi

if [[ -n "$ASSET_ENTRIES" ]]; then
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    printf '### %s\n' "$entry" >> "$ASSET_STRINGS"
    unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 4 >> "$ASSET_STRINGS" || true
  done <<<"$ASSET_ENTRIES"
fi

if [[ -n "$RAW_ENTRIES" ]]; then
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    printf '### %s\n' "$entry" >> "$RAW_STRINGS"
    unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 4 >> "$RAW_STRINGS" || true
  done <<<"$RAW_ENTRIES"
fi

if [[ -n "$ASSET_ENTRIES" || -n "$RAW_ENTRIES" ]]; then
  echo "[done] assets/res/raw 扫描完成"
fi

# 输出带条目上下文的匹配
report_strings() {
  local title="$1"
  local file="$2"
  local regex="$3"

  local raw count
  raw="$(awk -v re="$regex" '
    /^### / { entry = substr($0, 5); next }
    tolower($0) ~ tolower(re) { print "[" entry "] " $0 }
  ' "$file" 2>/dev/null || true)"
  count="$(printf '%s\n' "$raw" | grep -c . || true)"

  echo "------------------------------------------------------------"
  echo "$title（$count 行，最多显示 $MAX_MATCHES 行）："
  if [[ "$count" -gt 0 ]]; then
    printf '%s\n' "$raw" | awk -v max="$MAX_MATCHES" 'NR <= max' | sed 's/^/  /'
    if [[ "$count" -gt "$MAX_MATCHES" ]]; then
      echo "  ...（其余 $((count - MAX_MATCHES)) 行已省略）"
    fi
  else
    echo "  (无)"
  fi
}

echo "------------------------------------------------------------"
echo "assets / res/raw 配置扫描："
report_strings "URL" "$ASSET_STRINGS" 'https?://[a-z0-9._~:/?#@!$&*+,;=%-]+'
report_strings "明文 HTTP" "$ASSET_STRINGS" 'http://[a-z0-9._~:/?#@!$&*+,;=%-]+'
report_strings "敏感字段" "$ASSET_STRINGS" 'api[_-]?key|apikey|secret|token|password|passwd|bearer|authorization|private[_-]?key|client[_-]?secret'
report_strings "环境线索" "$ASSET_STRINGS" 'dev|develop|development|test|testing|uat|staging|preprod|sandbox'

if [[ -n "$RAW_ENTRIES" ]]; then
  report_strings "res/raw URL" "$RAW_STRINGS" 'https?://[a-z0-9._~:/?#@!$&*+,;=%-]+'
  report_strings "res/raw 敏感字段" "$RAW_STRINGS" 'api[_-]?key|apikey|secret|token|password|passwd|bearer|private[_-]?key'
fi

# ---------- 5. 汇总结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

RISK=false
FOUND=false

if grep -RqiE 'cleartextTrafficPermitted.*(true|0xffffffff)' "$XML_DUMP_DIR" 2>/dev/null; then
  echo "  ⚠ 网络安全配置允许明文流量（cleartextTrafficPermitted=true）。"
  RISK=true; FOUND=true
fi
if grep -RqiE 'trust-anchors' "$XML_DUMP_DIR" 2>/dev/null && \
   grep -RqiE 'src.*(user|0x3)' "$XML_DUMP_DIR" 2>/dev/null; then
  echo "  ⚠ 网络安全配置可能信任用户安装的 CA（src=user）；需确认是否只在测试环境使用。"
  RISK=true; FOUND=true
fi
if grep -RqiE 'debug-overrides' "$XML_DUMP_DIR" 2>/dev/null; then
  echo "  ⚠ 网络安全配置包含 debug-overrides；发布包应确认其作用范围。"
  RISK=true; FOUND=true
fi
if grep -RqiE 'full-backup-content|data-extraction-rules|include|exclude' "$XML_DUMP_DIR" 2>/dev/null; then
  echo "  - 存在备份/数据迁移规则：需确认是否包含敏感目录或数据库。"
  FOUND=true
fi
if [[ -n "$ASSET_ENTRIES" ]]; then
  if grep -qiE 'https?://' "$ASSET_STRINGS" 2>/dev/null; then
    echo "  - assets 中发现 URL：确认是业务地址、测试地址还是第三方文档/许可证地址。"
    FOUND=true
  fi
  if grep -qiE 'api[_-]?key|apikey|secret|password|private[_-]?key' "$ASSET_STRINGS" 2>/dev/null; then
    echo "  ⚠ assets 中出现敏感字段名：需确认是否内置真实凭据。"
    RISK=true; FOUND=true
  fi
  if grep -qiE 'http://' "$ASSET_STRINGS" 2>/dev/null; then
    echo "  ⚠ assets 中出现明文 http URL：确认是否为必须，以及是否会被拦截。"
    RISK=true; FOUND=true
  fi
  if grep -qiE 'dev|test|uat|staging|preprod|sandbox' "$ASSET_STRINGS" 2>/dev/null; then
    echo "  - assets 中出现测试/开发环境线索：确认生产包是否误带测试配置。"
    FOUND=true
  fi
fi

if [[ "$RISK" == true ]]; then
  echo "  以上为配置层面的静态信号，需结合运行环境和业务逻辑确认。"
  exit 0
fi

if [[ "$FOUND" == true ]]; then
  echo "  未发现高危配置，但存在需要人工确认的配置项。"
  exit 0
fi

echo "  未发现可解析的配置或明显线索。"
echo "  这不代表没有配置：可能没有 res/xml，或配置在 assets 之外的其他位置。"
exit 1
