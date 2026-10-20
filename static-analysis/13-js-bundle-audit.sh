#!/usr/bin/env bash
#
# 13-js-bundle-audit.sh —— 通用静态分析：JS / React Native / Hermes / Web 资源审计
#
# 用途：
#   1. 回答 APK/ZIP 内是否存在 JS 层代码（React Native bundle、Hermes 字节码、
#      WebView/H5 assets、Cordova/www 资源等）。
#   2. 从 JS/HTML/CSS/JSON/bundle 中提取：URL、密钥与令牌线索、调试/测试环境
#      线索、sourcemap、动态执行与 WebView 桥接线索、自定义关键字。
#   3. 不覆盖：Hermes 字节码反编译还原、JS 混淆还原、动态执行验证。
#
# 参数：
#   <APK|ZIP>      必填
#                  格式：存在且可读的 APK 或 ZIP 文件路径
#                  示例：./app.apk
#                  说明：AAB/APKS/IPA 会被识别并提示不适用，exit 2
#
#   --max N        可选
#                  格式：非负整数（^[0-9]+$）
#                  默认：30
#                  示例：--max 50
#                  说明：每个分类最多显示 N 行
#
#   --keywords STR 可选
#                  格式：逗号分隔的非空字符串
#                  默认：无
#                  示例：--keywords "internal,corp.example.com"
#                  说明：按字面量追加检索这些关键字
#
# 依赖：
#   unzip、strings、grep、awk、sort、wc
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./13-js-bundle-audit.sh <APK>
#   ./13-js-bundle-audit.sh <APK> --max 50
#   ./13-js-bundle-audit.sh <APK> --keywords "internal,corp.example.com"
#   ./13-js-bundle-audit.sh --help
#
# 输出：
#   输入类型、JS 资源清单、框架线索、各分类命中、【结论】。
#   临时文件放在 mktemp 目录，脚本退出时删除。
#
# 退出码：
#   0 = 扫描完成且发现至少一类线索
#   1 = 扫描完成但未发现线索，或未找到 JS 资源
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

MAX=30
KEYWORDS=""
TARGET=""

usage() {
  cat <<'EOF'
用法: ./13-js-bundle-audit.sh <APK|ZIP> [--max N] [--keywords "k1,k2"]

参数:
  <APK|ZIP>        必填。格式: APK/ZIP 文件路径。
  --max N          可选。格式: 非负整数。默认: 30。示例: --max 50
  --keywords STR   可选。格式: 逗号分隔字符串。示例: --keywords "internal,corp.example.com"
  -h, --help       显示本帮助。

退出码:
  0 = 扫描完成且发现线索
  1 = 未发现线索，或未找到 JS 资源
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
    --keywords)
      if [[ -z "${2:-}" ]]; then
        echo "[FAIL] --keywords 需要一个非空字符串。" >&2
        usage >&2
        exit 2
      fi
      KEYWORDS="$2"
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
  echo "[FAIL] 缺少必填参数 <APK|ZIP>。" >&2
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/js-audit.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

report_hits() {
  local label="$1" file="$2" total
  total="$(grep -c . "$file" 2>/dev/null || true)"
  echo "$label（$total 处）："
  if [[ "$total" -eq 0 ]]; then
    echo "  (无)"
  else
    awk -v max="$MAX" 'NR <= max { line = $0; if (length(line) > 300) line = substr(line, 1, 300) "..."; print "  - " line }' "$file"
    if [[ "$total" -gt "$MAX" ]]; then
      echo "  ...（其余 $((total - MAX)) 处已省略）"
    fi
  fi
}

echo "[loading] 正在读取 ZIP 条目..."
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
ENTRY_COUNT="$(printf '%s\n' "$ENTRIES" | grep -c . || true)"
echo "[done] 条目读取完成：$ENTRY_COUNT 个"

if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  echo "[FAIL] 输入不是有效的 ZIP/APK，或文件已损坏。" >&2
  exit 2
fi

INPUT_TYPE="ZIP"
if grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  INPUT_TYPE="APK"
elif grep -qx 'BundleConfig.pb' <<<"$ENTRIES" || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
  echo "[FAIL] 输入是 AAB，不是可直接分析的 APK/ZIP。" >&2
  echo "       请先用 bundletool 生成 APK，再运行本脚本。" >&2
  exit 2
elif grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
  echo "[FAIL] 输入是 iOS IPA，请使用 iOS 分析脚本。" >&2
  exit 2
fi

echo "============================================================"
echo "静态分析 13：JS / React Native / Hermes / Web 资源审计"
echo "目标：$TARGET"
echo "输入类型：$INPUT_TYPE"
echo "条目数：$ENTRY_COUNT"
echo "参数：max=$MAX keywords=${KEYWORDS:-无}"
echo "============================================================"

# ---------- 框架线索 ----------
echo "框架/运行时线索："
FRAME_HITS=0
check_entry() {
  local label="$1" pattern="$2"
  if grep -qE -- "$pattern" <<<"$ENTRIES"; then
    echo "  - $label"
    FRAME_HITS=$((FRAME_HITS + 1))
  fi
}
check_entry "React Native (libreactnativejni)" 'libreactnativejni\.so|libreactnative\.so'
check_entry "Hermes (libhermes)"             'libhermes(_executor)?\.so'
check_entry "React Native bundle"            '(^|/)index\.android\.bundle$|\.jsbundle$'
check_entry "Hermes 字节码 (.hbc)"            '\.hbc$|\.hermes$'
check_entry "Cordova / Web 资源"              '(^|/)assets/www/|cordova\.js'
check_entry "Unity"                          'libunity\.so|assets/bin/Data/'
check_entry "Flutter（非 JS，仅供参考）"        'libflutter\.so|libapp\.so'
if [[ "$FRAME_HITS" -eq 0 ]]; then
  echo "  (未识别到明确的 JS 运行时特征)"
fi

# ---------- 收集 JS 类条目 ----------
JS_LIST="$(printf '%s\n' "$ENTRIES" \
  | grep -Ei '(^|/)(index\.android\.bundle|main\.jsbundle|[^/]+\.(js|jsx|ts|tsx|mjs|cjs|bundle|jsbundle|hbc|hermes|html?|css|map))$' \
  || true)"

JS_COUNT="$(printf '%s\n' "$JS_LIST" | grep -c . || true)"
echo "------------------------------------------------------------"
echo "JS/Web 资源：$JS_COUNT 个"
if [[ "$JS_COUNT" -eq 0 ]]; then
  echo "  (未找到 JS/HTML/CSS/bundle 类条目)"
  echo "------------------------------------------------------------"
  echo "【结论】"
  echo "  - 未找到可审计的 JS/Web 资源，可能是原生、Flutter 或资源被加密/改名。"
  echo "  说明：本脚本只覆盖明文 JS/H5/HTML/CSS 及其字符串；不反编译 Hermes 字节码。"
  exit 1
fi
printf '%s\n' "$JS_LIST" | awk -v max="$MAX" 'NR <= max' | sed 's/^/  - /'
if [[ "$JS_COUNT" -gt "$MAX" ]]; then
  echo "  ...（其余 $((JS_COUNT - MAX)) 个已省略）"
fi

# ---------- 提取待扫描文本 ----------
: > "$TMP_DIR/map.txt"
i=0
echo "[loading] 正在提取 $JS_COUNT 个 JS/Web 条目（大文件可能需要一段时间）..."
while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  raw="$TMP_DIR/f$i.raw"
  txt="$TMP_DIR/f$i.txt"
  if ! unzip -p "$TARGET" "$entry" > "$raw" 2>/dev/null; then
    i=$((i + 1))
    continue
  fi
  case "$entry" in
    *.hbc|*.hermes)
      strings -a -n 6 "$raw" > "$txt" 2>/dev/null || : > "$txt"
      ;;
    *)
      cp "$raw" "$txt"
      ;;
  esac
  printf '%s|%s\n' "$i" "$entry" >> "$TMP_DIR/map.txt"
  i=$((i + 1))
done <<< "$JS_LIST"
echo "[done] 提取完成：$i 个条目"

scan_category() {
  local out="$1" pattern="$2"
  : > "$out"
  while IFS='|' read -r idx entry; do
    [[ -f "$TMP_DIR/f$idx.txt" ]] || continue
    grep -naE -- "$pattern" "$TMP_DIR/f$idx.txt" 2>/dev/null \
      | awk -v e="$entry" '{print "[" e "] " $0}' >> "$out" || true
  done < "$TMP_DIR/map.txt"
}

echo "[loading] 正在按类别扫描 JS/Web 内容..."
scan_category "$TMP_DIR/url.txt"      'https?://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+'
scan_category "$TMP_DIR/secret.txt"   'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
scan_category "$TMP_DIR/weak.txt"     '(api[_-]?key|app[_-]?secret|access[_-]?token|client[_-]?secret|password|passwd)[[:space:]]*[:=]'
scan_category "$TMP_DIR/debug.txt"    '__DEV__|sourceMappingURL=|localhost|127\.0\.0\.1|debug[[:space:]]*[:=][[:space:]]*true|https?://[^ ]*(dev|test|staging|sandbox|uat)\.'
scan_category "$TMP_DIR/dynamic.txt"  'eval[[:space:]]*\(|new Function[[:space:]]*\(|addJavascriptInterface|javascriptInterface|WebView'
echo "[done] 分类扫描完成"

if [[ -n "$KEYWORDS" ]]; then
  : > "$TMP_DIR/custom.txt"
  IFS=',' read -r -a KW_ARR <<< "$KEYWORDS"
  for kw in "${KW_ARR[@]}"; do
    kw="$(printf '%s' "$kw" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -n "$kw" ]] || continue
    while IFS='|' read -r idx entry; do
      [[ -f "$TMP_DIR/f$idx.txt" ]] || continue
      grep -naF -- "$kw" "$TMP_DIR/f$idx.txt" 2>/dev/null \
        | awk -v e="$entry" -v k="$kw" '{print "[" e "] (" k ") " $0}' >> "$TMP_DIR/custom.txt" || true
    done < "$TMP_DIR/map.txt"
  done
fi

echo "------------------------------------------------------------"
report_hits "URL" "$TMP_DIR/url.txt"
echo "------------------------------------------------------------"
report_hits "高置信密钥/令牌模式" "$TMP_DIR/secret.txt"
echo "------------------------------------------------------------"
report_hits "弱信号敏感字段赋值" "$TMP_DIR/weak.txt"
echo "------------------------------------------------------------"
report_hits "调试/测试环境线索" "$TMP_DIR/debug.txt"
echo "------------------------------------------------------------"
report_hits "动态执行/WebView 桥接" "$TMP_DIR/dynamic.txt"
if [[ -n "$KEYWORDS" ]]; then
  echo "------------------------------------------------------------"
  report_hits "自定义关键字" "$TMP_DIR/custom.txt"
fi

TOTAL_HITS=0
for f in url secret weak debug dynamic; do
  c="$(grep -c . "$TMP_DIR/$f.txt" 2>/dev/null || true)"
  TOTAL_HITS=$((TOTAL_HITS + c))
done
if [[ -n "$KEYWORDS" ]]; then
  c="$(grep -c . "$TMP_DIR/custom.txt" 2>/dev/null || true)"
  TOTAL_HITS=$((TOTAL_HITS + c))
fi

echo "------------------------------------------------------------"
echo "【结论】"
echo "  - 共扫描 $JS_COUNT 个 JS/Web 条目，命中线索 $TOTAL_HITS 处。"
if [[ -s "$TMP_DIR/secret.txt" ]]; then
  echo "  ⚠ 发现高置信密钥/令牌形态：必须人工核对上下文，strings/正则命中不等于真实凭据。"
fi
if [[ -s "$TMP_DIR/debug.txt" ]]; then
  echo "  ⚠ 发现调试/测试环境线索：确认生产包是否误带 dev/test 配置。"
fi
if [[ -s "$TMP_DIR/dynamic.txt" ]]; then
  echo "  ⚠ 发现动态执行/WebView 桥接线索：需结合调用方与输入来源判断风险。"
fi
if grep -qE '\.hbc$|\.hermes$' <<<"$JS_LIST"; then
  echo "  - 存在 Hermes 字节码：本脚本只做 strings 层提取，未做字节码反编译。"
fi
echo "  说明：结果来自文本/字符串启发式扫描，不证明漏洞；加密、混淆或动态加载的 JS 不在覆盖范围内。"
echo ""

if [[ "$TOTAL_HITS" -gt 0 ]]; then
  exit 0
fi
exit 1
