#!/usr/bin/env bash
#
# 18-secret-entropy.sh —— 通用静态分析：高熵密钥 / 硬编码凭据扫描
#
# 用途：
#   1. 对 APK/ZIP/任意文件提取字符串，先匹配已知密钥格式（AWS、Google、
#      GitHub、Slack、Stripe、私钥、JWT 等），再用香农熵筛选高随机性 token。
#   2. 输出高置信模式命中、高熵候选及其熵值/长度，作为人工核对的线索。
#   3. 不覆盖：凭据有效性验证、上下文语义判断、加密内容内部。
#      高熵结果是启发式，误报率较高，不能直接判定为真实密钥。
#
# 参数：
#   <输入>          必填
#                   格式：存在且可读的 APK/ZIP 或任意文件
#                   示例：./app.apk 或 ./config.bin
#                   说明：非 ZIP 文件会直接对文件做 strings 扫描
#
#   --max N         可选
#                   格式：非负整数（^[0-9]+$）
#                   默认：30
#                   示例：--max 100
#                   说明：高熵候选最多显示 N 条
#
#   --min-length N  可选
#                   格式：正整数（^[1-9][0-9]*$）
#                   默认：16
#                   示例：--min-length 20
#                   说明：候选 token 的最小长度
#
#   --threshold X   可选
#                   格式：0 到 8 之间的十进制数（如 3.5）
#                   默认：3.5
#                   示例：--threshold 4.0
#                   说明：香农熵阈值（bits/char），越高越严格
#
#   --all           可选
#                   格式：布尔开关，不带值
#                   默认：关闭
#                   说明：APK/ZIP 输入时扫描全部条目（默认只扫 DEX/arsc/.so/文本 assets）
#
# 依赖：
#   unzip、strings、grep、awk、sort、uniq
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./18-secret-entropy.sh <APK>
#   ./18-secret-entropy.sh <APK> --threshold 4.0 --min-length 20 --max 100
#   ./18-secret-entropy.sh <文件> --all
#   ./18-secret-entropy.sh --help
#
# 输出：
#   扫描规模、高置信模式、高熵候选（熵值/长度/token）、【结论】。
#   临时文件放在 mktemp 目录，脚本退出时删除。
#
# 退出码：
#   0 = 发现高置信模式或高熵候选
#   1 = 未发现候选
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

MAX=30
MIN_LEN=16
THRESHOLD=3.5
SCAN_ALL=false
TARGET=""

usage() {
  cat <<'EOF'
用法: ./18-secret-entropy.sh <输入> [--max N] [--min-length N] [--threshold X] [--all]

参数:
  <输入>           必填。格式: APK/ZIP 或任意文件路径。
  --max N          可选。格式: 非负整数。默认: 30
  --min-length N   可选。格式: 正整数。默认: 16
  --threshold X    可选。格式: 0-8 的十进制数。默认: 3.5
  --all            可选。布尔开关。扫描 ZIP 全部条目。
  -h, --help       显示本帮助。

退出码:
  0 = 发现高置信模式或高熵候选
  1 = 未发现候选
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
    --min-length)
      if [[ -z "${2:-}" || ! "${2:-}" =~ ^[1-9][0-9]*$ ]]; then
        echo "[FAIL] --min-length 的值 \"${2:-}\" 不合法：要求正整数。" >&2
        usage >&2
        exit 2
      fi
      MIN_LEN="$2"
      shift 2
      ;;
    --threshold)
      if [[ -z "${2:-}" || ! "${2:-}" =~ ^[0-8](\.[0-9]+)?$ ]]; then
        echo "[FAIL] --threshold 的值 \"${2:-}\" 不合法：要求 0 到 8 之间的十进制数。" >&2
        usage >&2
        exit 2
      fi
      THRESHOLD="$2"
      shift 2
      ;;
    --all)
      SCAN_ALL=true
      shift
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
  echo "[FAIL] 缺少必填参数 <输入>。" >&2
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

need_tool strings "macOS: xcode-select --install；Linux: sudo apt install binutils"
need_tool grep    "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk     "macOS 通常自带；Linux: sudo apt install gawk / mawk"
need_tool sort    "macOS 通常自带；Linux: sudo apt install coreutils"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/secret-entropy.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

report_hits() {
  local label="$1" file="$2"
  echo "$label（$(grep -c . "$file" 2>/dev/null || true) 条）："
  if [[ ! -s "$file" ]]; then
    echo "  (无)"
  else
    awk -v max="$MAX" 'NR <= max { line = $0; if (length(line) > 220) line = substr(line, 1, 220) "..."; print "  - " line }' "$file"
    local total
    total="$(grep -c . "$file" 2>/dev/null || true)"
    if [[ "$total" -gt "$MAX" ]]; then
      echo "  ...（其余 $((total - MAX)) 条已省略）"
    fi
  fi
}

echo "============================================================"
echo "静态分析 18：高熵密钥 / 硬编码凭据扫描"
echo "目标：$TARGET"
echo "参数：max=$MAX min_length=$MIN_LEN threshold=$THRESHOLD all=$SCAN_ALL"
echo "============================================================"

: > "$TMP_DIR/dump.txt"
ZIP_OK=false
if command -v unzip >/dev/null 2>&1 && unzip -Z1 "$TARGET" >/dev/null 2>&1; then
  ZIP_OK=true
fi

if [[ "$ZIP_OK" == true ]]; then
  ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
  ENTRY_COUNT="$(printf '%s\n' "$ENTRIES" | grep -c . || true)"
  if [[ "$SCAN_ALL" == true ]]; then
    SCAN_LIST="$ENTRIES"
  else
    SCAN_LIST="$(printf '%s\n' "$ENTRIES" \
      | grep -E '^(classes([0-9]+)?\.dex|resources\.arsc|lib/.+\.so|res/raw/.+|assets/.+\.(json|xml|txt|ya?ml|properties|env|conf|ini|js|jsx|ts|tsx|mjs|cjs|bundle|jsbundle|hbc|hermes|html?|css|csv|plist|strings|sql|pem|crt|key|cer|p12|mobileconfig)|index\.android\.bundle|[^/]+\.(jsbundle|bundle|hbc))$' \
      || true)"
  fi
  SCAN_COUNT="$(printf '%s\n' "$SCAN_LIST" | grep -c . || true)"
  echo "容器条目：$ENTRY_COUNT 个；待扫描条目：$SCAN_COUNT 个"
  echo "[loading] 正在提取字符串（大包可能需要几十秒到数分钟）..."
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 6 >> "$TMP_DIR/dump.txt" || true
  done <<< "$SCAN_LIST"
else
  echo "输入不是 ZIP：按普通文件处理。"
  echo "[loading] 正在提取字符串..."
  strings -a -n 6 "$TARGET" > "$TMP_DIR/dump.txt" 2>/dev/null || true
fi
DUMP_LINES="$(grep -c . "$TMP_DIR/dump.txt" 2>/dev/null || true)"
echo "[done] 字符串提取完成：$DUMP_LINES 行"

# ---------- 1. 已知密钥格式 ----------
echo "[loading] 正在匹配已知密钥格式..."
grep -aoE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
  "$TMP_DIR/dump.txt" 2>/dev/null | sort -u > "$TMP_DIR/strong.txt" || true
echo "[done] 已知格式匹配完成"

# ---------- 2. 高熵候选 ----------
echo "[loading] 正在生成候选并计算熵值（候选较多时可能需要一段时间）..."
grep -aoE '[A-Za-z0-9+/=_.-]{'"$MIN_LEN"',}' "$TMP_DIR/dump.txt" 2>/dev/null \
  | grep -E '[A-Za-z]' \
  | grep -E '[0-9]' \
  | grep -viE '^(https?|www\.|android|kotlin|flutter|java|com\.|org\.|net\.|io\.|www\.)|\.(png|jpe?g|gif|webp|so|dex|arsc|json|xml|html?|css|js|txt|md)$|^(android|alipay|tencent|google|facebook|amazon|cloudflare|schemas|apache|w3\.org)' \
  | grep -viE 'abcdefghijklmnopqrstuvwxyz|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789|qwertyuiop|asdfghjkl|zxcvbnm' \
  | sort -u > "$TMP_DIR/candidates.txt" || true

CAND_COUNT="$(grep -c . "$TMP_DIR/candidates.txt" 2>/dev/null || true)"
awk -v min="$MIN_LEN" -v thr="$THRESHOLD" '
  {
    s = $0
    n = length(s)
    if (n < min || n > 200) next
    delete c
    for (i = 1; i <= n; i++) c[substr(s, i, 1)]++
    h = 0
    for (k in c) { p = c[k] / n; h -= p * (log(p) / log(2)) }
    if (h >= thr) printf "%.2f|%d|%s\n", h, n, s
  }
' "$TMP_DIR/candidates.txt" | sort -t'|' -k1,1nr > "$TMP_DIR/entropy.txt" || true
echo "[done] 熵值计算完成：候选 $CAND_COUNT 个"

HIGH_ENTROPY_COUNT="$(grep -c . "$TMP_DIR/entropy.txt" 2>/dev/null || true)"

echo "------------------------------------------------------------"
report_hits "高置信密钥格式（精确模式）" "$TMP_DIR/strong.txt"
echo "------------------------------------------------------------"
echo "高熵候选（阈值 $THRESHOLD，长度 >= $MIN_LEN）：$HIGH_ENTROPY_COUNT 个"
if [[ "$HIGH_ENTROPY_COUNT" -eq 0 ]]; then
  echo "  (无)"
else
  awk -v max="$MAX" 'NR <= max' "$TMP_DIR/entropy.txt" \
    | awk -F'|' '{printf "  - entropy=%s len=%s token=%s\n", $1, $2, $3}'
  if [[ "$HIGH_ENTROPY_COUNT" -gt "$MAX" ]]; then
    echo "  ...（其余 $((HIGH_ENTROPY_COUNT - MAX)) 个已省略）"
  fi
fi

STRONG_COUNT="$(grep -c . "$TMP_DIR/strong.txt" 2>/dev/null || true)"
TOTAL=$((STRONG_COUNT + HIGH_ENTROPY_COUNT))

echo "------------------------------------------------------------"
echo "【结论】"
if [[ "$STRONG_COUNT" -gt 0 ]]; then
  echo "  ⚠ 命中 $STRONG_COUNT 条已知密钥格式：优先人工核对，可能是真实凭据，也可能是测试样例/文档字符串。"
fi
if [[ "$HIGH_ENTROPY_COUNT" -gt 0 ]]; then
  echo "  - 发现 $HIGH_ENTROPY_COUNT 个高熵候选：高熵只说明字符串随机性强，不等于密钥。"
  echo "    常见误报：哈希值、资源 ID、UUID、压缩/加密数据、Base64 图片片段。"
fi
if [[ "$TOTAL" -eq 0 ]]; then
  echo "  - 未发现已知密钥格式或高熵候选（阈值 $THRESHOLD）。"
  echo "  - 可能原因：没有明文凭据、内容被加密/压缩，或阈值设置过高。"
  echo "  说明：本脚本不做凭据有效性验证，不覆盖加密内容内部；结果需人工结合上下文确认。"
  exit 1
fi
echo "  说明：请结合命中所在的文件、调用链和配置判断真实性；本脚本不联网、不验证凭据。"
exit 0
