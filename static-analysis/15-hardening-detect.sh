#!/usr/bin/env bash
#
# 15-hardening-detect.sh —— 通用静态分析：加固 / 壳 / 反调试特征识别
#
# 用途：
#   1. 判断 APK 是否带有常见加固壳（360、腾讯、百度、梆梆、阿里、网易等）
#      以及反调试、Hook 检测等对抗特征。
#   2. 检查 classes*.dex 的魔数与熵值，提示 DEX 是否可能被加密/压缩。
#   3. 不覆盖：脱壳、内存 dump、真实防护强度验证。
#      本脚本只做识别，不能把加固包还原成可分析的 DEX。
#
# 参数：
#   <APK>           必填
#                   格式：存在且可读的 APK 文件路径
#                   示例：./app.apk
#                   说明：非 APK 输入会提示不适用，exit 2
#
#   --max N         可选
#                   格式：非负整数（^[0-9]+$）
#                   默认：20
#                   示例：--max 50
#                   说明：每个分类最多显示 N 行
#
#   --sample-mb N   可选
#                   格式：正整数（^[1-9][0-9]*$）
#                   默认：2
#                   示例：--sample-mb 4
#                   说明：计算 DEX 熵值时每个 DEX 最多采样的 MB 数
#
# 依赖：
#   unzip、strings、grep、awk、od、dd、sort
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./15-hardening-detect.sh <APK>
#   ./15-hardening-detect.sh <APK> --max 50
#   ./15-hardening-detect.sh <APK> --sample-mb 4
#   ./15-hardening-detect.sh --help
#
# 输出：
#   加固库名、DEX 结构与熵值、反调试/Hook 特征、各分类命中、【结论】。
#   临时文件放在 mktemp 目录，脚本退出时删除。
#
# 退出码：
#   0 = 发现至少一类加固/对抗特征
#   1 = 未发现明显加固/对抗特征
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

MAX=20
SAMPLE_MB=2
TARGET=""

usage() {
  cat <<'EOF'
用法: ./15-hardening-detect.sh <APK> [--max N] [--sample-mb N]

参数:
  <APK>           必填。格式: APK 文件路径。
  --max N         可选。格式: 非负整数。默认: 20。示例: --max 50
  --sample-mb N   可选。格式: 正整数。默认: 2。示例: --sample-mb 4
  -h, --help      显示本帮助。

退出码:
  0 = 发现加固/对抗特征
  1 = 未发现明显加固/对抗特征
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
    --sample-mb)
      if [[ -z "${2:-}" || ! "${2:-}" =~ ^[1-9][0-9]*$ ]]; then
        echo "[FAIL] --sample-mb 的值 \"${2:-}\" 不合法：要求正整数。" >&2
        usage >&2
        exit 2
      fi
      SAMPLE_MB="$2"
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
need_tool od      "macOS 通常自带；Linux: sudo apt install coreutils"
need_tool dd      "macOS 通常自带；Linux: sudo apt install coreutils"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hardening.XXXXXX")"
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

echo "[loading] 正在读取 ZIP 条目..."
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
ENTRY_COUNT="$(printf '%s\n' "$ENTRIES" | grep -c . || true)"
echo "[done] 条目读取完成：$ENTRY_COUNT 个"

if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  echo "[FAIL] 输入不是有效的 ZIP/APK，或文件已损坏。" >&2
  exit 2
fi
if ! grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  echo "[FAIL] 输入不是 APK（ZIP 根目录缺少 AndroidManifest.xml）。" >&2
  echo "       本脚本只接受 APK；AAB/APKS 请先转成 APK。" >&2
  exit 2
fi

echo "============================================================"
echo "静态分析 15：加固 / 壳 / 反调试特征识别"
echo "目标：$TARGET"
echo "输入类型：APK"
echo "条目数：$ENTRY_COUNT"
echo "参数：max=$MAX sample_mb=$SAMPLE_MB"
echo "============================================================"

# ---------- 1. 加固库名 ----------
: > "$TMP_DIR/packer-libs.txt"
printf '%s\n' "$ENTRIES" | grep -Ei 'lib/([^/]+/)?(lib)?(jiagu|jgdtc|shell|shellx|dexhelper|exec|execmain|protectclass|mobisec|sgmain|sgsecuritybody|tup|nesec|kwscmm|kwsgmain|dexprotector|nqshield|appguard|apkprotect|baiduprotect|secneo|mobisec|fprotect|sign|ddog|mssdk|ugc)[^/]*\.so$' \
  | sort > "$TMP_DIR/packer-libs.txt" || true

# ---------- 2. DEX 魔数与熵 ----------
: > "$TMP_DIR/dex-info.txt"
: > "$TMP_DIR/dex-anomaly.txt"
DEX_LIST="$(printf '%s\n' "$ENTRIES" | grep -E '^classes([0-9]+)?\.dex$' | sort || true)"
DEX_COUNT="$(printf '%s\n' "$DEX_LIST" | grep -c . || true)"
echo "[loading] 正在检查 $DEX_COUNT 个 DEX 的魔数与熵值（采样 ${SAMPLE_MB}MB/DEX）..."
while IFS= read -r dex; do
  [[ -n "$dex" ]] || continue
  out="$TMP_DIR/$(basename "$dex")"
  unzip -p "$TARGET" "$dex" > "$out" 2>/dev/null || continue
  size="$(wc -c < "$out" | tr -d ' ')"
  magic="$(dd if="$out" bs=1 count=8 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  entropy="$(dd if="$out" bs=1048576 count="$SAMPLE_MB" 2>/dev/null \
    | od -An -tu1 -v \
    | awk '{for(i=1;i<=NF;i++){c[$i]++;n++}} END{if(n==0){printf "0.00";exit} for(k in c){p=c[k]/n; s-=p*(log(p)/log(2))} printf "%.2f", s}')"
  if [[ "$magic" == 6465780a30* ]]; then
    valid="是"
  else
    valid="否"
  fi
  printf '%s|%s|%s|%s\n' "$dex" "$size" "$valid" "$entropy" >> "$TMP_DIR/dex-info.txt"
  if [[ "$valid" == "否" ]]; then
    printf '%s (魔数异常, entropy=%s)\n' "$dex" "$entropy" >> "$TMP_DIR/dex-anomaly.txt"
  elif awk -v e="$entropy" 'BEGIN{exit !(e >= 7.20)}'; then
    printf '%s (熵值 %.2f 偏高)\n' "$dex" "$entropy" >> "$TMP_DIR/dex-anomaly.txt"
  fi
done <<< "$DEX_LIST"
echo "[done] DEX 检查完成"

# ---------- 3. 加固/对抗字符串 ----------
: > "$TMP_DIR/anti-debug.txt"
SO_LIST="$(printf '%s\n' "$ENTRIES" | grep -E '^lib/[^/]+/.+\.so$' || true)"
SO_COUNT="$(printf '%s\n' "$SO_LIST" | grep -c . || true)"
echo "[loading] 正在扫描 $SO_COUNT 个 native 库的加固/对抗字符串..."
while IFS= read -r so; do
  [[ -n "$so" ]] || continue
  unzip -p "$TARGET" "$so" 2>/dev/null | strings -a -n 5 \
    | grep -Ei 'jiagu|bangcle|ijiami|dexhelper|dexprotector|nqshield|secneo|tencent.*shell|(^|[^a-z])frida([^a-z]|$)|(^|[^a-z])xposed|substrate|magisk|(^|[^a-z_])ptrace([^a-z_]|$)|TracerPid|anti.?debug|gum-js-loop|libhooker' \
    | awk -v e="$so" '{print "[" e "] " $0}' >> "$TMP_DIR/anti-debug.txt" || true
done <<< "$SO_LIST"
echo "[done] native 扫描完成"

echo "------------------------------------------------------------"
report_hits "加固/壳库名" "$TMP_DIR/packer-libs.txt"
echo "------------------------------------------------------------"
echo "DEX 结构（文件|大小|魔数有效|熵值）："
if [[ "$DEX_COUNT" -eq 0 ]]; then
  echo "  (未发现 classes*.dex)"
else
  awk -v max="$MAX" 'NR <= max' "$TMP_DIR/dex-info.txt" \
    | awk -F'|' '{printf "  - %-28s %10s bytes  magic=%s  entropy=%s\n", $1, $2, $3, $4}'
  if [[ "$DEX_COUNT" -gt "$MAX" ]]; then
    echo "  ...（其余 $((DEX_COUNT - MAX)) 个已省略）"
  fi
fi
echo "------------------------------------------------------------"
report_hits "DEX 异常（魔数/熵值）" "$TMP_DIR/dex-anomaly.txt"
echo "------------------------------------------------------------"
report_hits "native 加固/反调试/Hook 特征" "$TMP_DIR/anti-debug.txt"

PACKER_CNT="$(grep -c . "$TMP_DIR/packer-libs.txt" 2>/dev/null || true)"
ANOMALY_CNT="$(grep -c . "$TMP_DIR/dex-anomaly.txt" 2>/dev/null || true)"
ANTI_CNT="$(grep -c . "$TMP_DIR/anti-debug.txt" 2>/dev/null || true)"
TOTAL=$((PACKER_CNT + ANOMALY_CNT + ANTI_CNT))

echo "------------------------------------------------------------"
echo "【结论】"
if [[ "$PACKER_CNT" -gt 0 ]]; then
  if [[ "$ANOMALY_CNT" -gt 0 ]]; then
    echo "  ⚠ 检测到已知加固/壳库名，且 DEX 存在异常：应用可能经过整体加固，DEX 可能被加密或抽取。"
    echo "    本脚本不负责脱壳；需要动态 dump 或专用脱壳工具后再做代码审计。"
  else
    echo "  ⚠ 检测到安全/加固相关库名，但所有 DEX 魔数与熵值正常："
    echo "    可能是安全防护 SDK（例如 sgmain）、局部加固或误报，不一定是整体壳。"
    echo "    建议结合库的实际加载行为和 DEX 可读性判断。"
  fi
elif [[ "$ANOMALY_CNT" -gt 0 ]]; then
  echo "  ⚠ DEX 魔数异常或熵值偏高：存在加密/压缩/自定义加载的可能。"
fi
if [[ "$ANTI_CNT" -gt 0 ]]; then
  echo "  ⚠ 发现反调试/Hook 检测/Frida/Xposed 相关字符串：应用可能包含对抗逻辑。"
fi
if [[ "$TOTAL" -eq 0 ]]; then
  echo "  - 未发现明显的加固库名、DEX 异常或对抗字符串。"
  echo "  - 这不代表没有加固：自定义壳、改名库、动态下发都可能绕过启发式识别。"
  echo "  说明：本脚本只做特征识别，不做脱壳，也不验证防护强度。"
  exit 1
fi
echo "  说明：特征命中不等于正在启用，需结合运行行为确认；本脚本不修改样本、不联网。"
exit 0
