#!/usr/bin/env bash
#
# 05-compare-archives.sh —— 通用静态分析：两个归档/APK 的内容级对比
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   对比“基准包”和“待测包”的文件列表、每个文件的 SHA-256，
#   并对内容变化且大小相同的文件做逐字节比较，回答：
#     - 哪些文件只存在于基准包？
#     - 哪些文件只存在于待测包？
#     - 哪些文件路径相同但内容不同？
#     - 改动是“等长改写”还是“大小也变了”？
#     - 改动集中在 Manifest、DEX、原生库、资源还是 assets？
#
#   默认排除 META-INF/（v1 签名文件天然不同），可用 --include-meta-inf 包含。
#
# 参数：
#   <基准包>        必填
#                   格式：存在且可读的 APK/ZIP/JAR 文件路径（必须是 ZIP 容器）
#                   示例：./baseline.apk
#                   说明：作为对比基准；脚本只读，不会修改
#   <待测包>        必填
#                   格式：存在且可读的 APK/ZIP/JAR 文件路径（必须是 ZIP 容器）
#                   示例：./suspect.apk
#                   说明：待检测包；脚本只读，不会修改
#   --include-meta-inf  可选
#                   格式：布尔开关，不带值
#                   默认：关闭（排除 META-INF/）
#                   示例：--include-meta-inf
#                   说明：也比较 META-INF/；v1 签名文件天然不同，通常不需要
#   --max-cmp N     可选
#                   格式：非负整数（^[0-9]+$）
#                   默认：10
#                   示例：--max-cmp 20
#                   说明：最多对 N 个内容变化的文件做逐字节 cmp；0 表示不做
#
# 依赖：
#   unzip、cmp、awk、sort、find、strings，以及 shasum/sha256sum/openssl 之一。
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./05-compare-archives.sh <基准包> <待测包>
#   ./05-compare-archives.sh <基准包> <待测包> --include-meta-inf
#   ./05-compare-archives.sh <基准包> <待测包> --max-cmp 20
#   ./05-compare-archives.sh --help
#
#   错误输入示例：
#     ./05-compare-archives.sh app.apk
#       → 缺少第二个包，exit 2
#     ./05-compare-archives.sh app.apk note.txt
#       → note.txt 不是 ZIP 容器，exit 2
#
# 输出：
#   包级摘要、重复 ZIP 条目、逐文件 SHA-256 对比统计、变化/新增/删除列表、
#   变化文件的逐字节差异摘要、【结论】。
#   不修改输入；临时文件放在 mktemp 目录，退出时删除。
#
# 退出码：
#   0 = 除 META-INF（或按参数排除的范围）外，文件列表和内容完全一致
#   1 = 存在差异
#   2 = 参数/依赖/输入错误
#
set -euo pipefail
export LC_ALL=C

INCLUDE_META=false
MAX_CMP_FILES=10
MAX_CMP_BYTES=52428800   # 超过 50MB 的文件不做逐字节 cmp，避免耗时过长
MAX_LIST=50

usage() {
  cat <<'EOF'
用法:
  ./05-compare-archives.sh <基准包> <待测包>
  ./05-compare-archives.sh <基准包> <待测包> --include-meta-inf
  ./05-compare-archives.sh <基准包> <待测包> --max-cmp 20
  ./05-compare-archives.sh --help

参数:
  <基准包>             必填。格式: 存在且可读的 APK/ZIP/JAR 路径（ZIP 容器）。示例: ./baseline.apk
  <待测包>             必填。格式: 存在且可读的 APK/ZIP/JAR 路径（ZIP 容器）。示例: ./suspect.apk
  --include-meta-inf   可选。布尔开关。默认: 关闭（排除 META-INF/）。示例: --include-meta-inf
  --max-cmp N          可选。格式: 非负整数。默认: 10。示例: --max-cmp 20

输出:
  包级摘要、逐文件哈希对比、变化/新增/删除列表、逐字节差异摘要、【结论】。

退出码:
  0 = 完全一致
  1 = 存在差异
  2 = 参数/依赖/输入错误
EOF
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --include-meta-inf)
      INCLUDE_META=true
      shift
      ;;
    --max-cmp)
      if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
        echo "[FAIL] --max-cmp 需要一个非负整数" >&2
        exit 2
      fi
      MAX_CMP_FILES="$2"
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
      ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#ARGS[@]} -ne 2 ]]; then
  usage >&2
  exit 2
fi

BASE="${ARGS[0]}"
SUS="${ARGS[1]}"

for f in "$BASE" "$SUS"; do
  if [[ ! -f "$f" ]]; then
    echo "[FAIL] 文件不存在: $f" >&2
    exit 2
  fi
done

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
need_tool cmp    "macOS 通常自带；Linux: sudo apt install diffutils"
need_tool awk    "macOS 通常自带；Linux: sudo apt install gawk / mawk"
need_tool sort   "macOS 通常自带；Linux: sudo apt install coreutils"
need_tool find   "macOS 通常自带；Linux: sudo apt install findutils"
need_tool strings "macOS: xcode-select --install；Linux: sudo apt install binutils"

# ---------- 选择 SHA-256 工具 ----------
HASH_TOOL=""
HASH_OPTIONS=()
if command -v shasum >/dev/null 2>&1; then
  HASH_TOOL="shasum"
  HASH_OPTIONS=(-a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  HASH_TOOL="sha256sum"
elif command -v openssl >/dev/null 2>&1; then
  HASH_TOOL="openssl"
else
  echo "[FAIL] 缺少 SHA-256 工具。" >&2
  echo "       macOS 通常自带 shasum；Linux 可安装：" >&2
  echo "       sudo apt install coreutils openssl" >&2
  echo "       sudo dnf install coreutils openssl" >&2
  exit 2
fi

# ---------- 校验输入是有效 ZIP ----------
for f in "$BASE" "$SUS"; do
  if ! unzip -Z1 "$f" >/dev/null 2>&1; then
    echo "[FAIL] 无法读取 ZIP 目录: $f" >&2
    echo "       请确认它是 APK/ZIP/JAR 等 ZIP 容器，而不是已损坏文件。" >&2
    exit 2
  fi
done

# ---------- 解压到临时目录 ----------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/compare-archives.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
BASE_DIR="$TMP_DIR/base"
SUS_DIR="$TMP_DIR/sus"
mkdir -p "$BASE_DIR" "$SUS_DIR"

# -o：遇到重复 ZIP 条目时直接覆盖，避免 unzip 停在交互式
# “replace ...? [y]es, [n]o ...” 提示上。重复条目本身会在下面单独提示。
BASE_ENTRY_COUNT="$(unzip -Z1 "$BASE" 2>/dev/null | grep -c . || true)"
SUS_ENTRY_COUNT="$(unzip -Z1 "$SUS" 2>/dev/null | grep -c . || true)"
echo "[loading] 正在解压两个归档（基准 $BASE_ENTRY_COUNT 项，待测 $SUS_ENTRY_COUNT 项；大文件可能需要几十秒）..."
unzip -oq "$BASE" -d "$BASE_DIR"
unzip -oq "$SUS"  -d "$SUS_DIR"
echo "[done] 解压完成"

# 重复条目：同一路径在 ZIP 目录中出现多次。不同解析器可能取不同副本，
# 因此这里单独统计；下面的逐文件哈希只反映解压后实际留下的那个副本。
BASE_DUPES="$(unzip -Z1 "$BASE" 2>/dev/null | sort | uniq -d || true)"
SUS_DUPES="$(unzip -Z1 "$SUS" 2>/dev/null | sort | uniq -d || true)"
BASE_DUP_COUNT="$(printf '%s\n' "$BASE_DUPES" | grep -c . || true)"
SUS_DUP_COUNT="$(printf '%s\n' "$SUS_DUPES" | grep -c . || true)"

# ---------- 生成“哈希 + 相对路径”清单 ----------
# 输出格式：<sha256>\t<相对路径>
build_hash_manifest() {
  local dir="$1"
  local out="$2"
  local find_args=(-type f)

  if [[ "$INCLUDE_META" != true ]]; then
    find_args+=(-not -path './META-INF/*')
  fi

  if [[ "$HASH_TOOL" == "shasum" || "$HASH_TOOL" == "sha256sum" ]]; then
    ( cd "$dir" && find . "${find_args[@]}" -exec "$HASH_TOOL" "${HASH_OPTIONS[@]}" {} + ) \
      | awk '{ h=$1; sub(/^[^ ]+  /, ""); sub(/^\.\//, ""); print h "\t" $0 }' \
      | sort -t $'\t' -k2 > "$out"
  else
    : > "$out"
    while IFS= read -r -d '' f; do
      local rel="${f#./}"
      local h
      h="$(openssl dgst -sha256 "$f" | awk '{print $NF}')"
      printf '%s\t%s\n' "$h" "$rel" >> "$out"
    done < <( cd "$dir" && find . "${find_args[@]}" -print0 )
    sort -t $'\t' -k2 "$out" -o "$out"
  fi
}

BASE_HASH="$TMP_DIR/base.sha256"
SUS_HASH="$TMP_DIR/sus.sha256"
echo "[loading] 正在计算两个包内每个文件的 SHA-256（文件较多时可能需要一段时间）..."
build_hash_manifest "$BASE_DIR" "$BASE_HASH"
build_hash_manifest "$SUS_DIR"  "$SUS_HASH"
BASE_FILE_COUNT="$(wc -l < "$BASE_HASH" | tr -d ' ')"
SUS_FILE_COUNT="$(wc -l < "$SUS_HASH" | tr -d ' ')"
echo "[done] 哈希完成：基准 $BASE_FILE_COUNT 个文件，待测 $SUS_FILE_COUNT 个文件"

# ---------- 对比两个清单 ----------
RECORDS="$TMP_DIR/records.tsv"
awk -F'\t' '
  FNR==NR { base[$2]=$1; next }
  {
    if ($2 in base) {
      if (base[$2] == $1) print "SAME\t" $2;
      else                print "CHANGED\t" $2;
      delete base[$2];
    } else {
      print "ADDED\t" $2;
    }
  }
  END { for (p in base) print "REMOVED\t" p; }
' "$BASE_HASH" "$SUS_HASH" | sort > "$RECORDS"

SAME_COUNT="$(grep -c $'^SAME\t' "$RECORDS" || true)"
CHANGED_COUNT="$(grep -c $'^CHANGED\t' "$RECORDS" || true)"
ADDED_COUNT="$(grep -c $'^ADDED\t' "$RECORDS" || true)"
REMOVED_COUNT="$(grep -c $'^REMOVED\t' "$RECORDS" || true)"

has_record() {
  local kind="$1"
  local pattern="$2"
  awk -F'\t' -v k="$kind" -v p="$pattern" \
    '$1 == k && $2 ~ p { found=1 } END { exit !found }' "$RECORDS"
}

# ---------- 逐字节比较一个变化文件 ----------
cmp_one() {
  local rel="$1"
  local a="$BASE_DIR/$rel"
  local b="$SUS_DIR/$rel"
  [[ -f "$a" && -f "$b" ]] || return 0

  local sa sb
  sa="$(wc -c < "$a" | tr -d ' ')"
  sb="$(wc -c < "$b" | tr -d ' ')"

  echo "  - $rel"
  echo "      大小: 基准=$sa 字节, 待测=$sb 字节"

  if [[ "$sa" != "$sb" ]]; then
    echo "      大小不同，未做逐字节比较。"
    return 1
  fi

  if [[ "$sa" -gt "$MAX_CMP_BYTES" ]]; then
    echo "      文件超过 ${MAX_CMP_BYTES} 字节，跳过逐字节比较。"
    return 0
  fi

  local tmp diff_count first off skip
  tmp="$(mktemp "${TMPDIR:-/tmp}/cmp-one.XXXXXX")"
  cmp -l "$a" "$b" > "$tmp" 2>/dev/null || true
  diff_count="$(wc -l < "$tmp" | tr -d ' ')"
  echo "      等长修改: $diff_count 个字节不同"

  first="$(awk 'NR == 1 { print; exit }' "$tmp" || true)"
  if [[ -n "$first" ]]; then
    echo "      首个差异（偏移 原字节 新字节）: $first"
    off="$(awk '{print $1}' <<<"$first")"
    if [[ "$off" =~ ^[0-9]+$ ]]; then
      skip=$(( off > 32 ? off - 32 : 0 ))
      echo "      基准包上下文:"
      dd if="$a" bs=1 skip="$skip" count=96 2>/dev/null | strings -a | awk 'NR <= 3' | sed 's/^/        /'
      echo "      待测包上下文:"
      dd if="$b" bs=1 skip="$skip" count=96 2>/dev/null | strings -a | awk 'NR <= 3' | sed 's/^/        /'
    fi
  fi

  rm -f "$tmp"
  return 0
}

# ---------- 输出 ----------
echo "============================================================"
echo "静态分析：两个归档/APK 的内容级对比"
echo "基准包：$BASE"
echo "待测包：$SUS"
echo "META-INF：$([[ "$INCLUDE_META" == true ]] && echo "参与比较" || echo "已排除")"
echo "重复 ZIP 条目：基准=$BASE_DUP_COUNT, 待测=$SUS_DUP_COUNT"
if [[ "$BASE_DUP_COUNT" -gt 0 || "$SUS_DUP_COUNT" -gt 0 ]]; then
  echo "注意：存在重复条目时，解压结果通常只保留最后一个副本；"
  echo "      下面的哈希对比只覆盖该副本，重复条目本身需单独人工检查。"
  if [[ "$BASE_DUP_COUNT" -gt 0 ]]; then
    echo "  基准包重复条目（前 10）："
    printf '%s\n' "$BASE_DUPES" | awk 'NR <= 10' | sed 's/^/    - /'
  fi
  if [[ "$SUS_DUP_COUNT" -gt 0 ]]; then
    echo "  待测包重复条目（前 10）："
    printf '%s\n' "$SUS_DUPES" | awk 'NR <= 10' | sed 's/^/    - /'
  fi
fi
echo "============================================================"
echo "相同文件        : $SAME_COUNT"
echo "内容变化        : $CHANGED_COUNT"
echo "仅基准包存在    : $REMOVED_COUNT"
echo "仅待测包存在    : $ADDED_COUNT"

if [[ "$CHANGED_COUNT" -gt 0 ]]; then
  echo "------------------------------------------------------------"
  echo "内容变化的文件（前 $MAX_LIST 个）："
  awk -F'\t' -v max="$MAX_LIST" '$1 == "CHANGED" { print $2; if (++n >= max) exit }' "$RECORDS" | sed 's/^/  - /'
fi

if [[ "$REMOVED_COUNT" -gt 0 ]]; then
  echo "------------------------------------------------------------"
  echo "仅基准包存在的文件（前 $MAX_LIST 个）："
  awk -F'\t' -v max="$MAX_LIST" '$1 == "REMOVED" { print $2; if (++n >= max) exit }' "$RECORDS" | sed 's/^/  - /'
fi

if [[ "$ADDED_COUNT" -gt 0 ]]; then
  echo "------------------------------------------------------------"
  echo "仅待测包存在的文件（前 $MAX_LIST 个）："
  awk -F'\t' -v max="$MAX_LIST" '$1 == "ADDED" { print $2; if (++n >= max) exit }' "$RECORDS" | sed 's/^/  - /'
fi

# ---------- 对变化文件做逐字节分析 ----------
if [[ "$CHANGED_COUNT" -gt 0 && "$MAX_CMP_FILES" -gt 0 ]]; then
  echo "------------------------------------------------------------"
  echo "逐字节比较（最多 $MAX_CMP_FILES 个变化文件）："
  echo "[loading] 正在对最多 $MAX_CMP_FILES 个变化文件做逐字节比较..."
  shown=0
  while IFS=$'\t' read -r kind rel; do
    [[ "$kind" == "CHANGED" ]] || continue
    cmp_one "$rel" || true
    shown=$((shown + 1))
    [[ "$shown" -ge "$MAX_CMP_FILES" ]] && break
  done < "$RECORDS"
  echo "[done] 逐字节比较完成：$shown 个文件"
fi

# ---------- 差异归类 ----------
echo "------------------------------------------------------------"
echo "【结论】"

if [[ "$CHANGED_COUNT" -eq 0 && "$ADDED_COUNT" -eq 0 && "$REMOVED_COUNT" -eq 0 ]]; then
  echo "两个包在文件列表和文件内容上完全一致（按当前 META-INF 设置）。"
  if [[ "$INCLUDE_META" != true ]]; then
    echo "注意：本次排除了 META-INF/，因此本结论不能替代签名者/证书比对。"
  fi
  exit 0
fi

echo "两个包存在差异。"
if has_record CHANGED '^AndroidManifest\.xml$'; then
  echo "  - AndroidManifest.xml 变了：组件、权限、SDK 或安全配置可能变化。"
fi
if has_record CHANGED '^classes([0-9]+)?\.dex$'; then
  echo "  - classes*.dex 变了：Java/Kotlin 代码发生变化。"
fi
if has_record CHANGED '^lib/.*\.so$'; then
  echo "  - 原生库 .so 变了：native 代码发生变化。"
fi
if has_record CHANGED '^resources\.arsc$' || has_record CHANGED '^res/'; then
  echo "  - 资源发生变化：resources.arsc 或 res/ 下的内容不同。"
fi
if has_record CHANGED '^assets/'; then
  echo "  - assets 发生变化：内置资源/配置不同。"
fi
if has_record CHANGED '^META-INF/'; then
  echo "  - META-INF 发生变化：签名文件或签名相关元数据不同。"
fi
if [[ "$ADDED_COUNT" -gt 0 || "$REMOVED_COUNT" -gt 0 ]]; then
  echo "  - 存在新增/删除文件：包结构发生变化。"
fi

exit 1
