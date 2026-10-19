#!/usr/bin/env bash
#
# 11-native-audit.sh —— 通用静态分析：Native / 加固 / 对齐审计
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   - 列出 APK 内所有 .so：ABI、数量、大小、SHA-256
#   - 检查已知加固/壳的库名和字符串特征（启发式）
#   - 用 zipalign 检查 4 字节对齐
#   - 可选：用 readelf/greadelf/llvm-readelf 查看 .so 动态符号
#     （关注 JNI_OnLoad、导出函数等）
#
#   说明：
#     Android .so 是 ELF。macOS 自带的 otool/nm 主要面向 Mach-O，
#     不能可靠分析 ELF，因此这里优先使用 readelf/greadelf/llvm-readelf。
#     加固检测只基于库名和字符串特征，不能证明一定加壳，也不能脱壳。
#
# 参数：
#   <APK>            必填
#                     格式：存在且可读的 APK 文件路径；ZIP 根目录必须包含 AndroidManifest.xml
#                     示例：./app.apk
#                     说明：AAB/APKS/IPA/JAR/普通 ZIP 会被识别并提示不适用，exit 2
#   --symbols        可选
#                     格式：布尔开关，不带值
#                     默认：关闭
#                     示例：--symbols
#                     说明：查看 .so 的动态符号（需要 readelf/greadelf/llvm-readelf）
#   --max-symbols N  可选
#                     格式：非负整数（^[0-9]+$）
#                     默认：40
#                     示例：--max-symbols 80
#                     说明：每个 .so 最多显示 N 行导出符号
#
# 依赖：
#   unzip、strings、grep、awk、zipalign（Android SDK Build-Tools）、
#   shasum/sha256sum/openssl 之一。
#   --symbols 还需要 readelf、greadelf 或 llvm-readelf。
#   缺少时明确提示安装方式并退出，不会静默跳过。
#
# 用法：
#   ./11-native-audit.sh <APK>
#   ./11-native-audit.sh <APK> --symbols
#   ./11-native-audit.sh <APK> --symbols --max-symbols 80
#   ./11-native-audit.sh --help
#
#   错误输入示例：
#     ./11-native-audit.sh app.ipa
#       → 识别为 iOS IPA，提示 Android .so/zipalign 审计不适用，exit 2
#     ./11-native-audit.sh app.apk --max-symbols abc
#       → --max-symbols 不是非负整数，exit 2
#
# 输出：
#   .so 清单/ABI/大小/SHA-256、加固/壳特征命中、zipalign 结果、
#   可选动态符号、【结论】。
#   不修改输入；临时文件放在 mktemp 目录，退出时删除。
#
# 退出码：
#   0 = 分析完成，未发现加固特征，且对齐检查通过
#   1 = 分析完成，但发现加固特征、对齐失败，或 APK 内没有 .so
#   2 = 参数/依赖/输入错误
#
set -euo pipefail
export LC_ALL=C

SHOW_SYMBOLS=false
MAX_SYMBOLS=40
TARGET=""

usage() {
  cat <<'EOF'
用法:
  ./11-native-audit.sh <APK>
  ./11-native-audit.sh <APK> --symbols
  ./11-native-audit.sh <APK> --symbols --max-symbols 80
  ./11-native-audit.sh --help

参数:
  <APK>             必填。格式: 存在且可读的 APK 文件路径。示例: ./app.apk
  --symbols         可选。布尔开关。默认: 关闭。示例: --symbols
  --max-symbols N   可选。格式: 非负整数。默认: 40。示例: --max-symbols 80

输出:
  .so 清单/ABI/大小/SHA-256、加固特征、zipalign 结果、可选动态符号、【结论】。

退出码:
  0 = 未发现加固特征，且对齐检查通过
  1 = 发现加固特征、对齐失败，或 APK 内没有 .so
  2 = 参数/依赖/输入错误
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --symbols)
      SHOW_SYMBOLS=true
      shift
      ;;
    --max-symbols)
      if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
        echo "[FAIL] --max-symbols 需要一个非负整数" >&2
        exit 2
      fi
      MAX_SYMBOLS="$2"
      shift 2
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
        echo "[FAIL] 只能指定一个 APK" >&2
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

need_tool unzip   "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"
need_tool strings "macOS: xcode-select --install；Linux: sudo apt install binutils"
need_tool grep    "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk     "macOS 通常自带；Linux: sudo apt install gawk / mawk"

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

ZIPALIGN="$(find_android_tool zipalign || true)"
if [[ -z "$ZIPALIGN" ]]; then
  echo "[FAIL] 找不到 zipalign。" >&2
  echo "       安装 Android SDK Build-Tools：" >&2
  echo "       Android Studio → SDK Manager → SDK Tools → Android SDK Build-Tools" >&2
  echo "       或 sdkmanager \"build-tools;34.0.0\"" >&2
  exit 2
fi

HASH_TOOL=""
if command -v shasum >/dev/null 2>&1; then
  HASH_TOOL="shasum"
elif command -v sha256sum >/dev/null 2>&1; then
  HASH_TOOL="sha256sum"
elif command -v openssl >/dev/null 2>&1; then
  HASH_TOOL="openssl"
else
  echo "[FAIL] 缺少 SHA-256 工具。" >&2
  echo "       macOS 通常自带 shasum；Linux: sudo apt install coreutils openssl" >&2
  exit 2
fi

sha256_file() {
  local f="$1"
  if [[ "$HASH_TOOL" == "shasum" ]]; then
    shasum -a 256 "$f" | awk '{print $1}'
  elif [[ "$HASH_TOOL" == "sha256sum" ]]; then
    sha256sum "$f" | awk '{print $1}'
  else
    openssl dgst -sha256 "$f" | awk '{print $NF}'
  fi
}

# 查找 ELF 符号工具
find_readelf() {
  local c p
  for c in llvm-readelf readelf greadelf; do
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  for p in \
    /usr/local/opt/llvm/bin/llvm-readelf \
    /opt/homebrew/opt/llvm/bin/llvm-readelf \
    /usr/local/bin/greadelf \
    /opt/homebrew/bin/greadelf; do
    if [[ -x "$p" ]]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

READELF=""
if [[ "$SHOW_SYMBOLS" == true ]]; then
  READELF="$(find_readelf || true)"
  if [[ -z "$READELF" ]]; then
    echo "[FAIL] 找不到 ELF 符号工具（readelf / greadelf / llvm-readelf）。" >&2
    echo "       安装方式：" >&2
    echo "         macOS: brew install llvm        # 提供 llvm-readelf" >&2
    echo "                或 brew install binutils  # 提供 greadelf" >&2
    echo "         Linux: sudo apt install binutils" >&2
    echo "       说明：macOS 自带 otool 只支持 Mach-O，不适用于 Android ELF .so。" >&2
    exit 2
  fi
fi

# ---------- 1. 预检 ----------
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
if ! grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  echo "============================================================"
  echo "静态分析 11：Native / 加固 / 对齐审计"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  if [[ -n "$ENTRIES" ]]; then
    if grep -qx 'BundleConfig.pb' <<<"$ENTRIES" || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
      echo "这是 AAB，不是 APK。请先用 bundletool 生成 APK。"
    elif grep -qx 'toc.pb' <<<"$ENTRIES"; then
      echo "这是 APKS，请先解出 base.apk / split APK。"
    elif grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
      echo "这是 iOS IPA，Android .so/zipalign 审计不适用。"
    else
      echo "这不是 APK：ZIP 根目录没有 AndroidManifest.xml。"
    fi
  else
    echo "输入不是有效的 ZIP/APK。"
  fi
  exit 2
fi

NATIVE_ENTRIES="$(grep -E '^lib/[^/]+/.+\.so$' <<<"$ENTRIES" | sort || true)"
NATIVE_COUNT="$(printf '%s\n' "$NATIVE_ENTRIES" | grep -c . || true)"
ABI_LIST="$(grep -oE '^lib/[^/]+/' <<<"$ENTRIES" | cut -d/ -f2 | sort -u || true)"

# ---------- 2. 输出头 + 清单 ----------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/native-audit.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
ALL_STRINGS="$TMP_DIR/all-strings.txt"
: > "$ALL_STRINGS"

echo "============================================================"
echo "静态分析 11：Native / 加固 / 对齐审计"
echo "目标：$TARGET"
echo "zipalign：$ZIPALIGN"
echo "原生库总数：$NATIVE_COUNT"
echo "ABI：$(printf '%s' "$ABI_LIST" | paste -sd, - 2>/dev/null || echo "无")"
echo "============================================================"

if [[ "$NATIVE_COUNT" -eq 0 ]]; then
  echo "APK 内没有 lib/<abi>/*.so。"
  echo "可能是纯 Java/Kotlin 应用，或 native 库在 split APK 中。"
  echo "没有 .so 时无法做加固特征/符号分析；下面仍会做 zipalign 检查。"
else
  echo "原生库清单："
  echo "[loading] 正在提取并计算 $NATIVE_COUNT 个 .so 的大小、SHA-256 和字符串（大文件可能需要一段时间）..."
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    abi="$(cut -d/ -f2 <<<"$entry")"
    dest_dir="$TMP_DIR/native/$abi"
    mkdir -p "$dest_dir"
    dest="$dest_dir/$(basename "$entry")"
    unzip -p "$TARGET" "$entry" > "$dest"

    size="$(wc -c < "$dest" | tr -d ' ')"
    sha="$(sha256_file "$dest")"
    echo "  - $entry"
    echo "      大小: $size 字节"
    echo "      SHA-256: $sha"

    printf '### %s\n' "$entry" >> "$ALL_STRINGS"
    strings -a -n 4 "$dest" >> "$ALL_STRINGS" || true
  done <<<"$NATIVE_ENTRIES"
  echo "[done] .so 处理完成：$NATIVE_COUNT 个"
fi

# ---------- 3. 加固/壳特征（启发式） ----------
echo "------------------------------------------------------------"
echo "加固/壳特征（启发式）："

PACKER_ENTRY_HITS="$(grep -iE 'lib(jiagu|shell|dexhelper|protectclass|mobisec|nesec|baiduprotect|secshell|ijiami|bangcle|apkprotect|kwscmm|kwslinker)' <<<"$NATIVE_ENTRIES" || true)"
PACKER_ENTRY_COUNT="$(printf '%s\n' "$PACKER_ENTRY_HITS" | grep -c . || true)"

PACKER_STRING_HITS="$(awk '
  /^### / { entry = substr($0, 5); next }
  tolower($0) ~ /jiagu|dexhelper|mobisec|libnesec|baiduprotect|secshell|ijiami|bangcle|nagapt|protectclass/ {
    print "[" entry "] " $0
  }
' "$ALL_STRINGS" | sort -u | awk 'NR <= 20' || true)"
PACKER_STRING_COUNT="$(printf '%s\n' "$PACKER_STRING_HITS" | grep -c . || true)"

if [[ "$PACKER_ENTRY_COUNT" -gt 0 ]]; then
  echo "  库名命中："
  printf '%s\n' "$PACKER_ENTRY_HITS" | sed 's/^/    - /'
fi
if [[ "$PACKER_STRING_COUNT" -gt 0 ]]; then
  echo "  字符串命中（前 20 条）："
  printf '%s\n' "$PACKER_STRING_HITS" | sed 's/^/    /'
fi
if [[ "$PACKER_ENTRY_COUNT" -eq 0 && "$PACKER_STRING_COUNT" -eq 0 ]]; then
  echo "  (未命中已知特征)"
fi
echo "  注意：这是基于库名/字符串的启发式判断，不能证明一定加壳，也不能脱壳。"

# ---------- 4. zipalign 对齐检查 ----------
echo "------------------------------------------------------------"
echo "zipalign 4 字节对齐检查："
echo "[loading] 正在检查 APK 的 4 字节对齐..."
ALIGN_LOG="$TMP_DIR/zipalign.log"
ALIGN_OK=false
if "$ZIPALIGN" -c -v 4 "$TARGET" > "$ALIGN_LOG" 2>&1; then
  ALIGN_OK=true
  echo "  通过：APK 已按 4 字节对齐。"
else
  echo "  ⚠ 未通过：APK 存在未对齐条目。"
  echo "  关键输出："
  grep -iE 'bad|error|fail|not aligned|verification' "$ALIGN_LOG" \
    | awk 'NR <= 10' | sed 's/^/    /' || true
fi
echo "[done] 对齐检查完成"
echo "  说明：zipalign 只检查对齐，不验证签名有效性。"

# ---------- 5. 可选：动态符号 ----------
echo "------------------------------------------------------------"
if [[ "$SHOW_SYMBOLS" != true ]]; then
  echo "动态符号：未启用。"
  echo "  如需查看 JNI_OnLoad / 导出函数，可加 --symbols 重跑（需要 readelf/greadelf/llvm-readelf）。"
else
  echo "动态符号（工具：$READELF）："
  if [[ "$NATIVE_COUNT" -eq 0 ]]; then
    echo "  (没有 .so，跳过)"
  else
    echo "[loading] 正在读取 $NATIVE_COUNT 个 .so 的动态符号..."
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      abi="$(cut -d/ -f2 <<<"$entry")"
      so="$TMP_DIR/native/$abi/$(basename "$entry")"
      sym_log="$TMP_DIR/native/$abi/$(basename "$entry").syms.txt"

      if ! "$READELF" --dyn-syms "$so" > "$sym_log" 2> "$TMP_DIR/readelf.err"; then
        echo "  --- $entry"
        echo "      [WARN] readelf 解析失败：$(awk 'NR == 1 { print; exit }' "$TMP_DIR/readelf.err" 2>/dev/null || true)"
        continue
      fi

      jni_count="$(grep -c 'JNI_OnLoad' "$sym_log" || true)"
      imported_count="$(grep -E 'FUNC|OBJECT' "$sym_log" | grep -c ' UND ' || true)"
      exported_list="$(grep -E 'FUNC|OBJECT' "$sym_log" | grep -Ev ' UND ' \
        | awk -v max="$MAX_SYMBOLS" 'NR <= max' || true)"

      echo "  --- $entry"
      echo "      JNI_OnLoad 命中：$jni_count"
      echo "      导入符号（UND）：$imported_count 条"
      echo "      导出符号（前 $MAX_SYMBOLS 行，已排除 UND）："
      if [[ -n "$exported_list" ]]; then
        printf '%s\n' "$exported_list" | sed 's/^/        /'
      else
        echo "        (无)"
      fi
    done <<<"$NATIVE_ENTRIES"
    echo "[done] 动态符号读取完成"
  fi
fi

# ---------- 6. 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

RISK=false

if [[ "$NATIVE_COUNT" -eq 0 ]]; then
  echo "  - APK 内没有 .so：可能纯 Java/Kotlin，或 native 在 split APK 中。"
  RISK=true
fi
if [[ "$PACKER_ENTRY_COUNT" -gt 0 || "$PACKER_STRING_COUNT" -gt 0 ]]; then
  echo "  ⚠ 命中疑似加固/壳特征：需进一步确认是否为保护壳，以及是否影响静态分析。"
  RISK=true
fi
if [[ "$ALIGN_OK" != true ]]; then
  echo "  ⚠ APK 未通过 4 字节对齐检查：可能影响安装/加载，或说明打包流程不规范。"
  RISK=true
fi

if [[ "$RISK" == true ]]; then
  echo "  以上为静态结构信号，需结合打包方式、签名和运行环境确认。"
  exit 1
fi

echo "  未发现加固特征，且对齐检查通过。"
echo "  这不等于 native 代码安全；还需做符号、字符串和调用链分析。"
exit 0
