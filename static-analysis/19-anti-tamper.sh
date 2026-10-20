#!/usr/bin/env bash
#
# 19-anti-tamper.sh —— 通用静态分析：反篡改 / 反调试 / Root / 模拟器 / Hook 检测特征
#
# 用途：
#   1. 从 APK 的 DEX 与 native 库字符串中识别五类对抗特征：
#      Root 检测、模拟器检测、反调试、Hook/Frida/Xposed 检测、完整性校验。
#   2. 按类别输出命中次数、命中种类和前若干条证据，便于定位实现位置。
#   3. 不覆盖：加固壳识别（见单独的加固脚本）、真实防护强度验证、
#      运行时绕过、native 指令级分析。字符串命中不等于防护已启用。
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
#                   说明：每个类别最多显示 N 种命中
#
# 依赖：
#   unzip、strings、grep、awk、sort、uniq、tr
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./19-anti-tamper.sh <APK>
#   ./19-anti-tamper.sh <APK> --max 50
#   ./19-anti-tamper.sh --help
#
# 输出：
#   扫描规模、Root/模拟器/反调试/Hook/完整性五类命中、【结论】。
#   临时文件放在 mktemp 目录，脚本退出时删除。
#
# 退出码：
#   0 = 至少命中一类对抗特征
#   1 = 未发现明显对抗特征
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

MAX=20
TARGET=""

usage() {
  cat <<'EOF'
用法: ./19-anti-tamper.sh <APK> [--max N]

参数:
  <APK>      必填。格式: APK 文件路径。
  --max N    可选。格式: 非负整数。默认: 20。示例: --max 50
  -h, --help 显示本帮助。

退出码:
  0 = 至少命中一类对抗特征
  1 = 未发现明显对抗特征
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
need_tool uniq    "macOS 通常自带；Linux: sudo apt install coreutils"
need_tool tr      "macOS 通常自带；Linux: sudo apt install coreutils"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/anti-tamper.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

report_cat() {
  local key="$1" label="$2" pattern="$3"
  local file="$TMP_DIR/$key.txt"
  grep -Eo -- "$pattern" "$TMP_DIR/filtered.txt" 2>/dev/null \
    | tr 'A-Z' 'a-z' | sort | uniq -c \
    | awk '{c=$1; $1=""; sub(/^[[:space:]]+/, ""); if (length($0) > 120) $0 = substr($0, 1, 120); print c "|" $0}' \
    | sort -t'|' -k1,1nr > "$file" || true
}

sum_cat() {
  awk -F'|' '{s += $1} END {print s + 0}' "$1" 2>/dev/null || echo 0
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

DEX_LIST="$(printf '%s\n' "$ENTRIES" | grep -E '^classes([0-9]+)?\.dex$' | sort || true)"
SO_LIST="$(printf '%s\n' "$ENTRIES" | grep -E '^lib/[^/]+/.+\.so$' | sort || true)"
DEX_COUNT="$(printf '%s\n' "$DEX_LIST" | grep -c . || true)"
SO_COUNT="$(printf '%s\n' "$SO_LIST" | grep -c . || true)"

echo "============================================================"
echo "静态分析 19：反篡改 / 反调试 / Root / 模拟器 / Hook 检测特征"
echo "目标：$TARGET"
echo "输入类型：APK"
echo "条目数：$ENTRY_COUNT；DEX：$DEX_COUNT；native 库：$SO_COUNT"
echo "参数：max=$MAX"
echo "============================================================"

# ---------- 字符串提取 ----------
# 提取时统一转小写：后续关键字过滤和正则都按小写匹配，避免 grep -i 在大文件上反复折叠大小写
: > "$TMP_DIR/dump.txt"
echo "[loading] 正在提取 DEX 字符串（大包可能需要数十秒）..."
while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 5 | tr 'A-Z' 'a-z' >> "$TMP_DIR/dump.txt" || true
done <<< "$DEX_LIST"
echo "[done] DEX 字符串提取完成"

if [[ "$SO_COUNT" -gt 0 ]]; then
  echo "[loading] 正在提取 $SO_COUNT 个 native 库字符串（大包可能需要数分钟）..."
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 5 | tr 'A-Z' 'a-z' >> "$TMP_DIR/dump.txt" || true
  done <<< "$SO_LIST"
  echo "[done] native 字符串提取完成"
else
  echo "未发现 lib/*/*.so：跳过 native 字符串扫描。"
fi

DUMP_LINES="$(grep -c . "$TMP_DIR/dump.txt" 2>/dev/null || true)"
echo "字符串总行数：$DUMP_LINES"

# 先用固定字符串预过滤，避免在数百万行字符串上重复跑复杂正则
cat > "$TMP_DIR/keys.txt" <<'EOF'
isrooted
/sbin/su
/system/bin/su
/system/xbin/su
superuser
busybox
magisk
test-keys
rootbeer
checkroot
detectroot
rootcheck
which su
su -c
goldfish
ranchu
qemu
generic_x86
isemulator
checkemulator
genymotion
bluestacks
bignox
nox_player
ro.build.model
tracerpid
ptrace
/proc/self/status
isdebuggerconnected
waitfordebugger
antidebug
anti-debug
anti debug
android.os.debug
frida
libgadget
gadget.so
gum-js-loop
xposed
lsposed
edxposed
substrate
libhooker
/proc/self/maps
riru
zygisk
get_signatures
checksignatures
verifysignature
safetynet
playintegrity
integritymanager
attestation
tamper
signature
EOF
echo "[loading] 正在按关键字预过滤（固定字符串匹配，速度较快）..."
grep -Fa -f "$TMP_DIR/keys.txt" "$TMP_DIR/dump.txt" > "$TMP_DIR/filtered.txt" 2>/dev/null || true
FILTERED_LINES="$(grep -c . "$TMP_DIR/filtered.txt" 2>/dev/null || true)"
echo "[done] 预过滤完成：$FILTERED_LINES 行候选"

# ---------- 分类扫描 ----------
echo "[loading] 正在匹配对抗特征..."
report_cat root "Root 检测" '/system/(bin|xbin)/su|/sbin/su|superuser\.apk|busybox|magisk|test-keys|rootbeer|isrooted|checkroot|detectroot|rootcheck|su -c|which su'
report_cat emulator "模拟器检测" 'goldfish|ranchu|qemu|generic_x86|ro\.kernel\.qemu|isemulator|checkemulator|genymotion|bluestacks|com\.bignox|bignox|nox_player|ro\.build\.model[^|]*sdk'
report_cat antidebug "反调试" '(^|[^a-z_])ptrace([^a-z_]|$)|tracerpid|/proc/self/status|isdebuggerconnected|waitfordebugger|anti.?debug|android\.os\.debug'
report_cat hook "Hook / Frida / Xposed 检测" '(^|[^a-z])frida([^a-z]|$)|libgadget|gadget\.so|gum-js-loop|(^|[^a-z])xposed|lsposed|edxposed|substrate|libhooker|/proc/self/maps|riru|zygisk'
report_cat integrity "完整性 / 签名校验" 'get_signatures|checksignatures|verifysignature|safetynet|playintegrity|integritymanager|attestation|tamper|signature.?check|check.?signature'
echo "[done] 特征匹配完成"

print_cat() {
  local key="$1" label="$2" file="$TMP_DIR/$1.txt" total kinds
  total="$(sum_cat "$file")"
  kinds="$(grep -c . "$file" 2>/dev/null || true)"
  if [[ "$kinds" -eq 0 ]]; then
    echo "$label：未命中"
    return
  fi
  echo "$label：$total 处，$kinds 种"
  awk -v max="$MAX" 'NR <= max' "$file" \
    | awk -F'|' '{printf "  - %-6s %s\n", $1, $2}'
  if [[ "$kinds" -gt "$MAX" ]]; then
    echo "  ...（其余 $((kinds - MAX)) 种已省略）"
  fi
}

echo "------------------------------------------------------------"
print_cat root "Root 检测"
print_cat emulator "模拟器检测"
print_cat antidebug "反调试"
print_cat hook "Hook / Frida / Xposed 检测"
print_cat integrity "完整性 / 签名校验"

ROOT_CNT="$(sum_cat "$TMP_DIR/root.txt")"
EMU_CNT="$(sum_cat "$TMP_DIR/emulator.txt")"
ANTI_CNT="$(sum_cat "$TMP_DIR/antidebug.txt")"
HOOK_CNT="$(sum_cat "$TMP_DIR/hook.txt")"
INTEG_CNT="$(sum_cat "$TMP_DIR/integrity.txt")"
TOTAL=$((ROOT_CNT + EMU_CNT + ANTI_CNT + HOOK_CNT + INTEG_CNT))

echo "------------------------------------------------------------"
echo "【结论】"
if [[ "$TOTAL" -eq 0 ]]; then
  echo "  - 未发现明显 Root/模拟器/反调试/Hook/完整性校验特征。"
  echo "  - 这不代表没有防护：自定义实现、混淆、native 动态拼接都可能绕过字符串匹配。"
  echo "  说明：本脚本只做字符串级特征识别，不做脱壳、不做运行时验证。"
  exit 1
fi

CAT_HIT=0
[[ "$ROOT_CNT" -gt 0 ]] && { echo "  ⚠ Root 检测：$ROOT_CNT 处（例如 su 路径、Magisk、RootBeer）。"; CAT_HIT=$((CAT_HIT + 1)); }
[[ "$EMU_CNT" -gt 0 ]] && { echo "  ⚠ 模拟器检测：$EMU_CNT 处（例如 goldfish/qemu、Genymotion）。"; CAT_HIT=$((CAT_HIT + 1)); }
[[ "$ANTI_CNT" -gt 0 ]] && { echo "  ⚠ 反调试：$ANTI_CNT 处（例如 ptrace、TracerPid、isDebuggerConnected）。"; CAT_HIT=$((CAT_HIT + 1)); }
[[ "$HOOK_CNT" -gt 0 ]] && { echo "  ⚠ Hook 检测：$HOOK_CNT 处（例如 Frida、Xposed、/proc/self/maps）。"; CAT_HIT=$((CAT_HIT + 1)); }
[[ "$INTEG_CNT" -gt 0 ]] && { echo "  ⚠ 完整性/签名校验：$INTEG_CNT 处（例如 getSignatures、SafetyNet、Play Integrity）。"; CAT_HIT=$((CAT_HIT + 1)); }

echo "  - 共命中 $CAT_HIT 类特征。命中只说明代码中包含相关字符串或调用线索，不等于防护已启用或有效。"
echo "  - 常见误报：第三方 SDK 自带检测、调试日志、错误提示文案、测试代码。"
echo "  - 建议：结合调用链定位实现，再用动态手段确认检测触发条件与绕过难度。"
echo "  说明：本脚本不修改样本、不联网、不执行样本，也不验证实际防护强度。"
exit 0
