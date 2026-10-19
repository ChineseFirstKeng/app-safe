#!/usr/bin/env bash
#
# 03-unzip-inspect.sh —— 通用静态分析：归档 / APK 容器结构检查
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   不运行 App、不反编译，只读取 ZIP 目录，回答：
#     - 这是 APK 还是其他归档（AAB/IPA/APKS/JAR/普通 ZIP）？
#     - APK 结构是否完整（Manifest / 资源索引 / DEX）？
#     - 有几个 classes*.dex，各自多大？
#     - 包含哪些 ABI、多少个 .so？
#     - 是否存在 v1 签名相关文件？
#     - 解压后总大小、压缩率、顶层条目分布如何？
#     - 是否存在重复条目或可疑路径？
#
#   检查逻辑不做框架假设：不假设 Flutter / React Native / Unity / 原生，
#   只报告通用结构特征。也不解压、不反编译、不判断代码安全性。
#
# 依赖：
#   unzip
#   缺少时明确提示安装方式并退出，不会静默跳过检查。
#
# 用法：
#   ./03-unzip-inspect.sh <文件路径>
#
# 退出码：
#   0 = 结构符合完整 APK（Manifest + resources.arsc + DEX）
#   1 = 是 ZIP 但不是完整 APK，或 APK 结构不完整
#   2 = 参数/依赖错误
#
set -euo pipefail
export LC_ALL=C

TARGET="${1:-}"

if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  echo "用法: $0 <文件路径>"
  exit 2
fi
if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] 文件不存在: $TARGET" >&2
  exit 2
fi
if ! command -v unzip >/dev/null 2>&1; then
  echo "[FAIL] 缺少工具: unzip" >&2
  echo "       安装提示: macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip" >&2
  exit 2
fi

# ---------- 1. 读取 ZIP 目录（不落盘解压） ----------
TMP_ENTRIES="$(mktemp "${TMPDIR:-/tmp}/archive-entries.XXXXXX")"
trap 'rm -f "$TMP_ENTRIES"' EXIT

if ! unzip -Z1 "$TARGET" > "$TMP_ENTRIES" 2>/dev/null; then
  echo "============================================================"
  echo "静态分析 03：归档 / APK 容器结构检查"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  echo "无法读取 ZIP 目录：这个文件不是有效的 ZIP/APK，或已经损坏。"
  echo "建议：先确认文件类型和来源。"
  exit 1
fi

ENTRY_COUNT="$(grep -c . "$TMP_ENTRIES" || true)"

# ---------- 2. 通用归档统计 ----------
COMPRESSED_SIZE="$(wc -c < "$TARGET" | tr -d ' ')"
TOTAL_UNCOMPRESSED="$(unzip -l "$TARGET" 2>/dev/null | awk '$NF ~ /^files?$/ {print $1}' | tail -1 || true)"
COMPRESSION_RATIO="?"
if [[ "$TOTAL_UNCOMPRESSED" =~ ^[0-9]+$ && "$TOTAL_UNCOMPRESSED" -gt 0 ]]; then
  COMPRESSION_RATIO="$(awk -v c="$COMPRESSED_SIZE" -v u="$TOTAL_UNCOMPRESSED" \
    'BEGIN { printf "%.1f%%", c * 100 / u }')"
fi

TOP_LEVEL="$(awk -F/ '
  {
    if ($0 ~ /\/$/)          print $1 "/";
    else if (NF == 1)        print "(root)";
    else                     print $1 "/";
  }' "$TMP_ENTRIES" | sort | uniq -c | sort -nr | head -10 || true)"

# 重复条目：同一个路径在 ZIP 目录中出现多次。
# 不同解析器可能选择不同副本，是 APK 篡改/畸形包的常见手法之一。
DUPES="$(sort "$TMP_ENTRIES" | uniq -d || true)"
DUP_COUNT="$(printf '%s\n' "$DUPES" | grep -c . || true)"

# 可疑路径：绝对路径、路径穿越（同时覆盖 / 和 \ 两种分隔符）。
SUSPICIOUS="$(grep -E '(^/|(^|/)\.\.(/|$)|(^|\\)\.\.(\\|$)|^[A-Za-z]:\\)' "$TMP_ENTRIES" || true)"
SUSPICIOUS_COUNT="$(printf '%s\n' "$SUSPICIOUS" | grep -c . || true)"

# ---------- 3. 归档类型判定 ----------
HAS_ROOT_MANIFEST=false
HAS_ARSC=false
HAS_AAB=false
HAS_IPA=false
HAS_APKS=false
HAS_JAR=false

if grep -qx 'AndroidManifest.xml' "$TMP_ENTRIES"; then
  HAS_ROOT_MANIFEST=true
fi
if grep -qx 'resources.arsc' "$TMP_ENTRIES"; then
  HAS_ARSC=true
fi

if grep -qx 'BundleConfig.pb' "$TMP_ENTRIES"; then
  HAS_AAB=true
fi
if grep -q '^base/manifest/AndroidManifest\.xml$' "$TMP_ENTRIES"; then
  HAS_AAB=true
fi

if grep -qE '^Payload/[^/]+\.app/Info\.plist$' "$TMP_ENTRIES"; then
  HAS_IPA=true
fi

if grep -qx 'toc.pb' "$TMP_ENTRIES" && grep -qE '\.apk$' "$TMP_ENTRIES"; then
  HAS_APKS=true
fi

if grep -qx 'META-INF/MANIFEST.MF' "$TMP_ENTRIES" && grep -qE '\.class$' "$TMP_ENTRIES"; then
  HAS_JAR=true
fi

ARCHIVE_TYPE="ZIP"
if [[ "$HAS_ROOT_MANIFEST" == true ]]; then
  ARCHIVE_TYPE="APK"
elif [[ "$HAS_AAB" == true ]]; then
  ARCHIVE_TYPE="AAB"
elif [[ "$HAS_IPA" == true ]]; then
  ARCHIVE_TYPE="IPA"
elif [[ "$HAS_APKS" == true ]]; then
  ARCHIVE_TYPE="APKS"
elif [[ "$HAS_JAR" == true ]]; then
  ARCHIVE_TYPE="JAR"
fi

# ---------- 4. APK 专项结构 ----------
DEX_LIST=""
DEX_COUNT=0
ABI_LIST=""
NATIVE_COUNT=0
HAS_V1_MANIFEST=false
HAS_V1_SF=false
V1_CERT_COUNT=0
MANIFEST_SIZE=""
ARSC_SIZE=""

entry_size() {
  local entry="$1"
  local output
  output="$(unzip -l "$TARGET" "$entry" 2>/dev/null || true)"
  # unzip -l 的第 4 行是第一个匹配条目的长度字段
  awk 'NR==4 {print $1}' <<<"$output"
}

if [[ "$ARCHIVE_TYPE" == "APK" ]]; then
  MANIFEST_SIZE="$(entry_size 'AndroidManifest.xml')"
  ARSC_SIZE="$(entry_size 'resources.arsc')"

  DEX_LIST="$(grep -E '^classes([0-9]+)?\.dex$' "$TMP_ENTRIES" | sort || true)"
  DEX_COUNT="$(printf '%s\n' "$DEX_LIST" | grep -c . || true)"

  ABI_LIST="$(grep -oE '^lib/[^/]+/' "$TMP_ENTRIES" | cut -d/ -f2 | sort -u || true)"
  NATIVE_COUNT="$(grep -cE '^lib/[^/]+/.+\.so$' "$TMP_ENTRIES" || true)"

  if grep -qx 'META-INF/MANIFEST.MF' "$TMP_ENTRIES"; then
    HAS_V1_MANIFEST=true
  fi
  if grep -qE '^META-INF/.*\.SF$' "$TMP_ENTRIES"; then
    HAS_V1_SF=true
  fi
  V1_CERT_COUNT="$(grep -cE '^META-INF/.*\.(RSA|DSA|EC)$' "$TMP_ENTRIES" || true)"
fi

# ---------- 5. 输出 ----------
echo "============================================================"
echo "静态分析 03：归档 / APK 容器结构检查"
echo "目标：$TARGET"
echo "============================================================"
echo "归档类型          : $ARCHIVE_TYPE"
echo "ZIP 条目总数      : $ENTRY_COUNT"
echo "压缩后大小        : $COMPRESSED_SIZE 字节"
echo "解压后总大小      : ${TOTAL_UNCOMPRESSED:-?} 字节"
echo "压缩率            : $COMPRESSION_RATIO"
echo "重复条目          : $DUP_COUNT"
echo "可疑路径          : $SUSPICIOUS_COUNT"

echo "顶层条目分布（前 10）："
if [[ -n "$TOP_LEVEL" ]]; then
  printf '%s\n' "$TOP_LEVEL" | sed 's/^/  /'
else
  echo "  (无)"
fi

if [[ "$DUP_COUNT" -gt 0 ]]; then
  echo "重复条目列表（前 10）："
  printf '%s\n' "$DUPES" | head -10 | sed 's/^/  - /'
fi

if [[ "$SUSPICIOUS_COUNT" -gt 0 ]]; then
  echo "可疑路径列表（前 10）："
  printf '%s\n' "$SUSPICIOUS" | head -10 | sed 's/^/  - /'
fi

if [[ "$ARCHIVE_TYPE" == "APK" ]]; then
  echo "------------------------------------------------------------"
  echo "APK 结构："
  echo "  AndroidManifest.xml : $HAS_ROOT_MANIFEST (${MANIFEST_SIZE:-?} 字节)"
  echo "  resources.arsc      : $HAS_ARSC (${ARSC_SIZE:-?} 字节)"
  echo "  classes*.dex        : $DEX_COUNT 个"
  if [[ "$DEX_COUNT" -gt 0 ]]; then
    while IFS= read -r dex; do
      [[ -z "$dex" ]] && continue
      size="$(entry_size "$dex")"
      echo "    - $dex: ${size:-?} 字节"
    done <<<"$DEX_LIST"
  fi

  echo "  原生库 .so          : $NATIVE_COUNT 个"
  if [[ -n "$ABI_LIST" ]]; then
    echo "  支持的 ABI          : $(printf '%s' "$ABI_LIST" | paste -sd, -)"
    while IFS= read -r abi; do
      [[ -z "$abi" ]] && continue
      count="$(grep -cE "^lib/${abi}/.+\.so$" "$TMP_ENTRIES" || true)"
      echo "    - $abi: $count 个 .so"
    done <<<"$ABI_LIST"
  else
    echo "  支持的 ABI          : (无)"
  fi

  echo "  v1 MANIFEST.MF      : $HAS_V1_MANIFEST"
  echo "  v1 .SF 文件         : $HAS_V1_SF"
  echo "  v1 证书文件         : $V1_CERT_COUNT 个"
fi

# ---------- 6. 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

case "$ARCHIVE_TYPE" in
  APK)
    if [[ "$HAS_ROOT_MANIFEST" == true && "$HAS_ARSC" == true && "$DEX_COUNT" -gt 0 ]]; then
      echo "结构符合完整 APK：Manifest、resources.arsc 和 DEX 都存在。"
    elif [[ "$HAS_ROOT_MANIFEST" == true && "$HAS_ARSC" == true && "$DEX_COUNT" -eq 0 ]]; then
      echo "这是 APK，但没有 classes*.dex。"
      echo "可能是 split/配置 APK、仅含资源的包，或不含代码的特殊包；"
      echo "如果是 split APK，需要与 base.apk 一起分析。"
    elif [[ "$HAS_ROOT_MANIFEST" == true && "$HAS_ARSC" == false && "$DEX_COUNT" -gt 0 ]]; then
      echo "这是 APK，但有 DEX、缺少 resources.arsc。"
      echo "结构可能不完整，建议确认构建方式，或与同版本官方包对比。"
    else
      echo "这是 APK，但缺少 resources.arsc 和 classes*.dex。"
      echo "可能是 split/配置 APK、损坏包或特殊构建。"
    fi

    if [[ "$DUP_COUNT" -gt 0 ]]; then
      echo "检测到重复 ZIP 条目：不同解析器可能选择不同副本，需人工确认。"
    fi
    if [[ "$SUSPICIOUS_COUNT" -gt 0 ]]; then
      echo "检测到绝对路径或路径穿越条目：需人工确认。"
    fi
    if [[ "$V1_CERT_COUNT" -gt 0 || "$HAS_V1_MANIFEST" == true ]]; then
      echo "存在 v1 签名相关文件，但“文件存在”不等于“v1 实际生效”，最终以 apksigner 的验证结果为准。"
    else
      echo "未见 v1 签名文件：可能只使用 v2/v3 签名（APK Signature Scheme 不需要 META-INF 三件套）。"
    fi

    echo "后续可继续检查："
    echo "  1) 签名与证书（使用 apksigner）；"
    echo "  2) 包名/版本/权限（使用 aapt dump badging）；"
    echo "  3) 可读 Manifest/资源（使用 apkanalyzer / aapt2 / apktool）；"
    echo "  4) 代码（使用 jadx 或 dexdump）。"

    if [[ "$HAS_ARSC" == true && "$DEX_COUNT" -gt 0 ]]; then
      exit 0
    else
      exit 1
    fi
    ;;

  AAB)
    echo "这是 Android App Bundle（AAB），不是可直接安装的 APK。"
    echo "03 的 APK 结构检查不适用；请先用 bundletool 生成 APK 集，再逐个检查。"
    exit 1
    ;;

  IPA)
    echo "这是 iOS IPA，不是 Android APK。"
    echo "03 的 APK 结构检查不适用；请解包 Payload/*.app，按 iOS 流程分析。"
    exit 1
    ;;

  APKS)
    echo "这是 APK 集合（.apks），不是单个 APK。"
    echo "请先解出 base.apk 和各个 split APK，再逐个做结构检查。"
    exit 1
    ;;

  JAR)
    echo "这是 Java JAR，不是 Android APK。"
    echo "03 的 APK 结构检查不适用；可用 jadx/unzip 分析字节码。"
    exit 1
    ;;

  *)
    echo "这不是 APK：ZIP 根目录没有 AndroidManifest.xml。"
    echo "以上是通用 ZIP 结构信息；如果这是外层容器，请解压后对内部 APK 再跑一次。"
    exit 1
    ;;
esac
