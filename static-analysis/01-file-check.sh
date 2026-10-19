#!/usr/bin/env bash
#
# 01-file-check.sh —— 通用静态分析：文件/容器类型识别
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   拿到任意样本时，先回答“它到底是什么容器”。
#   只读文件头和 ZIP 目录，不运行、不解包、不修改目标文件。
#
#   可识别：
#     APK   —— Android 安装包（ZIP + 根目录 AndroidManifest.xml）
#     AAB   —— Android App Bundle（发布格式，不是可直接安装的 APK）
#     IPA   —— iOS 应用包（ZIP + Payload/*.app/Info.plist）
#     APKS  —— APK 集合（ZIP + toc.pb + *.apk）
#     JAR   —— Java 归档（ZIP + META-INF/MANIFEST.MF + *.class）
#     ZIP   —— 普通 ZIP / 无法归类的归档
#     其他  —— 非 ZIP 容器或损坏文件
#
# 依赖：
#   file、unzip
#   缺少依赖时会明确提示安装方式并退出，不会静默跳过检查。
#
# 用法：
#   ./01-file-check.sh <文件路径>
#
# 退出码：
#   0 = 识别为 APK / AAB / IPA / APKS / JAR
#   1 = 是有效 ZIP，但无法归入上述类型
#   2 = 不是 ZIP/归档，或参数/依赖错误
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

# ---------- 依赖检查 ----------
need_tool() {
  local tool="$1"
  local hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[FAIL] 缺少工具: $tool" >&2
    echo "       安装提示: $hint" >&2
    exit 2
  fi
}

need_tool file  "macOS 通常自带；Linux: sudo apt install file / sudo dnf install file"
need_tool unzip "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"

# ---------- 基础元信息 ----------
FILE_DESC="$(file -b "$TARGET")"
MIME_TYPE="$(file -b --mime-type "$TARGET" 2>/dev/null || echo "unknown")"
SIZE_BYTES="$(wc -c < "$TARGET" | tr -d ' ')"
SIZE_HUMAN="$(numfmt --to=iec "$SIZE_BYTES" 2>/dev/null || echo "${SIZE_BYTES} 字节")"

# ---------- ZIP 目录探测 ----------
# file 的判断会因平台和 magic 数据库版本略有差异；
# 最终以“unzip 能不能读出目录”为准。
ENTRIES=""
IS_ZIP=false
if unzip -Z1 "$TARGET" >/dev/null 2>&1; then
  IS_ZIP=true
  ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
fi

ENTRY_COUNT=0
if [[ -n "$ENTRIES" ]]; then
  ENTRY_COUNT="$(printf '%s\n' "$ENTRIES" | grep -c . || true)"
fi

# ---------- 结构特征 ----------
HAS_ROOT_MANIFEST=false
HAS_DEX=false
HAS_ARSC=false
HAS_AAB=false
HAS_IPA=false
HAS_APKS=false
HAS_JAR=false

if [[ "$IS_ZIP" == true ]]; then
  if grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
    HAS_ROOT_MANIFEST=true
  fi
  if grep -qE '^classes([0-9]+)?\.dex$' <<<"$ENTRIES"; then
    HAS_DEX=true
  fi
  if grep -qx 'resources.arsc' <<<"$ENTRIES"; then
    HAS_ARSC=true
  fi

  # AAB：根目录 BundleConfig.pb，或 base/manifest/AndroidManifest.xml
  if grep -qx 'BundleConfig.pb' <<<"$ENTRIES"; then
    HAS_AAB=true
  fi
  if grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
    HAS_AAB=true
  fi

  # IPA：Payload/<App>.app/Info.plist
  if grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
    HAS_IPA=true
  fi

  # APKS：toc.pb + 至少一个 .apk
  if grep -qx 'toc.pb' <<<"$ENTRIES" && grep -qE '\.apk$' <<<"$ENTRIES"; then
    HAS_APKS=true
  fi

  # JAR：META-INF/MANIFEST.MF + 至少一个 .class
  if grep -qx 'META-INF/MANIFEST.MF' <<<"$ENTRIES" && grep -qE '\.class$' <<<"$ENTRIES"; then
    HAS_JAR=true
  fi
fi

# ---------- 归档类型判定 ----------
# 根目录出现 AndroidManifest.xml 就按 APK 处理；
# 是否缺少 dex/resources 由 03 进一步判断（兼容 split/资源包）。
ARCHIVE_TYPE="unknown"
if [[ "$IS_ZIP" == true ]]; then
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
  else
    ARCHIVE_TYPE="ZIP"
  fi
fi

# ---------- 输出 ----------
echo "============================================================"
echo "静态分析 01：文件/容器类型识别"
echo "目标：$TARGET"
echo "============================================================"
echo "file            : $FILE_DESC"
echo "MIME            : $MIME_TYPE"
echo "大小            : $SIZE_BYTES 字节 ($SIZE_HUMAN)"
echo "ZIP 容器        : $IS_ZIP"
echo "ZIP 条目数      : $ENTRY_COUNT"
echo "归档类型        : $ARCHIVE_TYPE"

if [[ "$IS_ZIP" == true ]]; then
  echo "根目录 Manifest : $HAS_ROOT_MANIFEST"
  echo "classes*.dex    : $HAS_DEX"
  echo "resources.arsc  : $HAS_ARSC"
  echo "AAB 特征        : $HAS_AAB"
  echo "IPA 特征        : $HAS_IPA"
  echo "APKS 特征       : $HAS_APKS"
  echo "JAR 特征        : $HAS_JAR"
fi

# ---------- 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

case "$ARCHIVE_TYPE" in
  APK)
    echo "这是 Android APK：ZIP 容器 + 根目录 AndroidManifest.xml。"
    if [[ "$HAS_DEX" == false ]]; then
      echo "未发现 classes*.dex：可能是仅含资源的 APK，或 split/配置 APK。"
      echo "如果是 split APK，需要把 base.apk 和各 split APK 一起分析。"
    fi
    if [[ "$HAS_ARSC" == false ]]; then
      echo "未发现 resources.arsc：结构可能不完整，建议进一步检查资源索引或确认是否为 split APK。"
    fi
    echo "后续可继续检查：样本指纹、容器结构、签名与证书。"
    exit 0
    ;;

  AAB)
    echo "这是 Android App Bundle（AAB），不是可直接安装的 APK。"
    echo "下一步："
    echo "  1) 用 bundletool 生成 APK 集；"
    echo "  2) 对生成的 base.apk / split APK 分别做指纹、结构和签名检查。"
    exit 0
    ;;

  IPA)
    echo "这是 iOS IPA（ZIP 容器）。"
    echo "下一步："
    echo "  1) 解包 Payload/*.app；"
    echo "  2) 用 plutil 查看 Info.plist；"
    echo "  3) 用 codesign 查看签名；"
    echo "  4) 用 otool 检查 Mach-O 是否加密（cryptid）。"
    echo "注意：App Store 分发的 Mach-O 可能加密，静态分析前可能需要脱壳。"
    exit 0
    ;;

  APKS)
    echo "这是 APK 集合（.apks），不是单个 APK。"
    echo "下一步：先解出 base.apk 和各个 split APK，再逐个做指纹、结构和签名检查。"
    exit 0
    ;;

  JAR)
    echo "这是 Java JAR（ZIP 容器）。"
    echo "下一步：用 unzip/jadx 分析字节码；apksigner 不适用于 JAR。"
    exit 0
    ;;

  ZIP)
    echo "这是普通 ZIP，未发现 APK/AAB/IPA/APKS/JAR 的结构特征。"
    echo "可能原因："
    echo "  - 普通压缩包被改名为 .apk/.ipa；"
    echo "  - 这是 split 包、资源包或外层容器；"
    echo "  - 样本本身不是移动应用。"
    echo "建议：确认来源；如果是外层容器，先解压再逐个分析内部文件。"
    exit 1
    ;;

  *)
    echo "这不是可识别的 ZIP/APK/AAB/IPA/APKS/JAR 容器。"
    echo "可能是其他格式、加密容器或已损坏文件。"
    echo "建议：不要继续按 Android APK 流程分析，先确认样本来源和真实格式。"
    exit 2
    ;;
esac
