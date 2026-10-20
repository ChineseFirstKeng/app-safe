#!/usr/bin/env bash
#
# 17-aab-apks-pipeline.sh —— 通用静态分析：AAB / APKS 结构与拆分产物处理
#
# 用途：
#   1. 识别 AAB 的模块、DEX、native 库、资源分布；可选调用 bundletool
#      生成 universal APK，便于后续用 APK 脚本继续分析。
#   2. 识别 APKS 内的 base/split/standalone 包，按 ABI、密度、语言分类，
#      可选解包到指定目录。
#   3. 不覆盖：AAB 的 protobuf Manifest 语义解析（需 bundletool/aapt2 转换）、
#      split APK 的完整合并、动态下发模块。
#
# 参数：
#   <AAB|APKS>      必填
#                   格式：存在且可读的 AAB 或 APKS 文件
#                   示例：./app.aab
#                   说明：其他类型会被识别并提示不适用，exit 2
#
#   --out DIR       可选
#                   格式：目录路径（不存在时自动创建）
#                   默认：./aab-apks-out
#                   示例：--out ./out
#                   说明：bundletool 产物或 APKS 解包目录
#
#   --bundletool P  可选
#                   格式：存在的 bundletool JAR 路径
#                   默认：无（依次尝试 BUNDLETOOL 环境变量和 PATH 中的 bundletool）
#                   示例：--bundletool ./bundletool.jar
#                   说明：仅 AAB 需要；缺失时只做结构分析并 exit 1
#
#   --extract       可选
#                   格式：布尔开关，不带值
#                   默认：关闭
#                   说明：APKS 输入时把全部内容解包到 --out 目录
#
#   --max N         可选
#                   格式：非负整数（^[0-9]+$）
#                   默认：40
#                   示例：--max 100
#                   说明：每个列表最多显示 N 行
#
# 依赖：
#   unzip、file、grep、awk、find、sort
#   AAB 转换需要 java 与 bundletool（JAR）；aapt2 为可选。
#   缺少必需工具时：打印安装提示并 exit 2，不静默跳过。
#
# 用法：
#   ./17-aab-apks-pipeline.sh <AAB|APKS>
#   ./17-aab-apks-pipeline.sh <APKS> --extract --out ./splits
#   ./17-aab-apks-pipeline.sh <AAB> --bundletool ./bundletool.jar --out ./out
#   ./17-aab-apks-pipeline.sh --help
#
# 输出：
#   输入类型、模块/拆分清单、DEX/native/资源统计、转换结果、【结论】。
#   临时文件放在 mktemp 目录，脚本退出时删除。
#
# 退出码：
#   0 = 结构分析完成，且请求的转换/解包已完成
#   1 = 分析完成但转换未执行（例如 AAB 缺少 bundletool）
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

MAX=40
OUT_DIR="./aab-apks-out"
# 先保存环境变量，避免下面的脚本变量覆盖外部传入的 BUNDLETOOL
BUNDLETOOL_ENV="${BUNDLETOOL:-}"
BUNDLETOOL=""
EXTRACT=false
TARGET=""

usage() {
  cat <<'EOF'
用法: ./17-aab-apks-pipeline.sh <AAB|APKS> [--out DIR] [--bundletool P] [--extract] [--max N]

参数:
  <AAB|APKS>       必填。格式: AAB 或 APKS 文件路径。
  --out DIR        可选。格式: 目录路径。默认: ./aab-apks-out
  --bundletool P   可选。格式: bundletool JAR 路径。默认: 自动查找
  --extract        可选。布尔开关。APKS 输入时解包到 --out。
  --max N          可选。格式: 非负整数。默认: 40
  -h, --help       显示本帮助。

退出码:
  0 = 分析完成且请求的转换/解包完成
  1 = 分析完成但转换未执行
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
    --out)
      if [[ -z "${2:-}" ]]; then
        echo "[FAIL] --out 需要一个目录路径。" >&2
        usage >&2
        exit 2
      fi
      OUT_DIR="$2"
      shift 2
      ;;
    --bundletool)
      if [[ -z "${2:-}" || ! -f "$2" ]]; then
        echo "[FAIL] --bundletool 需要存在且可读的 JAR 路径。" >&2
        usage >&2
        exit 2
      fi
      BUNDLETOOL="$2"
      shift 2
      ;;
    --extract)
      EXTRACT=true
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
  echo "[FAIL] 缺少必填参数 <AAB|APKS>。" >&2
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

need_tool unzip "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"
need_tool grep  "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk   "macOS 通常自带；Linux: sudo apt install gawk / mawk"
need_tool find  "macOS 通常自带；Linux: sudo apt install findutils"
need_tool sort  "macOS 通常自带；Linux: sudo apt install coreutils"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aab-apks.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[loading] 正在读取容器条目..."
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
ENTRY_COUNT="$(printf '%s\n' "$ENTRIES" | grep -c . || true)"
echo "[done] 条目读取完成：$ENTRY_COUNT 个"

if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  echo "[FAIL] 输入不是有效的 ZIP 容器，或文件已损坏。" >&2
  exit 2
fi

INPUT_TYPE="UNKNOWN"
if grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  INPUT_TYPE="APK"
elif grep -qx 'BundleConfig.pb' <<<"$ENTRIES" || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
  INPUT_TYPE="AAB"
elif grep -qx 'toc.pb' <<<"$ENTRIES" && grep -q '\.apk$' <<<"$ENTRIES"; then
  INPUT_TYPE="APKS"
elif grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
  INPUT_TYPE="IPA"
fi

if [[ "$INPUT_TYPE" != "AAB" && "$INPUT_TYPE" != "APKS" ]]; then
  case "$INPUT_TYPE" in
    APK) echo "[FAIL] 输入是 APK，请直接对 APK 运行对应的分析脚本。" >&2 ;;
    IPA) echo "[FAIL] 输入是 IPA，请使用 iOS 分析脚本。" >&2 ;;
    *)   echo "[FAIL] 输入既不是 AAB 也不是 APKS。" >&2 ;;
  esac
  exit 2
fi

echo "============================================================"
echo "静态分析 17：AAB / APKS 结构与拆分产物处理"
echo "目标：$TARGET"
echo "输入类型：$INPUT_TYPE"
echo "条目数：$ENTRY_COUNT"
echo "参数：max=$MAX out=$OUT_DIR extract=$EXTRACT"
echo "============================================================"

if [[ "$INPUT_TYPE" == "APKS" ]]; then
  # ---------- APKS ----------
  SPLITS="$(printf '%s\n' "$ENTRIES" | grep -Ei '\.apk$' | sort || true)"
  SPLIT_COUNT="$(printf '%s\n' "$SPLITS" | grep -c . || true)"
  echo "APKS 拆分包：$SPLIT_COUNT 个"
  printf '%s\n' "$SPLITS" | awk -v max="$MAX" 'NR <= max' | sed 's/^/  - /'
  if [[ "$SPLIT_COUNT" -gt "$MAX" ]]; then
    echo "  ...（其余 $((SPLIT_COUNT - MAX)) 个已省略）"
  fi

  echo "------------------------------------------------------------"
  echo "拆分类型统计（按文件名启发式）："
  abi_cnt="$(printf '%s\n' "$SPLITS" | grep -ciE 'arm64|armeabi|x86|mips' || true)"
  dens_cnt="$(printf '%s\n' "$SPLITS" | grep -ciE 'ldpi|mdpi|hdpi|xhdpi|xxhdpi|xxxhdpi|tvdpi' || true)"
  lang_cnt="$(printf '%s\n' "$SPLITS" | grep -ciE 'config\.[a-z]{2}([_-]|\.)|-zh|-en' || true)"
  base_cnt="$(printf '%s\n' "$SPLITS" | grep -ciE 'base[-.]?(master|apk)|standalone' || true)"
  echo "  - ABI 相关：$abi_cnt"
  echo "  - 密度相关：$dens_cnt"
  echo "  - 语言相关：$lang_cnt"
  echo "  - base/standalone：$base_cnt"

  # 尝试读取 base APK 的包信息（aapt2 可选）
  AAPT2=""
  for cand in \
    "$HOME/Library/Android/sdk/build-tools/34.0.0/aapt2" \
    "$HOME/Library/Android/sdk/build-tools/31.0.0/aapt2"; do
    [[ -x "$cand" ]] && AAPT2="$cand" && break
  done
  if [[ -z "$AAPT2" ]] && command -v aapt2 >/dev/null 2>&1; then
    AAPT2="$(command -v aapt2)"
  fi

  BASE_SPLIT="$(printf '%s\n' "$SPLITS" | grep -Ei '(^|/)(base-master|base)\.apk$|standalone[^/]*\.apk$' | awk 'NR == 1')"
  if [[ -n "$AAPT2" && -n "$BASE_SPLIT" ]]; then
    unzip -p "$TARGET" "$BASE_SPLIT" > "$TMP_DIR/base.apk" 2>/dev/null || true
    if [[ -s "$TMP_DIR/base.apk" ]]; then
      echo "------------------------------------------------------------"
      echo "base 包信息（aapt2）："
      AAPT_OUT="$("$AAPT2" dump badging "$TMP_DIR/base.apk" 2>/dev/null | grep -E '^package:|^sdkVersion:|^targetSdkVersion:' || true)"
      if [[ -z "$AAPT_OUT" ]]; then
        echo "  (aapt2 解析失败：base 包不是有效 APK，或 Manifest 已损坏)"
      else
        printf '%s\n' "$AAPT_OUT" | sed 's/^/  /'
      fi
    fi
  else
    echo "------------------------------------------------------------"
    echo "base 包信息：未找到 base APK 或 aapt2，未解析 Manifest。"
  fi

  if [[ "$EXTRACT" == true ]]; then
    echo "[loading] 正在解包 APKS 到 $OUT_DIR（文件较大时可能需要一段时间）..."
    mkdir -p "$OUT_DIR"
    unzip -oq "$TARGET" -d "$OUT_DIR" 2>/dev/null
    echo "[done] 解包完成：$(find "$OUT_DIR" -type f | wc -l | tr -d ' ') 个文件"
  else
    echo "------------------------------------------------------------"
    echo "未指定 --extract：仅做结构分析，未写盘。"
  fi

  echo "------------------------------------------------------------"
  echo "【结论】"
  echo "  - APKS 共包含 $SPLIT_COUNT 个 APK 拆分，需按设备配置组合分析。"
  echo "  - 建议：对 base-master/base.apk 先跑 Manifest/DEX 审计，再对 ABI split 跑 native 审计。"
  if [[ "$EXTRACT" == true ]]; then
    echo "  - 已解包到：$OUT_DIR"
    exit 0
  fi
  echo "  说明：本脚本只做结构分类，不合并 split，也不重建完整安装包。"
  exit 0
fi

# ---------- AAB ----------
MODULES="$(printf '%s\n' "$ENTRIES" | grep -E '^[^/]+/manifest/AndroidManifest\.xml$' | cut -d'/' -f1 | sort -u || true)"
MODULE_COUNT="$(printf '%s\n' "$MODULES" | grep -c . || true)"
echo "AAB 模块：$MODULE_COUNT 个"
printf '%s\n' "$MODULES" | awk -v max="$MAX" 'NR <= max' | sed 's/^/  - /'

echo "------------------------------------------------------------"
echo "各模块内容统计（DEX / native / res / assets）："
while IFS= read -r mod; do
  [[ -n "$mod" ]] || continue
  dex="$(printf '%s\n' "$ENTRIES" | grep -cE "^${mod}/dex/classes[0-9]*\.dex$" || true)"
  so="$(printf '%s\n' "$ENTRIES" | grep -cE "^${mod}/lib/[^/]+/.+\.so$" || true)"
  res="$(printf '%s\n' "$ENTRIES" | grep -cE "^${mod}/res/" || true)"
  assets="$(printf '%s\n' "$ENTRIES" | grep -cE "^${mod}/assets/" || true)"
  printf '  - %-20s DEX=%-4s .so=%-4s res=%-4s assets=%-4s\n' "$mod" "$dex" "$so" "$res" "$assets"
done <<< "$MODULES"

BUNDLETOOL_JAR="$BUNDLETOOL"
if [[ -z "$BUNDLETOOL_JAR" && -n "$BUNDLETOOL_ENV" && -f "$BUNDLETOOL_ENV" ]]; then
  BUNDLETOOL_JAR="$BUNDLETOOL_ENV"
fi
if [[ -z "$BUNDLETOOL_JAR" ]] && command -v bundletool >/dev/null 2>&1; then
  BUNDLETOOL_JAR="$(command -v bundletool)"
fi

echo "------------------------------------------------------------"
if [[ -n "$BUNDLETOOL_JAR" ]]; then
  if ! command -v java >/dev/null 2>&1; then
    echo "[FAIL] 找到 bundletool，但缺少 java。" >&2
    echo "       安装提示: macOS: brew install openjdk；Linux: sudo apt install default-jre" >&2
    exit 2
  fi
  mkdir -p "$OUT_DIR"
  APKS_OUT="$OUT_DIR/$(basename "${TARGET%.aab}").apks"
  echo "[loading] 正在用 bundletool 生成 universal APKS（可能需要一段时间）..."
  if java -jar "$BUNDLETOOL_JAR" build-apks \
      --bundle="$TARGET" --output="$APKS_OUT" --mode=universal --overwrite >/dev/null 2>"$TMP_DIR/bundletool.log"; then
    echo "[done] 生成完成：$APKS_OUT"
    if unzip -Z1 "$APKS_OUT" 2>/dev/null | grep -qx 'universal.apk'; then
      unzip -oq "$APKS_OUT" 'universal.apk' -d "$OUT_DIR" 2>/dev/null || true
      echo "[done] 已解出：$OUT_DIR/universal.apk"
    fi
  else
    echo "[FAIL] bundletool 执行失败：" >&2
    awk 'NR <= 8' "$TMP_DIR/bundletool.log" | sed 's/^/       /' >&2 || true
    exit 2
  fi
else
  echo "未找到 bundletool：未生成 APK。"
  echo "  安装/使用方式："
  echo "    1) 下载 bundletool-all-*.jar：https://github.com/google/bundletool/releases"
  echo "    2) ./17-aab-apks-pipeline.sh <AAB> --bundletool /path/to/bundletool.jar --out $OUT_DIR"
  echo "  说明：AAB 的 Manifest 是 protobuf，未转换前无法用 aapt2 直接解析。"
fi

echo "------------------------------------------------------------"
echo "【结论】"
echo "  - AAB 共 $MODULE_COUNT 个模块；模块级 DEX/native/资源统计见上。"
if [[ -n "$BUNDLETOOL_JAR" ]]; then
  echo "  - 已生成 universal 产物，可继续对 $OUT_DIR/universal.apk 跑 APK 分析脚本。"
  exit 0
fi
echo "  - 未生成 APK：缺少 bundletool，AAB 的 Manifest/资源/代码未做进一步语义分析。"
echo "  说明：本脚本不解析 AAB protobuf，不替代 bundletool 的完整拆分逻辑。"
exit 1
