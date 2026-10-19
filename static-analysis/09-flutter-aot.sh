#!/usr/bin/env bash
#
# 09-flutter-aot.sh —— 通用静态分析：Flutter / Dart AOT（libapp.so）
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定样本的业务逻辑。
#
# 用途：
#   Flutter 的业务逻辑通常编译进 libapp.so（Dart AOT snapshot），
#   jadx 只能看到很薄的宿主层。本脚本针对 libapp.so 做：
#     - 列出 APK 内的 ABI、libapp.so / libflutter.so
#     - 计算 libapp.so 大小与 SHA-256
#     - 提取 Flutter/Dart 版本线索
#     - 提取 URL、测试/开发环境地址
#     - 检索高置信敏感字符串（key=value、AIza/AKIA、私钥标记）
#     - 可选：调用 blutter 还原 Dart 类名/函数名（需要你提前编译好 blutter）
#
#   注意：
#     默认只做 strings 层分析，不能还原完整 Dart 逻辑。
#     blutter 是可选外部工具，本脚本不负责安装/编译它；
#     需要时用 --blutter 直接传入已编译好的 blutter.py 或可执行文件路径。
#
# 参数：
#   <APK|libapp.so|目录> 必填
#                     格式：
#                       - APK 文件路径（ZIP 根目录含 AndroidManifest.xml）
#                       - ELF 格式的 libapp.so 文件
#                       - 包含 libapp.so 的目录（通常是解包后的 lib/<abi>/）
#                     示例：./app.apk、./libapp.so、./unpacked-lib
#                     说明：AAB/APKS/IPA/JAR/普通 ZIP/非 ELF 文件会被识别并 exit 2
#   --abi <abi>       可选
#                     格式：ABI 名称，区分大小写；常见值 arm64-v8a、armeabi-v7a、x86、x86_64
#                     默认：空（分析 APK 内全部 ABI）
#                     示例：--abi arm64-v8a
#                     说明：只对 APK 输入生效
#   --blutter <path>  可选
#                     格式：存在且可执行的 blutter.py 或可执行文件路径
#                     默认：空（不启用）
#                     示例：--blutter /path/to/blutter.py
#                     说明：启用 Dart 类名/函数名还原
#   --out <dir>       可选
#                     格式：目录路径；不存在时创建
#                     默认：./blutter-out
#                     示例：--out ./out
#                     说明：blutter 输出根目录；会写盘，不会被脚本删除
#   --max N           可选
#                     格式：非负整数（^[0-9]+$）
#                     默认：30
#                     示例：--max 60
#                     说明：每个分类最多显示 N 行
#
# 依赖：
#   strings、unzip（APK 输入时）、find、grep、awk、sort、od，
#   以及 shasum/sha256sum/openssl 之一。
#   缺少时明确提示安装方式并退出，不会静默跳过。
#   blutter 未提供时只做 strings 分析，不会因此退出。
#
# 用法：
#   ./09-flutter-aot.sh <APK>
#   ./09-flutter-aot.sh <APK> --abi arm64-v8a
#   ./09-flutter-aot.sh <libapp.so>
#   ./09-flutter-aot.sh <包含 lib/arm64-v8a/libapp.so 的目录>
#   ./09-flutter-aot.sh <APK> --blutter /path/to/blutter.py --out ./blutter-out
#   ./09-flutter-aot.sh --help
#
#   错误输入示例：
#     ./09-flutter-aot.sh app.ipa
#       → 识别为 iOS IPA，提示这不是 Android Flutter 包，exit 2
#     ./09-flutter-aot.sh note.txt
#       → 不是 APK，也不是 ELF 格式的 libapp.so，exit 2
#
# 输出：
#   每个 libapp.so 的 ABI/大小/SHA-256、Flutter/Dart 版本线索、URL、
#   测试/开发环境线索、高置信敏感字符串、【结论】。
#   可选 blutter 输出写入 --out 目录；其余临时文件退出时删除。
#
# 退出码：
#   0 = 完成至少一个 libapp.so 的分析
#   1 = 输入是 APK/目录，但没有找到 libapp.so
#   2 = 参数/依赖/输入错误（包括 AAB/APKS/IPA/JAR/非 ELF 文件）
#
set -euo pipefail
export LC_ALL=C

TARGET=""
ABI_FILTER=""
BLUTTER=""
OUT_BASE="$PWD/blutter-out"
MAX_LINES=30

usage() {
  cat <<'EOF'
用法:
  ./09-flutter-aot.sh <APK>
  ./09-flutter-aot.sh <APK> --abi arm64-v8a
  ./09-flutter-aot.sh <libapp.so>
  ./09-flutter-aot.sh <包含 libapp.so 的目录>
  ./09-flutter-aot.sh <APK> --blutter /path/to/blutter.py --out ./blutter-out
  ./09-flutter-aot.sh --help

参数:
  <APK|libapp.so|目录>  必填。格式: APK、ELF 格式的 libapp.so，或包含 libapp.so 的目录。
                         示例: ./app.apk、./libapp.so、./unpacked-lib
  --abi <abi>           可选。格式: ABI 名称（区分大小写），如 arm64-v8a、armeabi-v7a、x86、x86_64。
                         默认: 空（分析全部 ABI）。示例: --abi arm64-v8a
  --blutter <path>      可选。格式: blutter.py 或可执行文件路径。默认: 空（不启用）。
  --out <dir>           可选。格式: 目录路径。默认: ./blutter-out。示例: --out ./out
  --max N               可选。格式: 非负整数。默认: 30。示例: --max 60

输出:
  每个 libapp.so 的 ABI/大小/SHA-256、版本线索、URL、环境线索、敏感字符串、【结论】。
  可选 blutter 输出写入 --out 目录；其余临时文件退出时删除。

退出码:
  0 = 完成至少一个 libapp.so 的分析
  1 = 输入是 APK/目录，但没有找到 libapp.so
  2 = 参数/依赖/输入错误（包括 AAB/APKS/IPA/JAR/非 ELF 文件）
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --abi)
      if [[ -z "${2:-}" ]]; then
        echo "[FAIL] --abi 需要一个 ABI 名称，例如 arm64-v8a" >&2
        exit 2
      fi
      ABI_FILTER="$2"
      shift 2
      ;;
    --blutter)
      if [[ -z "${2:-}" ]]; then
        echo "[FAIL] --blutter 需要 blutter.py 或可执行文件路径" >&2
        exit 2
      fi
      BLUTTER="$2"
      shift 2
      ;;
    --out)
      if [[ -z "${2:-}" ]]; then
        echo "[FAIL] --out 需要一个输出目录" >&2
        exit 2
      fi
      OUT_BASE="$2"
      shift 2
      ;;
    --max)
      if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
        echo "[FAIL] --max 需要一个非负整数" >&2
        exit 2
      fi
      MAX_LINES="$2"
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
        echo "[FAIL] 只能指定一个输入" >&2
        exit 2
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[FAIL] 缺少必填参数 <APK|libapp.so|目录>。" >&2
  usage >&2
  exit 2
fi
if [[ ! -e "$TARGET" ]]; then
  echo "[FAIL] 路径不存在: $TARGET" >&2
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

need_tool strings "macOS: xcode-select --install；Linux: sudo apt install binutils / sudo dnf install binutils"
need_tool unzip   "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"
need_tool od      "macOS 通常自带；Linux: sudo apt install coreutils"
need_tool find    "macOS 通常自带；Linux: sudo apt install findutils"
need_tool grep    "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk     "macOS 通常自带；Linux: sudo apt install gawk / mawk"
need_tool sort    "macOS 通常自带；Linux: sudo apt install coreutils"

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

# blutter 路径预检（可选工具；只在用户显式传入时检查）
if [[ -n "$BLUTTER" ]]; then
  if [[ ! -e "$BLUTTER" ]]; then
    echo "[FAIL] --blutter 指定的路径不存在: $BLUTTER" >&2
    echo "       blutter 需要单独编译，项目地址：" >&2
    echo "       https://github.com/worawit/blutter" >&2
    echo "       编译完成后用 --blutter /path/to/blutter.py 或 --blutter /path/to/blutter 指定。" >&2
    exit 2
  fi
  if [[ "$BLUTTER" == *.py ]]; then
    need_tool python3 "macOS: brew install python3；Linux: sudo apt install python3"
  fi
fi

# ---------- 1. 识别输入并收集 libapp.so ----------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/flutter-aot.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

APP_SOS=()
IS_APK=false
INPUT_TYPE=""
ENTRIES=""

# 先识别输入类型，避免把 IPA/AAB/APKS/JAR/普通 ZIP 当成 APK，
# 也避免把任意非 ZIP 文件当成 libapp.so。
if [[ -d "$TARGET" ]]; then
  INPUT_TYPE="DIR"
elif [[ -f "$TARGET" ]]; then
  ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
  if [[ -n "$ENTRIES" ]]; then
    if grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
      INPUT_TYPE="APK"
    elif grep -qx 'BundleConfig.pb' <<<"$ENTRIES" \
      || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
      INPUT_TYPE="AAB"
    elif grep -qx 'toc.pb' <<<"$ENTRIES" && grep -q '\.apk$' <<<"$ENTRIES"; then
      INPUT_TYPE="APKS"
    elif grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
      INPUT_TYPE="IPA"
    elif grep -qx 'META-INF/MANIFEST.MF' <<<"$ENTRIES" \
      && grep -q '\.class$' <<<"$ENTRIES"; then
      INPUT_TYPE="JAR"
    else
      INPUT_TYPE="ZIP"
    fi
  else
    MAGIC="$(dd if="$TARGET" bs=1 count=4 2>/dev/null || true)"
    if [[ "$MAGIC" == $'\x7fELF' ]]; then
      INPUT_TYPE="ELF"
    else
      INPUT_TYPE="OTHER"
    fi
  fi
else
  echo "[FAIL] 路径不存在或不是普通文件/目录: $TARGET" >&2
  exit 2
fi

case "$INPUT_TYPE" in
  DIR)
    while IFS= read -r so; do
      [[ -n "$so" ]] && APP_SOS+=("$so")
    done < <(find "$TARGET" -type f -name 'libapp.so' 2>/dev/null | sort || true)

    if [[ ${#APP_SOS[@]} -eq 0 ]]; then
      echo "============================================================"
      echo "静态分析 09：Flutter / Dart AOT 分析"
      echo "目标目录：$TARGET"
      echo "输入类型：$INPUT_TYPE"
      echo "============================================================"
      echo "【结论】"
      echo "目录下没有找到 libapp.so。"
      echo "请确认输入是 Flutter APK 解包后的 lib/<abi>/ 目录，"
      echo "或直接把 libapp.so 文件作为输入。"
      exit 1
    fi
    ;;
  APK)
    IS_APK=true

    if [[ -n "$ABI_FILTER" ]]; then
      while IFS= read -r entry; do
        [[ -n "$entry" ]] && APP_SOS+=("$entry")
      done < <(grep -E "^lib/${ABI_FILTER}/libapp\.so$" <<<"$ENTRIES" || true)

      if [[ ${#APP_SOS[@]} -eq 0 ]]; then
        AVAILABLE_ABIS="$(grep -oE '^lib/[^/]+/' <<<"$ENTRIES" | cut -d/ -f2 | sort -u | paste -sd, - || true)"
        echo "[FAIL] APK 内没有 lib/${ABI_FILTER}/libapp.so。" >&2
        echo "       APK 内的 ABI：${AVAILABLE_ABIS:-无}" >&2
        exit 1
      fi
    else
      while IFS= read -r entry; do
        [[ -n "$entry" ]] && APP_SOS+=("$entry")
      done < <(grep -E '^lib/[^/]+/libapp\.so$' <<<"$ENTRIES" | sort || true)
    fi

    if [[ ${#APP_SOS[@]} -eq 0 ]]; then
      echo "============================================================"
      echo "静态分析 09：Flutter / Dart AOT 分析"
      echo "目标：$TARGET"
      echo "输入类型：$INPUT_TYPE"
      echo "============================================================"
      echo "【结论】"
      echo "APK 内没有 lib/*/libapp.so。"
      echo "可能原因："
      echo "  - 不是 Flutter 应用；"
      echo "  - Flutter 的 native 库在 split APK 中（如 config.arm64_v8a.apk）；"
      echo "  - 使用了非标准打包方式。"
      echo "如果是 split APK，请把包含 libapp.so 的 APK 或 lib/<abi>/ 目录作为输入。"
      exit 1
    fi
    ;;
  ELF)
    if [[ "$(basename "$TARGET")" != "libapp.so" ]]; then
      echo "[FAIL] 单文件输入只接受 libapp.so；检测到 ELF 文件：$TARGET" >&2
      echo "       如果这是重命名后的 libapp.so，请改名为 libapp.so 后重试。" >&2
      exit 2
    fi
    APP_SOS=("$TARGET")
    ;;
  AAB|APKS|IPA|JAR|ZIP)
    echo "============================================================"
    echo "静态分析 09：Flutter / Dart AOT 分析"
    echo "目标：$TARGET"
    echo "输入类型：$INPUT_TYPE"
    echo "============================================================"
    echo "【结论】"
    case "$INPUT_TYPE" in
      AAB)
        echo "这是 AAB，不是 APK。请先用 bundletool 生成 APK，再分析其中的 lib/<abi>/libapp.so。"
        ;;
      APKS)
        echo "这是 APKS，请先解出 base.apk / split APK，或直接对包含 libapp.so 的 APK/目录运行本脚本。"
        ;;
      IPA)
        echo "这是 iOS IPA，不是 Android Flutter 包。Android libapp.so 分析不适用。"
        echo "如需分析 iOS Flutter，请使用 iOS IPA 分析流程。"
        ;;
      JAR)
        echo "这是 JAR，不包含 Android lib/<abi>/libapp.so。"
        ;;
      ZIP)
        echo "这是普通 ZIP：根目录没有 AndroidManifest.xml，也没有 lib/<abi>/libapp.so。"
        ;;
    esac
    exit 2
    ;;
  OTHER)
    echo "============================================================"
    echo "静态分析 09：Flutter / Dart AOT 分析"
    echo "目标：$TARGET"
    echo "============================================================"
    echo "【结论】"
    if [[ "$(basename "$TARGET")" == "libapp.so" ]]; then
      echo "文件名为 libapp.so，但文件头不是 ELF；请确认文件完整、未损坏。"
    else
      echo "输入不是 APK、libapp.so，也不是包含 libapp.so 的目录。"
      echo "支持：APK、ELF 格式的 libapp.so、包含 libapp.so 的目录。"
    fi
    exit 2
    ;;
  *)
    echo "[FAIL] 不支持的输入类型: $INPUT_TYPE（$TARGET）" >&2
    exit 2
    ;;
esac

# ---------- 2. 逐个 libapp.so 分析 ----------
TOTAL_FOUND=false
TOTAL_ENV=false
TOTAL_SECRET=false

for app_so in "${APP_SOS[@]}"; do
  SO_PATH=""
  LIB_DIR=""
  ABI=""

  if [[ "$IS_APK" == true ]]; then
    ABI="$(cut -d/ -f2 <<<"$app_so")"
    LIB_DIR="$TMP_DIR/lib/$ABI"
    mkdir -p "$LIB_DIR"

    # 解出该 ABI 的全部 .so，方便 strings 分析和 blutter
    echo "[loading] 正在从 APK 提取 ABI=$ABI 的 native 库（大包可能需要一段时间）..."
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      base="$(basename "$entry")"
      unzip -p "$TARGET" "$entry" > "$LIB_DIR/$base"
    done < <(grep -E "^lib/${ABI}/.+\.so$" <<<"$ENTRIES" || true)
    echo "[done] native 库提取完成"

    SO_PATH="$LIB_DIR/$(basename "$app_so")"
  elif [[ -d "$TARGET" ]]; then
    SO_PATH="$app_so"
    LIB_DIR="$(dirname "$app_so")"
    # 尝试从 .../lib/<abi>/libapp.so 中取 ABI
    ABI="$(basename "$(dirname "$app_so")")"
  else
    SO_PATH="$app_so"
    LIB_DIR="$(dirname "$app_so")"
    ABI="(未知)"
  fi

  if [[ ! -f "$SO_PATH" ]]; then
    echo "[WARN] 无法读取 libapp.so: $SO_PATH" >&2
    continue
  fi

  TOTAL_FOUND=true
  SO_SIZE="$(wc -c < "$SO_PATH" | tr -d ' ')"
  SO_SHA="$(sha256_file "$SO_PATH")"
  STRINGS_FILE="$TMP_DIR/strings-${ABI//\//_}.txt"
  echo "[loading] 正在扫描 $app_so 的字符串（大文件可能需要一段时间）..."
  strings -a -n 4 "$SO_PATH" > "$STRINGS_FILE"
  echo "[done] 字符串扫描完成"

  echo "============================================================"
  echo "静态分析 09：Flutter / Dart AOT 分析"
  echo "目标：$TARGET"
  echo "ABI：$ABI"
  echo "libapp.so：$app_so"
  echo "大小：$SO_SIZE 字节"
  echo "SHA-256：$SO_SHA"
  if [[ -f "$LIB_DIR/libflutter.so" ]]; then
    echo "libflutter.so：存在"
  else
    echo "libflutter.so：不存在（部分分析可能受限）"
  fi
  echo "============================================================"

  # Flutter / Dart 版本线索
  VERSION_HINTS="$(grep -Eo 'Flutter [0-9]+\.[0-9]+\.[0-9]+|Dart (VM|SDK) version[: ]+[0-9]+\.[0-9]+\.[0-9]+|Dart [0-9]+\.[0-9]+\.[0-9]+' "$STRINGS_FILE" \
    | sort -u | awk 'NR <= 10' || true)"
  echo "Flutter/Dart 版本线索："
  if [[ -n "$VERSION_HINTS" ]]; then
    printf '%s\n' "$VERSION_HINTS" | sed 's/^/  - /'
  else
    echo "  (未提取到明确版本号)"
  fi

  # URL：过滤明显的文档/命名空间噪声，保留业务地址和环境地址
  URLS="$(grep -Eo '(https?|wss?|ftp)://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$STRINGS_FILE" \
    | sed -E 's/[]>,.;:)]+$//' \
    | awk -F/ '
        {
          host = $3
          sub(/^.*@/, "", host)
          sub(/:[0-9]+$/, "", host)
          if (host ~ /\./ || host == "localhost" || host ~ /^[0-9]+(\.[0-9]+){3}$/ || host ~ /^\[/) print
        }' \
    | grep -Ev '^https?://(api\.flutter\.dev|docs\.flutter\.dev|flutter\.dev|dart\.dev|dartbug\.com|storage\.googleapis\.com|android\.googlesource\.com|github\.com|www\.w3\.org|ns\.adobe\.com|schemas\.android\.com)/' \
    | sort -u || true)"
  URL_COUNT="$(printf '%s\n' "$URLS" | grep -c . || true)"

  echo "------------------------------------------------------------"
  echo "URL（$URL_COUNT 个，已过滤常见文档/命名空间地址）："
  if [[ "$URL_COUNT" -gt 0 ]]; then
    printf '%s\n' "$URLS" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  - /'
    if [[ "$URL_COUNT" -gt "$MAX_LINES" ]]; then
      echo "  ...（其余 $((URL_COUNT - MAX_LINES)) 个已省略）"
    fi
  else
    echo "  (无)"
  fi

  # 环境线索：URL host 或 host:port 中包含 dev/test/uat/staging 等
  ENV_URLS="$(printf '%s\n' "$URLS" \
    | grep -Ei '([.-]|://)(dev|develop|development|test|testing|uat|staging|stage|preprod|sandbox)([.-]|:|/|$)' \
    | grep -Ev '^https?://([^/]*\.)?pub\.dev(/|$)' || true)"
  ENV_HOSTPORTS="$(grep -Eo '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}:[0-9]{2,5}' "$STRINGS_FILE" \
    | sort -u \
    | grep -Ei '(^|[.-])(dev|develop|development|test|testing|uat|staging|stage|preprod|sandbox)([.-]|:)' \
    | grep -Ev '(^|\.)pub\.dev(:|$)' || true)"
  ENV_MATCHES="$(printf '%s\n%s\n' "$ENV_URLS" "$ENV_HOSTPORTS" \
    | grep -v '^$' | awk '!seen[$0]++' | awk -v max="$MAX_LINES" 'NR <= max' || true)"
  ENV_COUNT="$(printf '%s\n' "$ENV_MATCHES" | grep -c . || true)"

  echo "------------------------------------------------------------"
  echo "测试/开发/预发环境线索（$ENV_COUNT 条）："
  if [[ "$ENV_COUNT" -gt 0 ]]; then
    printf '%s\n' "$ENV_MATCHES" | sed 's/^/  - /'
    TOTAL_ENV=true
  else
    echo "  (无)"
  fi

  # 高置信敏感字符串
  SECRETS="$(grep -E 'AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|(api[_-]?key|apikey|secret|password|passwd)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9_./+=-]{8,}' "$STRINGS_FILE" \
    | sort -u | awk -v max="$MAX_LINES" 'NR <= max' || true)"
  SECRET_COUNT="$(printf '%s\n' "$SECRETS" | grep -c . || true)"

  echo "------------------------------------------------------------"
  echo "高置信敏感字符串（$SECRET_COUNT 行）："
  if [[ "$SECRET_COUNT" -gt 0 ]]; then
    printf '%s\n' "$SECRETS" | sed 's/^/  - /'
    TOTAL_SECRET=true
  else
    echo "  (无)"
  fi

  # 可选 blutter
  if [[ -n "$BLUTTER" ]]; then
    BLUTTER_OUT="$OUT_BASE/$ABI"
    mkdir -p "$BLUTTER_OUT"
    BLUTTER_LOG="$TMP_DIR/blutter-${ABI//\//_}.log"

    echo "------------------------------------------------------------"
    echo "[loading] blutter：正在还原 Dart 结构，输出到 $BLUTTER_OUT（可能需要几分钟）..."
    if [[ ! -f "$LIB_DIR/libflutter.so" ]]; then
      echo "[WARN] $LIB_DIR 下没有 libflutter.so；blutter 通常需要它，可能失败。"
    fi

    BLUTTER_OK=false
    if [[ "$BLUTTER" == *.py ]]; then
      if python3 "$BLUTTER" "$LIB_DIR" "$BLUTTER_OUT" > "$BLUTTER_LOG" 2>&1; then
        BLUTTER_OK=true
      fi
    else
      if "$BLUTTER" "$LIB_DIR" "$BLUTTER_OUT" > "$BLUTTER_LOG" 2>&1; then
        BLUTTER_OK=true
      fi
    fi

    if [[ "$BLUTTER_OK" == true ]]; then
      echo "[done] blutter 还原完成：$BLUTTER_OUT"
      echo "可查看该目录下的 asm/、pp.txt 等输出。"
    else
      echo "[done] blutter 执行结束：失败"
      echo "[WARN] blutter 执行失败。输出末尾：" >&2
      tail -15 "$BLUTTER_LOG" | sed 's/^/       /' >&2
      echo "       请确认 blutter 已按官方 README 完成编译，且 lib 目录包含 libapp.so 和 libflutter.so。" >&2
    fi
  fi
done

if [[ "$TOTAL_FOUND" != true ]]; then
  echo "[FAIL] 没有成功分析任何 libapp.so。" >&2
  exit 1
fi

echo "------------------------------------------------------------"
echo "【结论】"
echo "已完成 ${#APP_SOS[@]} 个 libapp.so 的静态分析。"
if [[ "$TOTAL_ENV" == true ]]; then
  echo "  ⚠ 发现测试/开发/预发环境地址：确认生产包是否误带测试配置。"
fi
if [[ "$TOTAL_SECRET" == true ]]; then
  echo "  ⚠ 发现高置信敏感字符串：需人工确认是否为真实密钥/令牌。"
fi
if [[ -z "$BLUTTER" ]]; then
  echo "  本次未启用 blutter，只做了 strings 层分析，Dart 类名/函数名未还原。"
  echo "  如需深入分析，可先编译 blutter，再用 --blutter /path/to/blutter.py 重跑。"
fi
echo "  strings 结果是启发式的；需要结合上下文和真实配置确认。"
exit 0
