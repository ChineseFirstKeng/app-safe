#!/usr/bin/env bash
#
# 07-strings-harvest.sh —— 通用静态分析：字符串与硬编码情报
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   对 APK/ZIP 或任意文件做 strings 扫描，收集：
#     - URL（http/https/ws/wss/ftp）
#     - IP 地址
#     - 邮箱
#     - 敏感关键字（api_key/secret/token/password/私钥标记等）
#     - 测试/开发/预发环境线索（dev/test/uat/staging/sandbox 等）
#     - 你自己指定的关键字
#
#   注意：
#     strings 只能看到“可打印字符串”，看不到加密/压缩后的内容；
#     关键字命中也不等于真实凭据。结果需要人工确认。
#
# 参数：
#   <APK/ZIP/文件>   必填
#                    格式：存在且可读的文件路径；APK/ZIP 自动读取条目，其他文件整体扫描
#                    示例：./app.apk、./sample.zip、./libapp.so
#                    说明：不是 ZIP 时按普通文件扫描
#   --all            可选
#                    格式：布尔开关，不带值
#                    默认：关闭（APK 只扫描 DEX/resources.arsc/.so/res/raw/文本型 assets）
#                    示例：--all
#                    说明：扫描 ZIP 的全部条目
#   --keywords "a,b,c" 可选
#                    格式：逗号分隔的非空字符串
#                    默认：空（不追加自定义关键字）
#                    示例：--keywords "foo,bar"
#                    说明：按字面量匹配，不区分大小写
#   --max N          可选
#                    格式：非负整数（^[0-9]+$）
#                    默认：40
#                    示例：--max 80
#                    说明：每个分类最多显示 N 行
#
# 依赖：
#   strings（binutils / Xcode Command Line Tools）、unzip、grep、awk、sort。
#   缺少时明确提示安装方式并退出，不会静默跳过。
#
# 用法：
#   ./07-strings-harvest.sh <APK/ZIP/文件>
#   ./07-strings-harvest.sh <APK> --all
#   ./07-strings-harvest.sh <APK> --keywords "foo,bar" --max 80
#   ./07-strings-harvest.sh --help
#
#   错误输入示例：
#     ./07-strings-harvest.sh missing.apk
#       → 文件不存在，exit 2
#     ./07-strings-harvest.sh app.apk --max abc
#       → --max 不是非负整数，exit 2
#
# 输出：
#   扫描范围、URL、IP、邮箱、高置信敏感模式、弱信号、环境线索、
#   自定义关键字命中、【结论】。不修改输入；临时目录退出时删除。
#
# 退出码：
#   0 = 分析完成，至少发现一类线索
#   1 = 分析完成，未发现常见线索（不代表没有敏感信息）
#   2 = 参数/依赖/输入错误
#
set -euo pipefail
export LC_ALL=C

MAX_LINES=40
SCAN_ALL=false
CUSTOM_KEYWORDS=""
ARGS=()

usage() {
  cat <<'EOF'
用法:
  ./07-strings-harvest.sh <APK/ZIP/文件>
  ./07-strings-harvest.sh <APK> --all
  ./07-strings-harvest.sh <APK> --keywords "foo,bar" --max 80
  ./07-strings-harvest.sh --help

参数:
  <APK/ZIP/文件>       必填。格式: 存在且可读的文件路径。示例: ./app.apk
  --all                可选。布尔开关。默认: 关闭。示例: --all
  --keywords "a,b,c"   可选。格式: 逗号分隔字符串。默认: 空。示例: --keywords "foo,bar"
  --max N              可选。格式: 非负整数。默认: 40。示例: --max 80

输出:
  URL、IP、邮箱、敏感模式、环境线索、自定义关键字、【结论】。

退出码:
  0 = 至少发现一类线索
  1 = 未发现常见线索
  2 = 参数/依赖/输入错误
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      SCAN_ALL=true
      shift
      ;;
    --keywords)
      if [[ -z "${2:-}" ]]; then
        echo "[FAIL] --keywords 需要一个逗号分隔的关键字字符串" >&2
        exit 2
      fi
      CUSTOM_KEYWORDS="$2"
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
      ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#ARGS[@]} -ne 1 ]]; then
  echo "[FAIL] 必须且只能指定一个输入文件。" >&2
  usage >&2
  exit 2
fi

TARGET="${ARGS[0]}"
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

need_tool strings "macOS: xcode-select --install；Linux: sudo apt install binutils / sudo dnf install binutils"
need_tool unzip   "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"
need_tool grep    "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk     "macOS 通常自带；Linux: sudo apt install gawk / mawk"
need_tool sort    "macOS 通常自带；Linux: sudo apt install coreutils"

# ---------- 1. 判断是否 ZIP，并决定扫描范围 ----------
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
IS_ZIP=false
IS_APK=false
SCAN_SCOPE="整个文件"

if [[ -n "$ENTRIES" ]]; then
  IS_ZIP=true
  if grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
    IS_APK=true
  fi
fi

SCAN_ENTRIES=""
if [[ "$IS_ZIP" == true ]]; then
  if [[ "$SCAN_ALL" == true ]]; then
    SCAN_ENTRIES="$(grep -v '/$' <<<"$ENTRIES" || true)"
    SCAN_SCOPE="ZIP 全部条目"
  elif [[ "$IS_APK" == true ]]; then
    SCAN_ENTRIES="$(grep -E '^(classes([0-9]+)?\.dex|resources\.arsc|lib/.+\.so|res/raw/.+|assets/.+\.(json|xml|txt|ya?ml|properties|env|conf|ini|js|html?|css|csv|plist|strings|sql|pem|crt|key|cer|p12|mobileconfig))$' <<<"$ENTRIES" || true)"
    SCAN_SCOPE="APK 默认条目（DEX / resources.arsc / .so / res/raw / 文本型 assets）"
  else
    SCAN_ENTRIES="$(grep -v '/$' <<<"$ENTRIES" || true)"
    SCAN_SCOPE="ZIP 全部条目（非 APK）"
  fi

  if [[ -z "$SCAN_ENTRIES" ]]; then
    echo "[FAIL] 没有找到可扫描的条目。" >&2
    echo "       可以加 --all 扫描全部 ZIP 条目。" >&2
    exit 2
  fi
fi

# ---------- 2. 提取 strings ----------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/strings-harvest.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
STRINGS_FILE="$TMP_DIR/strings.txt"
: > "$STRINGS_FILE"

if [[ "$IS_ZIP" == true ]]; then
  SCAN_ENTRY_COUNT="$(printf '%s\n' "$SCAN_ENTRIES" | grep -c . || true)"
  echo "[loading] 正在扫描 $SCAN_ENTRY_COUNT 个条目并提取字符串（大包可能需要一段时间）..."
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    # 条目之间加标记，便于后面输出“命中来自哪个条目”
    printf '### %s\n' "$entry" >> "$STRINGS_FILE"
    unzip -p "$TARGET" "$entry" 2>/dev/null | strings -a -n 4 >> "$STRINGS_FILE" || true
  done <<<"$SCAN_ENTRIES"
else
  echo "[loading] 正在扫描整个文件并提取字符串（大文件可能需要一段时间）..."
  strings -a -n 4 "$TARGET" > "$STRINGS_FILE"
fi

STRING_LINES="$(wc -l < "$STRINGS_FILE" | tr -d ' ')"
echo "[done] 字符串提取完成：$STRING_LINES 行"

if [[ "$STRING_LINES" -eq 0 ]]; then
  echo "============================================================"
  echo "静态分析 07：字符串与硬编码情报"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  echo "没有提取到可打印字符串；目标可能是加密/压缩内容或空文件。"
  exit 1
fi

# ---------- 3. 提取各类线索 ----------
# URL：先提取，再去掉末尾标点；过滤掉没有点号的伪 URL（如 http://http），
# 以及常见的 XML/规范命名空间，避免结果被框架样板噪声淹没。
URLS="$(grep -Eo '(https?|wss?|ftp)://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$STRINGS_FILE" \
  | sed -E 's/[]>,.;:)]+$//' \
  | awk -F/ '
      {
        host = $3
        sub(/^.*@/, "", host)
        sub(/:[0-9]+$/, "", host)
        if (host ~ /\./ || host == "localhost" || host ~ /^[0-9]+(\.[0-9]+){3}$/ || host ~ /^\[/) print
      }' \
  | grep -Ev '^https?://(www\.w3\.org|ns\.adobe\.com|schemas\.android\.com|xmlpull\.org|java\.sun\.com|www\.unicode\.org)/' \
  | sort -u || true)"
URL_COUNT="$(printf '%s\n' "$URLS" | grep -c . || true)"

IPS="$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?' "$STRINGS_FILE" \
  | sort -u || true)"
IP_COUNT="$(printf '%s\n' "$IPS" | grep -c . || true)"

# 邮箱：用常见 TLD 白名单 + 过滤纯数字本地部分，减少对
# Dart/Java 符号（如 _Foo@123.method）的误报。
EMAILS="$(grep -Eoi '[A-Za-z0-9][A-Za-z0-9._%+-]*@([A-Za-z0-9-]+\.)+(com|cn|net|org|io|tv|co|edu|gov|me|dev|app|info|biz|xyz|cloud|tech|ai|hk|us|uk|jp|de|fr|ru|in|au|ca|br|es|it|nl|se|no|fi|dk|pl|ch|at|be|cz|pt|ro|hu|ie|il|kr|sg|my|th|vn|id|ph|tw|mo|eu|asia|mobi|name|pro|travel|jobs|tel|cat|post)' "$STRINGS_FILE" \
  | grep -Ev '^[0-9]+@|@[0-9]+\.' \
  | sort -u || true)"
EMAIL_COUNT="$(printf '%s\n' "$EMAILS" | grep -c . || true)"

# 高置信敏感模式：要求出现“key=value”形态或明确的密钥标记，
# 避免把普通文案里的 token 单词全部算进来。
HIGH_SIGNAL_MATCHES="$(awk -v max="$MAX_LINES" '
  /^### / { entry = substr($0, 5); next }
  {
    low = tolower($0)
    hit = 0
    if (match(low, /(api[_-]?key|apikey|secret|password|passwd|client[_-]?secret|access[_-]?key|refresh[_-]?token)[[:space:]]*[:=][[:space:]]*[a-z0-9_.\/+=-]+/)) {
      v = substr(low, RSTART, RLENGTH)
      sub(/^[^:=]*[:=][[:space:]]*/, "", v)
      if (length(v) >= 8) hit = 1
    }
    if (!hit && match(low, /bearer[[:space:]]+[a-z0-9._~+\/-]+/)) {
      v = substr(low, RSTART, RLENGTH)
      sub(/^bearer[[:space:]]+/, "", v)
      if (length(v) >= 8) hit = 1
    }
    if (!hit && /BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY/) hit = 1
    if (!hit && /AKIA[0-9A-Z]{16}/) hit = 1
    if (!hit && /AIza[0-9A-Za-z_-]{35}/) hit = 1
    if (hit) {
      print "[" entry "] " $0
      n++
      if (n >= max) exit
    }
  }
' "$STRINGS_FILE" || true)"
HIGH_SIGNAL_COUNT="$(printf '%s\n' "$HIGH_SIGNAL_MATCHES" | grep -c . || true)"

# 弱信号：只出现 token/secret/password 等词。可能是字段名、日志或文案，
# 单独列出，避免和高置信命中混在一起。
WEAK_SIGNAL_MATCHES="$(awk -v max="$MAX_LINES" '
  /^### / { entry = substr($0, 5); next }
  tolower($0) ~ /api[_-]?key|apikey|secret|token|password|passwd|bearer|authorization|jwt|private[_-]?key|session[_-]?id/ {
    print "[" entry "] " $0
    n++
    if (n >= max) exit
  }
' "$STRINGS_FILE" || true)"
WEAK_SIGNAL_COUNT="$(printf '%s\n' "$WEAK_SIGNAL_MATCHES" | grep -c . || true)"

# 环境线索：只看 URL 的 host，或 host:port 形态，避免把 pub.dev、
# 构建路径、androidx.test 等标识符误判成环境地址。
ENV_URLS="$(printf '%s\n' "$URLS" \
  | grep -Ei '([.-]|://)(dev|develop|development|test|testing|uat|staging|stage|preprod|sandbox)([.-]|:|/|$)' \
  | grep -Ev '^https?://(api|docs|plugins)\.flutter\.dev/|^https?://([^/]*\.)?pub\.dev/' || true)"
ENV_HOSTPORTS="$(grep -Eo '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}:[0-9]{2,5}' "$STRINGS_FILE" \
  | sort -u \
  | grep -Ei '(^|[.-])(dev|develop|development|test|testing|uat|staging|stage|preprod|sandbox)([.-]|:)' \
  | grep -Ev '^(api|docs|plugins)\.flutter\.dev|(^|\.)pub\.dev' || true)"
ENV_MATCHES="$(printf '%s\n%s\n' "$ENV_URLS" "$ENV_HOSTPORTS" \
  | grep -v '^$' | awk '!seen[$0]++' | awk -v max="$MAX_LINES" 'NR <= max' || true)"
ENV_COUNT="$(printf '%s\n' "$ENV_MATCHES" | grep -c . || true)"

# 自定义关键字：按字面量匹配，避免用户输入被当成正则。
CUSTOM_MATCHES=""
CUSTOM_COUNT=0
if [[ -n "$CUSTOM_KEYWORDS" ]]; then
  IFS=',' read -r -a KEYS <<<"$CUSTOM_KEYWORDS"
  for key in "${KEYS[@]}"; do
    # 去掉首尾空白
    key="$(printf '%s' "$key" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$key" ]] && continue
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      CUSTOM_MATCHES+="[$key] $hit"$'\n'
      CUSTOM_COUNT=$((CUSTOM_COUNT + 1))
      [[ "$CUSTOM_COUNT" -ge "$MAX_LINES" ]] && break
    done < <(grep -F -i -- "$key" "$STRINGS_FILE" || true)
    [[ "$CUSTOM_COUNT" -ge "$MAX_LINES" ]] && break
  done
fi

# ---------- 4. 输出 ----------
echo "============================================================"
echo "静态分析 07：字符串与硬编码情报"
echo "目标：$TARGET"
echo "扫描范围：$SCAN_SCOPE"
echo "strings 行数：$STRING_LINES"
echo "============================================================"

echo "URL（$URL_COUNT 个，去重）："
if [[ "$URL_COUNT" -gt 0 ]]; then
  printf '%s\n' "$URLS" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  - /'
  [[ "$URL_COUNT" -gt "$MAX_LINES" ]] && echo "  ...（其余 $((URL_COUNT - MAX_LINES)) 个已省略）"
else
  echo "  (无)"
fi

echo "------------------------------------------------------------"
echo "IP 地址（$IP_COUNT 个，去重；形状匹配，可能是版本号）："
if [[ "$IP_COUNT" -gt 0 ]]; then
  printf '%s\n' "$IPS" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  - /'
else
  echo "  (无)"
fi

echo "------------------------------------------------------------"
echo "邮箱（$EMAIL_COUNT 个，去重）："
if [[ "$EMAIL_COUNT" -gt 0 ]]; then
  printf '%s\n' "$EMAILS" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  - /'
else
  echo "  (无)"
fi

echo "------------------------------------------------------------"
echo "高置信敏感模式（key=value / Bearer / 私钥标记 / 云厂商密钥，最多 $MAX_LINES 行）："
if [[ -n "$HIGH_SIGNAL_MATCHES" ]]; then
  printf '%s\n' "$HIGH_SIGNAL_MATCHES" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  /'
else
  echo "  (无)"
fi

echo "------------------------------------------------------------"
echo "弱信号关键字（token/secret/password 等，可能是字段名或文案，最多 $MAX_LINES 行）："
if [[ -n "$WEAK_SIGNAL_MATCHES" ]]; then
  printf '%s\n' "$WEAK_SIGNAL_MATCHES" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  /'
else
  echo "  (无)"
fi

echo "------------------------------------------------------------"
echo "测试/开发/预发环境线索（$ENV_COUNT 行）："
if [[ -n "$ENV_MATCHES" ]]; then
  printf '%s\n' "$ENV_MATCHES" | sed 's/^/  - /'
else
  echo "  (无)"
fi

if [[ -n "$CUSTOM_KEYWORDS" ]]; then
  echo "------------------------------------------------------------"
  echo "自定义关键字命中（最多 $MAX_LINES 行）："
  if [[ -n "$CUSTOM_MATCHES" ]]; then
    printf '%s' "$CUSTOM_MATCHES" | awk -v max="$MAX_LINES" 'NR <= max' | sed 's/^/  /'
  else
    echo "  (无)"
  fi
fi

# ---------- 5. 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

FOUND=false
if [[ "$URL_COUNT" -gt 0 ]]; then
  echo "  - 发现 $URL_COUNT 个 URL：注意其中是否有内网地址、测试域名或明文 http。"
  FOUND=true
fi
if [[ "$HIGH_SIGNAL_COUNT" -gt 0 ]]; then
  echo "  - 高置信敏感模式命中 $HIGH_SIGNAL_COUNT 行：需确认是否包含真实密钥/令牌/口令。"
  echo "    即使是高置信模式，也需要人工核对上下文，不能仅凭命中判定泄露。"
  FOUND=true
fi
if [[ "$WEAK_SIGNAL_COUNT" -gt 0 ]]; then
  echo "  - 弱信号关键字命中 $WEAK_SIGNAL_COUNT 行：可能只是字段名、日志或文案。"
  FOUND=true
fi
if [[ "$IP_COUNT" -gt 0 ]]; then
  echo "  - 发现 $IP_COUNT 个 IP 形状字符串：确认是否为内网地址或测试环境地址。"
  FOUND=true
fi
if [[ "$EMAIL_COUNT" -gt 0 ]]; then
  echo "  - 发现 $EMAIL_COUNT 个邮箱：确认是否为真实联系人/账号。"
  FOUND=true
fi
if [[ "$ENV_COUNT" -gt 0 ]]; then
  echo "  - 发现 $ENV_COUNT 条测试/开发/预发环境线索：确认生产包是否误带测试配置。"
  FOUND=true
fi
if [[ "$CUSTOM_COUNT" -gt 0 ]]; then
  echo "  - 自定义关键字命中 $CUSTOM_COUNT 行。"
  FOUND=true
fi

if [[ "$FOUND" != true ]]; then
  echo "  未发现常见线索。"
  echo "  这不代表没有敏感信息：字符串可能被加密、压缩，或不在本次扫描范围内。"
  exit 1
fi

echo "  以上结果来自 strings 启发式扫描；需要人工核对上下文和真实性。"
exit 0
