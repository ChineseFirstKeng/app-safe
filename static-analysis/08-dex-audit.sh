#!/usr/bin/env bash
#
# 08-dex-audit.sh —— 通用静态分析：DEX / Java / Kotlin 代码审计
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   反编译或反汇编 APK 里的 classes*.dex，按常见风险模式做检索：
#     - 日志输出（Log.* / System.out / printStackTrace）
#     - WebView 风险（addJavascriptInterface / setJavaScriptEnabled / 文件访问）
#     - 弱加密（AES/ECB、DES、MD5、SHA-1、硬编码密钥）
#     - TLS / 证书校验（X509TrustManager、HostnameVerifier）
#     - 本地存储（SharedPreferences、外部存储、world-readable）
#     - 动态加载/执行（DexClassLoader、System.load、Runtime.exec）
#     - 硬编码敏感信息（api key / secret / password / 私钥标记）
#
#   注意：
#     本脚本只覆盖 DEX（Java/Kotlin）层，不覆盖 native、Dart AOT、
#     JavaScript 或其他运行时逻辑。命中也不等于漏洞，需要人工看上下文。
#
# 参数：
#   <APK|classes.dex> 必填
#                     格式：存在且可读的 APK 文件路径，或 DEX 文件路径（文件头为 dex）
#                     示例：./app.apk、./classes.dex
#                     说明：传入 APK 时自动取出 classes*.dex
#   --engine jadx|dexdump 可选
#                     格式：枚举，只能是 jadx 或 dexdump
#                     默认：auto（优先 jadx，失败时回退 dexdump）
#                     示例：--engine dexdump
#                     说明：强制指定反编译/反汇编引擎
#   --max N           可选
#                     格式：非负整数（^[0-9]+$）
#                     默认：15
#                     示例：--max 30
#                     说明：每个风险分类最多显示 N 条命中
#
# 依赖：
#   unzip（APK 输入时需要）、grep、awk；
#   jadx 或 dexdump 至少一个：
#     jadx     —— 可读性更好，输出 Java 风格代码
#     dexdump  —— Android SDK Build-Tools 自带，输出 Dalvik 反汇编
#   缺少时明确提示安装方式并退出，不会静默跳过。
#
# 用法：
#   ./08-dex-audit.sh <APK>
#   ./08-dex-audit.sh <classes.dex>
#   ./08-dex-audit.sh <APK> --engine dexdump --max 30
#   ./08-dex-audit.sh --help
#
#   错误输入示例：
#     ./08-dex-audit.sh app.ipa
#       → 识别为 iOS IPA，提示不包含 DEX，exit 2
#     ./08-dex-audit.sh app.apk --engine foo
#       → --engine 只支持 jadx/dexdump，exit 2
#
# 输出：
#   DEX 数量、各风险分类命中、关键组合统计、【结论】。
#   不修改输入；临时文件放在 mktemp 目录，退出时删除。
#
# 退出码：
#   0 = 分析完成，至少发现一类风险模式
#   1 = 分析完成，未发现常见风险模式；或输入没有 DEX
#   2 = 参数/依赖/输入错误
#
set -euo pipefail
export LC_ALL=C

MAX_MATCHES=15
ENGINE="auto"
TARGET=""

usage() {
  cat <<'EOF'
用法:
  ./08-dex-audit.sh <APK>
  ./08-dex-audit.sh <classes.dex>
  ./08-dex-audit.sh <APK> --engine dexdump --max 30
  ./08-dex-audit.sh --help

参数:
  <APK|classes.dex>       必填。格式: 存在且可读的 APK 或 DEX 文件路径。示例: ./app.apk
  --engine jadx|dexdump   可选。枚举。默认: auto。示例: --engine dexdump
  --max N                 可选。格式: 非负整数。默认: 15。示例: --max 30

输出:
  DEX 数量、各风险分类命中、关键组合统计、【结论】。

退出码:
  0 = 至少发现一类风险模式
  1 = 未发现常见风险模式，或输入没有 DEX
  2 = 参数/依赖/输入错误
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --engine)
      if [[ "${2:-}" != "jadx" && "${2:-}" != "dexdump" ]]; then
        echo "[FAIL] --engine 只支持 jadx 或 dexdump" >&2
        exit 2
      fi
      ENGINE="$2"
      shift 2
      ;;
    --max)
      if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
        echo "[FAIL] --max 需要一个非负整数" >&2
        exit 2
      fi
      MAX_MATCHES="$2"
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
        echo "[FAIL] 只能指定一个输入文件" >&2
        exit 2
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[FAIL] 缺少必填参数 <APK|classes.dex>。" >&2
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

need_tool unzip "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"
need_tool grep  "macOS 通常自带；Linux: sudo apt install grep"
need_tool awk   "macOS 通常自带；Linux: sudo apt install gawk / mawk"

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

JADX="$(command -v jadx 2>/dev/null || true)"
DEXDUMP="$(find_android_tool dexdump || true)"

# 根据用户选择和实际可用工具决定引擎
if [[ "$ENGINE" == "auto" ]]; then
  if [[ -n "$JADX" ]]; then
    ENGINE="jadx"
  elif [[ -n "$DEXDUMP" ]]; then
    ENGINE="dexdump"
  else
    echo "[FAIL] 既没有 jadx，也没有 dexdump。" >&2
    echo "       二选一安装即可：" >&2
    echo "       jadx（推荐，可读性更好）：" >&2
    echo "         macOS: brew install jadx" >&2
    echo "         Linux: 从 https://github.com/skylot/jadx/releases 下载并加入 PATH" >&2
    echo "       dexdump（Android SDK Build-Tools 自带）：" >&2
    echo "         1) Android Studio → SDK Manager → SDK Tools → Android SDK Build-Tools" >&2
    echo "         2) 或 sdkmanager \"build-tools;34.0.0\"" >&2
    exit 2
  fi
fi

if [[ "$ENGINE" == "jadx" && -z "$JADX" ]]; then
  echo "[FAIL] 指定了 --engine jadx，但找不到 jadx。" >&2
  echo "       macOS: brew install jadx" >&2
  echo "       Linux: 从 https://github.com/skylot/jadx/releases 下载并加入 PATH" >&2
  exit 2
fi
if [[ "$ENGINE" == "dexdump" && -z "$DEXDUMP" ]]; then
  echo "[FAIL] 指定了 --engine dexdump，但找不到 dexdump。" >&2
  echo "       安装 Android SDK Build-Tools：" >&2
  echo "       Android Studio → SDK Manager → SDK Tools → Android SDK Build-Tools" >&2
  echo "       或 sdkmanager \"build-tools;34.0.0\"" >&2
  exit 2
fi

# jadx 依赖 Java；JAVA_HOME 指向文件时先清掉，避免误判。
if [[ "$ENGINE" == "jadx" ]]; then
  if [[ -n "${JAVA_HOME:-}" && ! -x "$JAVA_HOME/bin/java" ]]; then
    unset JAVA_HOME
  fi
  if ! command -v java >/dev/null 2>&1 && [[ -z "${JAVA_HOME:-}" ]]; then
    echo "[FAIL] jadx 需要 Java，但找不到 java / JAVA_HOME。" >&2
    echo "       macOS: brew install openjdk@17" >&2
    echo "              export JAVA_HOME=\$(/usr/libexec/java_home -v 17)" >&2
    echo "       Linux: sudo apt install openjdk-17-jdk" >&2
    exit 2
  fi
fi

# ---------- 1. 识别输入类型 ----------
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
IS_APK=false
IS_DEX=false

if [[ -n "$ENTRIES" ]] && grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  IS_APK=true
else
  MAGIC="$(dd if="$TARGET" bs=1 count=3 2>/dev/null || true)"
  if [[ "$MAGIC" == "dex" ]]; then
    IS_DEX=true
  fi
fi

if [[ "$IS_APK" != true && "$IS_DEX" != true ]]; then
  echo "============================================================"
  echo "静态分析 08：DEX / Java / Kotlin 代码审计"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  if [[ -n "$ENTRIES" ]]; then
    if grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES" || grep -qx 'BundleConfig.pb' <<<"$ENTRIES"; then
      echo "这是 AAB，不是 APK。请先用 bundletool 生成 APK，再对 APK 做 DEX 审计。"
    elif grep -qx 'toc.pb' <<<"$ENTRIES"; then
      echo "这是 APKS，请先解出 base.apk / split APK，或直接对其中的 classes*.dex 运行本脚本。"
    elif grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
      echo "这是 iOS IPA，不包含 Android DEX。"
    else
      echo "输入是 ZIP，但不是 APK，且不是 .dex 文件。"
    fi
  else
    echo "输入既不是 APK，也不是 DEX（文件头不是 dex）。"
  fi
  exit 2
fi

# ---------- 2. 收集 DEX 文件 ----------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dex-audit.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

DEX_LIST=()
if [[ "$IS_APK" == true ]]; then
  while IFS= read -r dex; do
    [[ -n "$dex" ]] && DEX_LIST+=("$dex")
  done < <(grep -E '^classes([0-9]+)?\.dex$' <<<"$ENTRIES" | sort || true)

  if [[ ${#DEX_LIST[@]} -eq 0 ]]; then
    echo "============================================================"
    echo "静态分析 08：DEX / Java / Kotlin 代码审计"
    echo "目标：$TARGET"
    echo "============================================================"
    echo "【结论】"
    echo "APK 内没有 classes*.dex。"
    echo "可能只有资源或 native 代码，或代码在非 DEX 运行时中。"
    echo "本脚本只审计 DEX/Java/Kotlin 层，无法覆盖这种情况。"
    exit 1
  fi
else
  DEX_LIST=("$TARGET")
fi

echo "============================================================"
echo "静态分析 08：DEX / Java / Kotlin 代码审计"
echo "目标：$TARGET"
echo "引擎：$ENGINE"
echo "DEX 数量：${#DEX_LIST[@]}"
echo "============================================================"

# ---------- 3. 反编译 / 反汇编 ----------
SEARCH_DIR=""
if [[ "$ENGINE" == "jadx" ]]; then
  JADX_OUT="$TMP_DIR/jadx-out"
  JADX_LOG="$TMP_DIR/jadx.log"
  mkdir -p "$JADX_OUT"

  echo "[loading] 正在运行 jadx 反编译（样本较大时可能需要几十秒到数分钟）..."
  if "$JADX" -d "$JADX_OUT" --no-res "$TARGET" > "$JADX_LOG" 2>&1; then
    echo "[done] jadx 反编译完成"
    SEARCH_DIR="$JADX_OUT"
  else
    echo "[done] jadx 执行结束：失败"
    echo "[WARN] jadx 执行失败。" >&2
    tail -20 "$JADX_LOG" | sed 's/^/       /' >&2
    if [[ -n "$DEXDUMP" ]]; then
      echo "[WARN] 回退到 dexdump。" >&2
      ENGINE="dexdump"
    else
      echo "[FAIL] 没有 dexdump 可回退。" >&2
      exit 1
    fi
  fi
fi

if [[ "$ENGINE" == "dexdump" ]]; then
  DEXDUMP_OUT="$TMP_DIR/dexdump-out"
  mkdir -p "$DEXDUMP_OUT"

  echo "[loading] 正在反汇编 ${#DEX_LIST[@]} 个 DEX（文件较大时可能需要一段时间）..."
  if [[ "$IS_APK" == true ]]; then
    for dex in "${DEX_LIST[@]}"; do
      out="$DEXDUMP_OUT/$(basename "$dex").txt"
      unzip -p "$TARGET" "$dex" > "$TMP_DIR/$(basename "$dex")"
      echo "  - 正在反汇编 $dex ..."
      if ! "$DEXDUMP" -d "$TMP_DIR/$(basename "$dex")" > "$out" 2> "$TMP_DIR/dexdump.err"; then
        echo "[FAIL] dexdump 处理 $dex 失败：" >&2
        tail -10 "$TMP_DIR/dexdump.err" | sed 's/^/       /' >&2
        exit 1
      fi
    done
  else
    out="$DEXDUMP_OUT/$(basename "$TARGET").txt"
    echo "  - 正在反汇编 $(basename "$TARGET") ..."
    if ! "$DEXDUMP" -d "$TARGET" > "$out" 2> "$TMP_DIR/dexdump.err"; then
      echo "[FAIL] dexdump 处理失败：" >&2
      tail -10 "$TMP_DIR/dexdump.err" | sed 's/^/       /' >&2
      exit 1
    fi
  fi
  echo "[done] DEX 反汇编完成：${#DEX_LIST[@]} 个"

  SEARCH_DIR="$DEXDUMP_OUT"
fi

if [[ -z "$SEARCH_DIR" || ! -d "$SEARCH_DIR" ]]; then
  echo "[FAIL] 没有得到可检索的反编译/反汇编结果。" >&2
  exit 1
fi

# ---------- 4. 风险模式检索 ----------
LAST_TOTAL=0

report_category() {
  local title="$1"
  local regex="$2"
  local raw matches count

  raw="$(grep -RInE -- "$regex" "$SEARCH_DIR" 2>/dev/null || true)"
  count="$(printf '%s\n' "$raw" | grep -c . || true)"

  echo "------------------------------------------------------------"
  echo "$title（$count 处）"
  if [[ "$count" -gt 0 ]]; then
    # 用 awk 截断而不是 head：head 提前退出会让 printf 收到 SIGPIPE，
    # 在 set -o pipefail 下会把整个脚本打断。
    matches="$(printf '%s\n' "$raw" | awk -v max="$MAX_MATCHES" 'NR <= max' | sed "s#^$SEARCH_DIR/##")"
    printf '%s\n' "$matches" | sed 's/^/  /'
    if [[ "$count" -gt "$MAX_MATCHES" ]]; then
      echo "  ...（其余 $((count - MAX_MATCHES)) 处已省略）"
    fi
  else
    echo "  (无)"
  fi

  LAST_TOTAL="$count"
}

report_category "日志输出" \
  'Log\.(v|d|i|w|e)\(|System\.out|printStackTrace|println'

report_category "WebView 风险" \
  'addJavascriptInterface|setJavaScriptEnabled|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|loadUrl'

report_category "弱加密 / 硬编码密钥" \
  'AES/ECB|DES/|MD5|SHA-1|Cipher\.getInstance|SecretKeySpec|IvParameterSpec'

report_category "TLS / 证书校验" \
  'X509TrustManager|checkServerTrusted|HostnameVerifier|TrustManager|setSSLSocketFactory'

report_category "本地存储" \
  'SharedPreferences|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getExternalStorage|openFileOutput'

report_category "动态加载 / 执行" \
  'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|System\.load|System\.loadLibrary|Runtime\.exec|ProcessBuilder'

report_category "硬编码敏感信息" \
  'api[_-]?key|apikey|secret|password|passwd|Bearer |BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}'

# 单独统计几个高风险组合，便于结论判断
count_in_search() {
  local regex="$1"
  grep -RInE -- "$regex" "$SEARCH_DIR" 2>/dev/null | wc -l | tr -d ' ' || true
}

WEBVIEW_COUNT="$(count_in_search 'addJavascriptInterface')"
TRUST_COUNT="$(count_in_search 'X509TrustManager|HostnameVerifier|checkServerTrusted')"
WORLD_STORAGE_COUNT="$(count_in_search 'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE')"
DYNAMIC_COUNT="$(count_in_search 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader')"
SECRET_COUNT="$(count_in_search 'BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}')"
LOG_COUNT="$(count_in_search 'Log\.(v|d|i|w|e)\(|System\.out|printStackTrace')"

# ---------- 5. 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

RISK=false

if [[ "$WEBVIEW_COUNT" -gt 0 ]]; then
  echo "  ⚠ 存在 addJavascriptInterface：WebView 与 JS 桥接需确认是否暴露敏感能力。"
  RISK=true
fi
if [[ "$TRUST_COUNT" -gt 0 ]]; then
  echo "  ⚠ 存在自定义 TLS/证书校验：需确认是否错误地信任所有证书。"
  RISK=true
fi
if [[ "$WORLD_STORAGE_COUNT" -gt 0 ]]; then
  echo "  ⚠ 存在 MODE_WORLD_READABLE/WRITEABLE：旧版 Android 上文件可能被其他应用读取。"
  RISK=true
fi
if [[ "$DYNAMIC_COUNT" -gt 0 ]]; then
  echo "  ⚠ 存在动态 DEX 加载：需确认加载来源是否可信。"
  RISK=true
fi
if [[ "$SECRET_COUNT" -gt 0 ]]; then
  echo "  ⚠ 发现私钥标记 / 云厂商密钥形态的字符串：需确认是否为真实凭据。"
  RISK=true
fi
if [[ "$LOG_COUNT" -gt 0 ]]; then
  echo "  - 存在日志输出：需确认发布包是否会打印敏感数据。"
fi

if [[ "$RISK" != true ]]; then
  echo "  未发现上述高风险模式。"
  echo "  这不等于安全：动态行为、反射、native 和其他运行时逻辑不在本脚本范围内。"
  exit 1
fi

echo "  以上为静态检索结果，命中不等于漏洞；请结合调用链和业务逻辑确认。"
exit 0
