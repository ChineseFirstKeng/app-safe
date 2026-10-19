#!/usr/bin/env bash
#
# 04-apksigner-check.sh —— 通用静态分析：APK 签名与证书检查
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   调用 apksigner 验证 APK 签名，回答：
#     - 签名是否有效（密码学上是否自洽）？
#     - 启用了 v1/v2/v3/v3.1/v4 哪些方案？
#     - 有几个签名者？证书 DN 和 SHA-256 摘要是什么？
#     - 是否与给定的官方证书摘要一致？
#
#   重要：
#     apksigner 输出 “Verifies” 只代表“签名与证书自洽”，
#     不代表“官方发布”“可信”“没有被改过”。
#     攻击者用自己的证书重打包，同样会 Verifies。
#     判断是否被换签，必须比对证书 SHA-256。
#
#   适用范围：
#     仅适用于 APK / split APK。
#     AAB、APKS、IPA、JAR 会在预检阶段被识别并给出对应处理建议。
#
# 依赖：
#   unzip、java、apksigner
#   缺少时明确提示安装方式并退出，不会静默跳过检查。
#
# 用法：
#   ./04-apksigner-check.sh <APK 路径>
#   ./04-apksigner-check.sh <APK 路径> <期望的证书SHA-256>
#   EXPECTED_CERT_SHA256=<值> ./04-apksigner-check.sh <APK 路径>
#
# 退出码：
#   0 = 签名有效（若提供证书基准，则还要求至少一个签名者匹配）
#   1 = 签名无效/未签名，或证书与基准不一致
#   2 = 参数、依赖、或输入不是 APK
#
set -euo pipefail
export LC_ALL=C

TARGET="${1:-}"
EXPECTED_CERT="${2:-${EXPECTED_CERT_SHA256:-}}"

if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  echo "用法: $0 <APK 路径> [期望的证书SHA-256]"
  exit 2
fi
if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] 文件不存在: $TARGET" >&2
  exit 2
fi

# ---------- 1. 依赖检查 ----------
if ! command -v unzip >/dev/null 2>&1; then
  echo "[FAIL] 缺少工具: unzip" >&2
  echo "       安装提示: macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip" >&2
  exit 2
fi

# JAVA_HOME 指向文件时（例如 /usr/bin/java）会让部分工具误判，先清掉
if [[ -n "${JAVA_HOME:-}" && ! -x "$JAVA_HOME/bin/java" ]]; then
  unset JAVA_HOME
fi
if ! command -v java >/dev/null 2>&1; then
  if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
    export PATH="$JAVA_HOME/bin:$PATH"
  else
    echo "[FAIL] 找不到 java；apksigner 需要 JDK/JRE。" >&2
    echo "       macOS: brew install openjdk@17" >&2
    echo "              然后设置 JAVA_HOME，例如：" >&2
    echo "              export JAVA_HOME=\$(/usr/libexec/java_home -v 17)" >&2
    echo "       Linux: sudo apt install openjdk-17-jdk" >&2
    echo "              或 sudo dnf install java-17-openjdk" >&2
    exit 2
  fi
fi

# 优先 PATH；否则在常见 Android SDK 目录中查找可执行的 apksigner
find_apksigner() {
  if command -v apksigner >/dev/null 2>&1; then
    command -v apksigner
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
      candidate="$root/build-tools/$ver/apksigner"
      if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return 0
      fi
    done < <(ls -1 "$root/build-tools" 2>/dev/null \
      | sort -t. -k1,1nr -k2,2nr -k3,3nr)
  done
  return 1
}

APKSIGNER="$(find_apksigner)" || {
  echo "[FAIL] 找不到 apksigner。" >&2
  echo "       安装方式：" >&2
  echo "         1) Android Studio → SDK Manager → SDK Tools → Android SDK Build-Tools" >&2
  echo "         2) 或命令行：sdkmanager \"build-tools;34.0.0\"" >&2
  echo "         3) 安装后把 build-tools/<版本> 加入 PATH，" >&2
  echo "            或设置 ANDROID_HOME / ANDROID_SDK_ROOT" >&2
  exit 2
}

# ---------- 2. 预检：先识别容器类型 ----------
# apksigner 只认 APK。直接拿 AAB/APKS/IPA/JAR/普通 ZIP 喂给它，
# 会输出 Java 异常或误导性的“签名无效”。这里先做类型识别。
ZIP_ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
if [[ -z "$ZIP_ENTRIES" ]]; then
  echo "============================================================"
  echo "静态分析 04：APK 签名与证书检查"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  echo "无法读取 ZIP 目录：这不是有效的 ZIP/APK，或文件已经损坏。"
  echo "建议：先确认文件类型和来源。"
  exit 2
fi

HAS_ROOT_MANIFEST=false
HAS_AAB=false
HAS_APKS=false
HAS_IPA=false

if grep -qx 'AndroidManifest.xml' <<<"$ZIP_ENTRIES"; then
  HAS_ROOT_MANIFEST=true
fi
if grep -qx 'BundleConfig.pb' <<<"$ZIP_ENTRIES"; then
  HAS_AAB=true
fi
if grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ZIP_ENTRIES"; then
  HAS_AAB=true
fi
if grep -qx 'toc.pb' <<<"$ZIP_ENTRIES" && grep -qE '\.apk$' <<<"$ZIP_ENTRIES"; then
  HAS_APKS=true
fi
if grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ZIP_ENTRIES"; then
  HAS_IPA=true
fi

if [[ "$HAS_ROOT_MANIFEST" != true ]]; then
  echo "============================================================"
  echo "静态分析 04：APK 签名与证书检查"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  if [[ "$HAS_AAB" == true ]]; then
    echo "这是 Android App Bundle（AAB），不是可直接安装的 APK。"
    echo "apksigner 不能直接验证 AAB；请先用 bundletool 生成 APK 集，再逐个验证。"
  elif [[ "$HAS_APKS" == true ]]; then
    echo "这是 APK 集合（.apks），不是单个 APK。"
    echo "请先解出 base.apk 和各个 split APK，再逐个验证签名。"
  elif [[ "$HAS_IPA" == true ]]; then
    echo "这是 iOS IPA；apksigner 不适用。"
    echo "请用 codesign / plutil / otool 按 iOS 流程分析。"
  else
    echo "这不是 Android APK：ZIP 根目录没有 AndroidManifest.xml。"
    echo "apksigner 只适用于 APK；请先确认输入文件类型。"
  fi
  exit 2
fi

# ---------- 3. 执行签名验证 ----------
# 同时捕获 stdout/stderr；退出码单独保存，避免 set -e 直接终止
APKSIGNER_OUTPUT="$("$APKSIGNER" verify --verbose --print-certs "$TARGET" 2>&1)" \
  && APKSIGNER_RC=0 || APKSIGNER_RC=$?

echo "============================================================"
echo "静态分析 04：APK 签名与证书检查"
echo "目标：$TARGET"
echo "工具：$APKSIGNER"
echo "============================================================"
echo "$APKSIGNER_OUTPUT"

# ---------- 4. 解析结果 ----------
VERIFIED=false
if [[ "$APKSIGNER_RC" -eq 0 ]] && grep -q '^Verifies$' <<<"$APKSIGNER_OUTPUT"; then
  VERIFIED=true
fi

get_field() {
  # 取以 key 开头的那一行，去掉 "key:" 前缀，保留值里的冒号
  local key="$1"
  awk -v key="$key" 'index($0, key) == 1 {
    v = substr($0, length(key) + 1)
    sub(/^[[:space:]]*:[[:space:]]*/, "", v)
    print v
    exit
  }' <<<"$APKSIGNER_OUTPUT"
}

V1="$(get_field 'Verified using v1 scheme (JAR signing)')"
V2="$(get_field 'Verified using v2 scheme (APK Signature Scheme v2)')"
V3="$(get_field 'Verified using v3 scheme (APK Signature Scheme v3)')"
V31="$(get_field 'Verified using v3.1 scheme (APK Signature Scheme v3.1)')"
V4="$(get_field 'Verified using v4 scheme (APK Signature Scheme v4)')"
SIGNER_COUNT="$(get_field 'Number of signers')"
CERT_DN="$(get_field 'Signer #1 certificate DN')"
CERT_SHA256="$(get_field 'Signer #1 certificate SHA-256 digest')"
KEY_ALG="$(get_field 'Signer #1 key algorithm')"
KEY_SIZE="$(get_field 'Signer #1 key size (bits)')"

# 归一化证书摘要：允许带冒号、空格、大写
extract_sha256() {
  local value lower token
  value="$1"
  lower="$(printf '%s' "$value" | tr 'A-F' 'a-f')"
  token="$(printf '%s' "$lower" | grep -Eo '[0-9a-f]{64}' | head -1 || true)"
  if [[ -n "$token" ]]; then
    printf '%s' "$token"
  else
    printf '%s' "$lower" | tr -cd '0-9a-f'
  fi
}

NORMALIZED_EXPECTED="$(extract_sha256 "$EXPECTED_CERT")"
NORMALIZED_ACTUAL="$(extract_sha256 "$CERT_SHA256")"

# ---------- 5. 输出结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

if [[ "$VERIFIED" != true ]]; then
  echo "签名无效或未签名。"
  echo "apksigner 退出码：$APKSIGNER_RC"
  echo "这不是一个可正常安装/发布的已签名 APK；"
  echo "如果这是重打包产物，说明签名步骤失败，或证书/对齐有问题。"
  exit 1
fi

echo "签名在密码学上有效：APK 内容与签名者证书自洽。"
echo "签名方案：v1=${V1:-?}  v2=${V2:-?}  v3=${V3:-?}  v3.1=${V31:-?}  v4=${V4:-?}"
echo "签名者数量：${SIGNER_COUNT:-?}"
echo "签名者 #1 DN：${CERT_DN:-?}"
echo "签名者 #1 证书 SHA-256：${CERT_SHA256:-?}"
echo "密钥算法：${KEY_ALG:-?} ${KEY_SIZE:-?} bit"

# 多签名者时逐一列出，避免只看到 #1
if [[ "${SIGNER_COUNT:-1}" =~ ^[0-9]+$ && "${SIGNER_COUNT:-1}" -gt 1 ]]; then
  echo "检测到多个签名者，逐一列出："
  grep -E '^Signer #[0-9]+ certificate (DN|SHA-256 digest):' <<<"$APKSIGNER_OUTPUT" \
    | sed 's/^/  /' || true
fi

if [[ -n "$NORMALIZED_EXPECTED" ]]; then
  MATCH=false
  if [[ -n "$NORMALIZED_ACTUAL" && "$NORMALIZED_ACTUAL" == "$NORMALIZED_EXPECTED" ]]; then
    MATCH=true
  else
    # 多签名者：只要任意一个证书摘要匹配基准，就认为“至少有一个签名者是预期的”
    while IFS= read -r digest; do
      [[ -z "$digest" ]] && continue
      if [[ "$(extract_sha256 "$digest")" == "$NORMALIZED_EXPECTED" ]]; then
        MATCH=true
        break
      fi
    done < <(grep -E '^Signer #[0-9]+ certificate SHA-256 digest:' <<<"$APKSIGNER_OUTPUT" \
      | sed -E 's/^[^:]+:[[:space:]]*//' || true)
  fi

  if [[ "$MATCH" == true ]]; then
    echo "证书摘要与基准一致：至少有一个签名者的证书是预期证书。"
    if [[ "${SIGNER_COUNT:-1}" =~ ^[0-9]+$ && "${SIGNER_COUNT:-1}" -gt 1 ]]; then
      echo "注意：该 APK 有多个签名者，仍需逐个确认其余签名者是否可信。"
    fi
    exit 0
  else
    echo "证书摘要与基准不一致：没有任何签名者的证书匹配基准。"
    echo "这通常意味着 APK 被换签/重打包，或你拿错了基准包。"
    exit 1
  fi
fi

echo "未提供官方证书基准，因此只能确认“签名自洽”，不能确认“官方发布”。"
echo "请把上面的证书 SHA-256 与官方包/官方证书摘要比对。"
echo "提示：v2/v3 的存在只说明签名覆盖范围和是否支持轮换，不能单独作为篡改证据。"
exit 0
