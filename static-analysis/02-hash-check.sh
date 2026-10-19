#!/usr/bin/env bash
#
# 02-hash-check.sh —— 通用静态分析：样本指纹
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   计算任意文件的 SHA-256（以及辅助的 SHA-1），用于：
#     1) 记录样本唯一身份；
#     2) 与官方/已知样本哈希比对；
#     3) 分析前后确认文件没有被改动。
#
#   只回答“是不是同一份文件”，不回答“是否恶意”。
#
# 依赖：
#   SHA-256：shasum、sha256sum、openssl 三者至少一个；
#   SHA-1  ：可选，找不到时只给出安装提示，不影响 SHA-256。
#   缺少必需依赖时会明确提示安装方式并退出，不会静默跳过检查。
#
# 用法：
#   ./02-hash-check.sh <文件路径>
#   ./02-hash-check.sh <文件路径> <期望的 SHA-256>
#   EXPECTED_SHA256=<期望值> ./02-hash-check.sh <文件路径>
#
# 退出码：
#   0 = 提供了基准且一致
#   1 = 提供了基准但不一致
#   2 = 参数/依赖错误
#   3 = 没有提供基准（仅记录指纹）
#
set -euo pipefail
export LC_ALL=C

TARGET="${1:-}"
EXPECTED="${2:-${EXPECTED_SHA256:-}}"

if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  echo "用法: $0 <文件路径> [期望的SHA-256]"
  exit 2
fi
if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] 文件不存在: $TARGET" >&2
  exit 2
fi

# ---------- 依赖检查与哈希计算 ----------
SHA256=""
if command -v shasum >/dev/null 2>&1; then
  SHA256="$(shasum -a 256 "$TARGET" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  SHA256="$(sha256sum "$TARGET" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
  SHA256="$(openssl dgst -sha256 "$TARGET" | awk '{print $NF}')"
else
  echo "[FAIL] 缺少 SHA-256 工具。" >&2
  echo "       macOS 通常自带 shasum；Linux 可安装 coreutils 或 openssl：" >&2
  echo "       sudo apt install coreutils openssl" >&2
  echo "       sudo dnf install coreutils openssl" >&2
  exit 2
fi

# SHA-1 只作为辅助指纹；找不到时提示安装，不阻断 SHA-256。
SHA1=""
if command -v shasum >/dev/null 2>&1; then
  SHA1="$(shasum -a 1 "$TARGET" | awk '{print $1}')"
elif command -v sha1sum >/dev/null 2>&1; then
  SHA1="$(sha1sum "$TARGET" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
  SHA1="$(openssl dgst -sha1 "$TARGET" | awk '{print $NF}')"
else
  SHA1="(未找到 SHA-1 工具；安装 coreutils 或 openssl 后可输出)"
fi

SIZE_BYTES="$(wc -c < "$TARGET" | tr -d ' ')"

echo "============================================================"
echo "静态分析 02：样本指纹"
echo "目标：$TARGET"
echo "============================================================"
echo "SHA-256 : $SHA256"
echo "SHA-1   : $SHA1"
echo "大小    : $SIZE_BYTES 字节"

# ---------- 基准归一化 ----------
# 支持直接传 64 位十六进制，也支持 "SHA256 (file) = ..." 这类整行文本。
extract_sha256() {
  local value lower token
  value="$1"
  lower="$(printf '%s' "$value" | tr 'A-F' 'a-f')"
  token="$(printf '%s' "$lower" | grep -Eo '[0-9a-f]{64}' | head -1 || true)"
  if [[ -n "$token" ]]; then
    printf '%s' "$token"
  else
    # 兜底：去掉冒号、空格等分隔符后再取十六进制字符
    printf '%s' "$lower" | tr -cd '0-9a-f'
  fi
}

NORMALIZED_EXPECTED="$(extract_sha256 "$EXPECTED")"

# ---------- 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

if [[ -z "$NORMALIZED_EXPECTED" ]]; then
  echo "已记录样本指纹。"
  echo "未提供基准哈希，因此无法判断样本是否被替换或修改。"
  echo "把下面这行写入基线，后续用同一命令复核："
  echo "  $SHA256  $TARGET"
  exit 3
fi

if [[ "$SHA256" == "$NORMALIZED_EXPECTED" ]]; then
  echo "SHA-256 与基准一致：样本逐字节相同。"
  echo "这只能证明“是同一份文件”，不能证明“文件安全”。"
  exit 0
fi

echo "SHA-256 与基准不一致：样本至少有一个字节不同。"
echo "可能原因："
echo "  - 被重新打包、重签名或内容修改；"
echo "  - 不是同一版本/同一构建；"
echo "  - 基准值或样本路径拿错了。"
echo "可进一步检查："
echo "  - 容器结构是否变化；"
echo "  - 签名证书是否变化（仅 APK）；"
echo "  - 对两个样本做内容级 diff，定位具体改动。"
exit 1
