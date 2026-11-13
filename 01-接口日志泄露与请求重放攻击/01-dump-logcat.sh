#!/usr/bin/env bash
#
# 01-dump-logcat.sh —— 导出当前设备日志
#
# 用法：
#   ./01-dump-logcat.sh
#   ./01-dump-logcat.sh /tmp/homewoo-log.txt
#   ./01-dump-logcat.sh --help
#
# 说明：
#   - 执行 adb logcat -d，把当前日志原样写入文件；
#   - 不统计、不筛选、不修改设备；
#   - 默认输出到 evidence/logcat-<时间戳>.txt。
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

case "${1:-}" in
  -h|--help)
    echo "用法: $0 [输出文件]"
    echo "默认: $ROOT/evidence/logcat-<时间戳>.txt"
    exit 0
    ;;
esac

OUT="${1:-$ROOT/evidence/logcat-$(date +%Y%m%d-%H%M%S).txt}"

command -v adb >/dev/null 2>&1 || {
  echo "[FAIL] 缺少 adb" >&2
  exit 2
}

adb get-state >/dev/null 2>&1 || {
  echo "[FAIL] 未检测到在线 Android 设备" >&2
  exit 2
}

mkdir -p "$(dirname "$OUT")"
adb logcat -d > "$OUT"

echo "日志已保存: $OUT"
echo "注意：日志可能包含 Token、签名等敏感信息，请勿提交或外发。"
