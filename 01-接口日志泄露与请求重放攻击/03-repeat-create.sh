#!/usr/bin/env bash
#
# 03-repeat-create.sh —— 重复重放最近一条 create 请求
#
# 用途：
#   把日志里同一条 create 请求重复发送 N 次，观察服务端是否每次都接受。
#
# 参数：
#   --times N     必填
#                 格式：正整数（^[1-9][0-9]*$），最大 100
#                 示例：--times 5
#                 说明：重复次数
#
#   --delay S     可选
#                 格式：非负整数（^[0-9]+$）
#                 默认：1
#                 示例：--delay 1
#                 说明：每次之间的间隔秒数
#
#   --yes         可选
#                 格式：布尔开关，不带值
#                 说明：跳过交互确认；非交互环境必须带
#
# 依赖：
#   adb、python3、可用的 Root 测试设备
#
# 用法：
#   ./03-repeat-create.sh --times 5
#   ./03-repeat-create.sh --times 5 --delay 1 --yes
#   ./03-repeat-create.sh --help
#
# 输出：
#   每次重放的 ACTION / HTTP_STATUS / RETURN_CODE / BUSINESS_SUCCESS；
#   证据写入 evidence/repeat-<时间戳>/<序号>/。
#
# 退出码：
#   0 = 全部成功
#   1 = 有失败
#   2 = 参数、环境或日志错误
#
# 注意：
#   这是写操作，会创建多条日历事件。演示后请在 App 中删除这些事件，
#   并撤销测试会话。
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TIMES=""
DELAY=1
YES=false

usage() {
  cat <<'EOF'
用法:
  ./03-repeat-create.sh --times N [--delay S] [--yes]
  ./03-repeat-create.sh --help

参数:
  --times N   必填。重复次数，正整数，最大 100。
  --delay S   可选。每次间隔秒数，默认 1。
  --yes       可选。跳过交互确认；非交互环境必须带。

示例:
  ./03-repeat-create.sh --times 5
  ./03-repeat-create.sh --times 5 --delay 1 --yes

退出码:
  0 = 全部成功
  1 = 有失败
  2 = 参数、环境或日志错误
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --times)
      [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || {
        echo "[FAIL] --times 需要正整数。" >&2
        usage >&2
        exit 2
      }
      TIMES="$2"
      shift 2
      ;;
    --delay)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || {
        echo "[FAIL] --delay 需要非负整数。" >&2
        usage >&2
        exit 2
      }
      DELAY="$2"
      shift 2
      ;;
    --yes)
      YES=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] 未知参数: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$TIMES" ]] || {
  echo "[FAIL] 缺少 --times。" >&2
  usage >&2
  exit 2
}

(( TIMES <= 100 )) || {
  echo "[FAIL] --times 最大 100，收到 $TIMES。" >&2
  exit 2
}

if [[ "$YES" != true ]]; then
  if [[ -t 0 ]]; then
    read -r -p "将重放 create ${TIMES} 次，确认？[y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || {
      echo "已取消。"
      exit 1
    }
  else
    echo "[FAIL] 非交互环境需要 --yes。" >&2
    exit 2
  fi
fi

command -v adb >/dev/null 2>&1 || {
  echo "[FAIL] 缺少 adb。" >&2
  exit 2
}

echo "[loading] 正在执行 preflight..."
"$ROOT/run_replay_attack.sh" preflight

if ! adb logcat -d -b main 2>/dev/null | grep -q '/calendar/event/create'; then
  echo "[FAIL] 日志中没有 create 请求。" >&2
  echo "       请先在 App 中新建一条测试事件，再运行本脚本。" >&2
  exit 2
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BASE_DIR="$ROOT/evidence/repeat-$STAMP"
mkdir -p "$BASE_DIR"

OK=0
FAIL=0

for i in $(seq 1 "$TIMES"); do
  echo "=== [$i/$TIMES] ==="
  if EVIDENCE_DIR="$BASE_DIR/$i" "$ROOT/run_replay_attack.sh" create; then
    OK=$((OK + 1))
  else
    FAIL=$((FAIL + 1))
  fi
  if [[ "$i" -lt "$TIMES" && "$DELAY" -gt 0 ]]; then
    sleep "$DELAY"
  fi
done

echo "============================================================"
echo "重复重放完成：成功 $OK，失败 $FAIL"
echo "证据目录：$BASE_DIR"
echo "============================================================"
echo "注意：这是写操作。演示后请在 App 中删除新增事件，并撤销测试会话。"

[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
