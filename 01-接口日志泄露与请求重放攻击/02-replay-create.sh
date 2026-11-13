#!/usr/bin/env bash
#
# 02-replay-create.sh —— 重放最近一条 create 请求，新增一条日历
#
# 用法：
#   ./02-replay-create.sh
#
# 说明：
#   - 调用 run_replay_attack.sh create；
#   - 需要 App 已经产生过 create 请求（日志中有 XHOME_API create 块）；
#   - 建议先用 01-dump-logcat.sh 确认日志里有 create 请求。
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "$ROOT/run_replay_attack.sh" create
