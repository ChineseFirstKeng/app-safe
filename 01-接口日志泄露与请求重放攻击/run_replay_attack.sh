#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-help}"
TEST_APK="${TEST_APK:-$ROOT/../app-arm64-v8a-release.apk}"

need_device() {
  command -v adb >/dev/null || { echo "缺少 adb" >&2; exit 1; }
  adb get-state >/dev/null 2>&1 || { echo "未检测到在线 Android 设备" >&2; exit 1; }
  if ! adb shell su -c id 2>/dev/null | grep -q 'uid=0'; then
    echo "设备未确认 Root，停止执行" >&2
    exit 1
  fi
}

case "$ACTION" in
  help)
    echo "用法: $0 preflight|list|create|update|delete|verify|compare|cleanup|restore-original"
    ;;
  preflight)
    need_device
    command -v python3 >/dev/null || { echo "缺少 python3" >&2; exit 1; }
    [[ -f "$TEST_APK" ]] || { echo "测试 APK 不存在: $TEST_APK" >&2; exit 1; }
    [[ "${HOMEWOO_TEST_BASE:-https://xhome-dev.sdmc.tv:18443/aihome/cloud-api/awp}" == https://xhome-dev.sdmc.tv:*/* ]] || { echo "测试端点未声明为授权开发环境" >&2; exit 1; }
    sha256sum "$TEST_APK"
    echo "PREFLIGHT_PASSED=true"
    echo "ADB_STATE=READY"
    adb shell su -c id | sed -E 's/(uid=0[^)]*)/ROOT=\1/'
    ;;
  list|create|update|delete|verify)
    need_device
    export EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/evidence}"
    exec python3 "$ROOT/scripts/homewoo_calendar_replay.py" "$ACTION"
    ;;
  compare)
    if [[ $# -lt 4 ]]; then
      echo "用法: $0 compare {create|update|delete} <before.json> <after.json> [event_id]" >&2
      exit 2
    fi
    exec python3 "$ROOT/scripts/verify_replay_result.py" "${@:2}"
    ;;
  cleanup)
    adb logcat -c
    echo "LOGCAT_CLEARED=true"
    ;;
  restore-original)
    need_device
    adb logcat -c
    echo "RESTORE_SCOPE=仅清理设备日志；本攻击不改写 APK"
    echo "BUSINESS_DATA_CLEANUP=需按证据人工删除测试事件并复核"
    echo "LOGCAT_CLEARED=true"
    ;;
  *)
    echo "未知操作: $ACTION" >&2
    echo "用法: $0 preflight|list|create|update|delete|verify|compare|cleanup|restore-original" >&2
    exit 2
    ;;
esac
