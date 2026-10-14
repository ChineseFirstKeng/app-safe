#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APK="${TEST_APK:-$ROOT/../app-arm64-v8a-release.apk}"
ACTION="${1:-help}"

case "$ACTION" in
  help)
    echo "用法: $0 preflight|extract|forge-invalid|verify|restore-original"
    echo "TEST_APK 可指定原始 APK；forge-invalid 只测试明显无效的 OAuth 回调。"
    ;;
  preflight)
    command -v adb >/dev/null || { echo "缺少 adb" >&2; exit 1; }
    command -v python3 >/dev/null || { echo "缺少 python3" >&2; exit 1; }
    adb get-state >/dev/null 2>&1 || { echo "没有在线 Android 设备" >&2; exit 1; }
    python3 "$ROOT/scripts/extract_apk_deeplink.py" "$APK"
    python3 "$ROOT/scripts/forge_invalid_callback.py" preflight "$APK" "$ROOT/evidence"
    ;;
  extract)
    python3 "$ROOT/scripts/extract_apk_deeplink.py" "$APK"
    ;;
  forge-invalid|verify|restore-original)
    command -v adb >/dev/null || { echo "缺少 adb" >&2; exit 1; }
    command -v python3 >/dev/null || { echo "缺少 python3" >&2; exit 1; }
    python3 "$ROOT/scripts/forge_invalid_callback.py" "$ACTION" "$APK" "$ROOT/evidence"
    ;;
  *)
    echo "未知操作: $ACTION" >&2
    exit 2
    ;;
esac
