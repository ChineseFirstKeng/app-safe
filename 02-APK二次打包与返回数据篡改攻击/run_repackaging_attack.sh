#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-help}"
APK="${2:-$ROOT/artifacts/homewoo-repackaged-local-mock.apk}"
SDK="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$SDK/build-tools/36.0.0}"
JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}"
export JAVA_HOME

need_adb() {
  command -v adb >/dev/null || { echo "缺少 adb" >&2; exit 1; }
  adb get-state >/dev/null 2>&1 || { echo "未检测到在线 Android 设备" >&2; exit 1; }
}

case "$ACTION" in
  mock)
    mkdir -p "$ROOT/evidence"
    export MOCK_EVIDENCE_FILE="${MOCK_EVIDENCE_FILE:-$ROOT/evidence/mock-events.log}"
    exec python3 "$ROOT/scripts/mock_calendar_server.py"
    ;;
  preflight)
    command -v adb >/dev/null || { echo "缺少 adb" >&2; exit 1; }
    command -v python3 >/dev/null || { echo "缺少 python3" >&2; exit 1; }
    [[ -x "$JAVA_HOME/bin/java" ]] || { echo "缺少 Java: $JAVA_HOME/bin/java" >&2; exit 1; }
    command -v unzip >/dev/null || { echo "缺少 unzip" >&2; exit 1; }
    command -v zip >/dev/null || { echo "缺少 zip" >&2; exit 1; }
    command -v apktool >/dev/null || { echo "缺少 apktool" >&2; exit 1; }
    [[ -x "$BUILD_TOOLS/zipalign" ]] || { echo "缺少 zipalign: $BUILD_TOOLS/zipalign" >&2; exit 1; }
    [[ -x "$BUILD_TOOLS/apksigner" ]] || { echo "缺少 apksigner: $BUILD_TOOLS/apksigner" >&2; exit 1; }
    [[ -f "${KEYSTORE_PATH:-$ROOT/keys/test-release-v2.jks}" ]] || { echo "缺少测试 keystore" >&2; exit 1; }
    adb get-state >/dev/null 2>&1 || { echo "未检测到在线 Android 设备" >&2; exit 1; }
    adb shell su -c id 2>/dev/null | grep -q 'uid=0' || { echo "设备未确认 Root" >&2; exit 1; }
    [[ -f "$APK" ]] || { echo "APK 不存在: $APK" >&2; exit 1; }
    echo "PREFLIGHT_PASSED=true"
    ;;
  build)
    SOURCE="${2:-$ROOT/../app-arm64-v8a-release.apk}"
    TARGET="${3:-http://192.168.68.84:18443}"
    OUTPUT="${4:-$ROOT/artifacts/homewoo-repackaged-new.apk}"
    python3 "$ROOT/scripts/validate_test_target.py" "$TARGET"
    exec bash "$ROOT/scripts/build_repackaged_homewoo.sh" "$SOURCE" "$TARGET" "$OUTPUT"
    ;;
  install)
    need_adb
    [[ -f "$APK" ]] || { echo "APK 不存在: $APK" >&2; exit 1; }
    adb push "$APK" /data/local/tmp/homewoo-repackaged-test.apk
    adb shell su -mm -c 'pm install -r /data/local/tmp/homewoo-repackaged-test.apk'
    adb shell monkey -p com.sdmc.homewoo 1
    ;;
  clean-install)
    need_adb
    [[ -f "$APK" ]] || { echo "APK 不存在: $APK" >&2; exit 1; }
    adb push "$APK" /data/local/tmp/homewoo-repackaged-test.apk
    adb shell su -mm -c 'pm uninstall com.sdmc.homewoo' || true
    adb shell su -mm -c 'pm install -r /data/local/tmp/homewoo-repackaged-test.apk'
    adb shell monkey -p com.sdmc.homewoo 1
    ;;
  verify)
    need_adb
    EXPECTED_TARGET="${EXPECTED_TARGET:-http://192.168.68.84:18443}"
    command -v strings >/dev/null || { echo "缺少 strings" >&2; exit 1; }
    unzip -p "$APK" lib/arm64-v8a/libapp.so | strings | grep -q "$EXPECTED_TARGET" || {
      echo "VERIFY_FAILED: APK 内嵌目标地址不匹配: $EXPECTED_TARGET" >&2
      exit 1
    }
    EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/evidence}"
    mkdir -p "$EVIDENCE_DIR"
    EVIDENCE_FILE="$EVIDENCE_DIR/verify-$(date +%Y%m%d-%H%M%S).xml"
    cleanup_verify_ui() {
      adb shell rm -f /sdcard/homewoo-window.xml >/dev/null 2>&1 || :
    }
    trap cleanup_verify_ui EXIT
    adb shell uiautomator dump /sdcard/homewoo-window.xml >/dev/null 2>&1
    adb shell cat /sdcard/homewoo-window.xml \
      | grep -oE 'TAMPERED_BY_REPACKAGED_APP|Calendar|No event' \
      > "$EVIDENCE_FILE"
    if ! grep -q 'TAMPERED_BY_REPACKAGED_APP' "$EVIDENCE_FILE"; then
      echo "VERIFY_FAILED: 未发现篡改标记，证据=$EVIDENCE_FILE" >&2
      exit 1
    fi
    MOCK_EVIDENCE_FILE="${MOCK_EVIDENCE_FILE:-$ROOT/evidence/mock-events.log}"
    if [[ ! -f "$MOCK_EVIDENCE_FILE" ]] || ! grep -q 'MOCK_RESPONSE_SENT marker=TAMPERED_BY_REPACKAGED_APP' "$MOCK_EVIDENCE_FILE"; then
      echo "VERIFY_FAILED: 未发现 Mock 收到目标请求的证据" >&2
      exit 1
    fi
    sha256sum "$APK" > "$EVIDENCE_DIR/apk-sha256.txt"
    echo "VERIFY_PASSED=true"
    echo "EVIDENCE_FILE=$EVIDENCE_FILE"
    echo "MOCK_EVIDENCE_FILE=$MOCK_EVIDENCE_FILE"
    echo "APK_SHA256_FILE=$EVIDENCE_DIR/apk-sha256.txt"
    ;;
  verify-signature)
    [[ -f "$APK" ]] || { echo "APK 不存在: $APK" >&2; exit 1; }
    "$BUILD_TOOLS/apksigner" verify --verbose "$APK"
    ;;
  restore-original)
    need_adb
    SOURCE="${2:-$ROOT/../app-arm64-v8a-release.apk}"
    [[ -f "$SOURCE" ]] || { echo "原始 APK 不存在: $SOURCE" >&2; exit 1; }
    adb shell su -mm -c 'pm uninstall com.sdmc.homewoo' || true
    adb push "$SOURCE" /data/local/tmp/homewoo-original.apk
    adb shell su -mm -c 'pm install -r /data/local/tmp/homewoo-original.apk'
    adb shell monkey -p com.sdmc.homewoo 1
    "$BUILD_TOOLS/apksigner" verify --verbose "$SOURCE"
    sha256sum "$SOURCE"
    adb shell uiautomator dump /sdcard/homewoo-original.xml >/dev/null 2>&1
    adb shell cat /sdcard/homewoo-original.xml | grep -q 'TAMPERED_BY_REPACKAGED_APP' && {
      echo "RESTORE_FAILED: 设备页面仍包含篡改标记" >&2
      exit 1
    }
    adb shell cat /sdcard/homewoo-original.xml | grep -Eq 'Home Woo|Your home, organized\.|Calendar' || {
      echo "RESTORE_FAILED: 未发现原始 Homewoo 页面标记" >&2
      exit 1
    }
    echo "RESTORE_VERIFIED=true"
    ;;
  help|*)
    if [[ "$ACTION" != "help" ]]; then
      echo "未知操作: $ACTION" >&2
      exit 2
    fi
    echo "用法: $0 preflight|mock|build|install|clean-install|verify|verify-signature|restore-original [参数]"
    ;;
esac
