#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-help}"
INPUT="${2:-$ROOT/../app-arm64-v8a-release.apk}"
APK="${3:-$ROOT/artifacts/homewoo-custom-home-repackaged-v8.apk}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/evidence}"
SDK="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$SDK/build-tools/36.0.0}"
JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}"
export JAVA_HOME

need_adb() {
  command -v adb >/dev/null || { echo "缺少 adb" >&2; exit 1; }
  adb get-state >/dev/null 2>&1 || { echo "未检测到在线 Android 设备" >&2; exit 1; }
}

verify_original_state() {
  need_adb
  [[ -f "$INPUT" ]] || { echo "原始 APK 不存在: $INPUT" >&2; exit 1; }
  mkdir -p "$EVIDENCE_DIR"
  local stamp local_hash device_hash package_path ui_marker evidence_file
  stamp="$(date +%Y%m%d-%H%M%S)"
  evidence_file="$EVIDENCE_DIR/restore-$stamp.txt"
  "$BUILD_TOOLS/apksigner" verify "$INPUT" >/dev/null
  local_hash="$(sha256sum "$INPUT" | awk '{print $1}')"
  package_path="$(adb shell pm path com.sdmc.homewoo | head -n 1 | tr -d '\r' | sed 's/^package://')"
  [[ "$package_path" == /data/app/*/base.apk ]] || { echo "RESTORE_FAILED: 无法确认设备 APK 路径" >&2; exit 1; }
  device_hash="$(adb shell su -c "sha256sum $package_path" | awk '{print $1}' | tr -d '\r')"
  [[ "$local_hash" == "$device_hash" ]] || { echo "RESTORE_FAILED: 设备 APK 与原始 APK 哈希不一致" >&2; exit 1; }
  adb shell uiautomator dump /sdcard/homewoo-original.xml >/dev/null 2>&1
  if adb shell cat /sdcard/homewoo-original.xml | grep -q '自定义首页'; then
    echo "RESTORE_FAILED: 设备页面仍包含自定义首页" >&2
    exit 1
  fi
  ui_marker="$(adb shell cat /sdcard/homewoo-original.xml | grep -oE 'Home Woo|Your home, organized\.|Calendar' | head -n 1)"
  [[ -n "$ui_marker" ]] || { echo "RESTORE_FAILED: 未发现原始 Homewoo 页面标记" >&2; exit 1; }
  adb shell rm -f /sdcard/homewoo-original.xml >/dev/null 2>&1 || :
  {
    echo "TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "ORIGINAL_APK_SHA256=$local_hash"
    echo "INSTALLED_APK_SHA256=$device_hash"
    echo "INSTALLED_APK_PATH=$package_path"
    echo "ORIGINAL_UI_MARKER=$ui_marker"
    echo "RESTORE_VERIFIED=true"
  } > "$evidence_file"
  echo "RESTORE_EVIDENCE=$evidence_file"
  echo "RESTORE_VERIFIED=true"
}

case "$ACTION" in
  preflight)
    command -v adb >/dev/null || { echo "缺少 adb" >&2; exit 1; }
    command -v apktool >/dev/null || { echo "缺少 apktool" >&2; exit 1; }
    command -v python3 >/dev/null || { echo "缺少 python3" >&2; exit 1; }
    command -v zipalign >/dev/null || command -v "$HOME/Library/Android/sdk/build-tools/36.0.0/zipalign" >/dev/null || { echo "缺少 zipalign" >&2; exit 1; }
    command -v apksigner >/dev/null || command -v "$HOME/Library/Android/sdk/build-tools/36.0.0/apksigner" >/dev/null || { echo "缺少 apksigner" >&2; exit 1; }
    [[ -x "$JAVA_HOME/bin/javac" ]] || { echo "缺少 javac: $JAVA_HOME/bin/javac" >&2; exit 1; }
    [[ -x "$BUILD_TOOLS/d8" ]] || { echo "缺少 d8: $BUILD_TOOLS/d8" >&2; exit 1; }
    [[ -f "$SDK/platforms/android-35/android.jar" ]] || { echo "缺少 Android platform android-35" >&2; exit 1; }
    [[ -f "${KEYSTORE_PATH:-$ROOT/keys/custom-home-test.jks}" ]] || { echo "缺少测试 keystore" >&2; exit 1; }
    adb get-state >/dev/null 2>&1 || { echo "未检测到在线 Android 设备" >&2; exit 1; }
    adb shell su -c id 2>/dev/null | grep -q 'uid=0' || { echo "设备未确认 Root" >&2; exit 1; }
    [[ -f "$INPUT" ]] || { echo "原始 APK 不存在: $INPUT" >&2; exit 1; }
    [[ -f "$APK" ]] || { echo "输出 APK 不存在: $APK" >&2; exit 1; }
    echo "PREFLIGHT_PASSED=true"
    ;;
  build)
    KEYSTORE_PASS="${KEYSTORE_PASS:?请先通过环境变量提供授权测试 keystore 密码}"
    export KEYSTORE_PASS
    exec bash "$ROOT/build_custom_home_attack.sh" "$INPUT" "$APK"
    ;;
  install)
    need_adb
    [[ -f "$APK" ]] || { echo "APK 不存在: $APK" >&2; exit 1; }
    adb push "$APK" /data/local/tmp/homewoo-custom-home-v8.apk
    adb shell su -mm -c 'pm install -r /data/local/tmp/homewoo-custom-home-v8.apk'
    adb shell am force-stop com.sdmc.homewoo
    adb shell am start -n com.sdmc.homewoo/.MainActivity
    ;;
  mock)
    need_adb
    mkdir -p "$EVIDENCE_DIR"
    export LANDING_EVIDENCE_FILE="${LANDING_EVIDENCE_FILE:-$EVIDENCE_DIR/landing.log}"
    adb reverse tcp:18080 tcp:18080
    exec python3 "$ROOT/scripts/local_landing_server.py"
    ;;
  clean-install)
    need_adb
    [[ -f "$APK" ]] || { echo "APK 不存在: $APK" >&2; exit 1; }
    adb push "$APK" /data/local/tmp/homewoo-custom-home-v8.apk
    adb shell su -mm -c 'pm uninstall com.sdmc.homewoo' || true
    adb shell su -mm -c 'pm install -r /data/local/tmp/homewoo-custom-home-v8.apk'
    adb shell am force-stop com.sdmc.homewoo
    adb shell am start -n com.sdmc.homewoo/.MainActivity
    ;;
  verify)
    need_adb
    mkdir -p "$EVIDENCE_DIR"
    STAMP="$(date +%Y%m%d-%H%M%S)"
    UI_FILE="$EVIDENCE_DIR/ui-$STAMP.txt"
    ACTIVITY_FILE="$EVIDENCE_DIR/activity-$STAMP.txt"
    LOG_FILE="$EVIDENCE_DIR/logcat-$STAMP.txt"
    RAW_UI="${TMPDIR:-/tmp}/homewoo-ui-$$.xml"
    cleanup_verify_ui() {
      rm -f "$RAW_UI"
      adb shell rm -f /sdcard/homewoo-custom-home.xml >/dev/null 2>&1 || :
    }
    trap cleanup_verify_ui EXIT
    adb shell uiautomator dump /sdcard/homewoo-custom-home.xml >/dev/null 2>&1
    adb shell cat /sdcard/homewoo-custom-home.xml > "$RAW_UI"
    grep -oE '自定义首页|登录成功后替换原 Homewoo 首页|打开测试落地页' "$RAW_UI" > "$UI_FILE"
    adb shell dumpsys activity activities \
      | grep -E 'mResumedActivity|com.sdmc.homewoo/.MainActivity|CustomHomeActivity' \
      > "$ACTIVITY_FILE"
    if adb logcat -d -t 1000 \
      | sed -E 's/(accessToken|authorization|cookie|signature|password)([=:])[^ ,;]*/\1\2<redacted>/Ig' \
      | grep -E 'HomewooRedirect|FATAL EXCEPTION|LinkageError|Displayed com\.sdmc\.homewoo' \
      > "$LOG_FILE"; then
      LOG_EVIDENCE_PRESENT=true
    else
      LOG_EVIDENCE_PRESENT=false
    fi
    for marker in '自定义首页' '登录成功后替换原 Homewoo 首页' '打开测试落地页'; do
      grep -q "$marker" "$UI_FILE" || { echo "VERIFY_FAILED: 缺少 UI 标记 $marker" >&2; exit 1; }
    done
    grep -q 'com.sdmc.homewoo/.MainActivity' "$ACTIVITY_FILE" || { echo "VERIFY_FAILED: 当前 Activity 不是 Homewoo 主页面" >&2; exit 1; }
    PACKAGE_PATH="$(adb shell pm path com.sdmc.homewoo | head -n 1 | tr -d '\r' | sed 's/^package://')"
    [[ "$PACKAGE_PATH" == /data/app/*/base.apk ]] || { echo "VERIFY_FAILED: 无法确认设备上的 APK 路径" >&2; exit 1; }
    INSTALLED_HASH="$(adb shell su -c "sha256sum $PACKAGE_PATH" | awk '{print $1}' | tr -d '\r')"
    LOCAL_HASH="$(sha256sum "$APK" | awk '{print $1}')"
    [[ "$INSTALLED_HASH" == "$LOCAL_HASH" ]] || { echo "VERIFY_FAILED: 设备 APK 与归档包哈希不一致" >&2; exit 1; }
    sha256sum "$APK" > "$EVIDENCE_DIR/apk-sha256.txt"
    SUMMARY_FILE="$EVIDENCE_DIR/verify-$STAMP.txt"
    {
      echo "TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')"
      echo "INSTALLED_APK_PATH=$PACKAGE_PATH"
      echo "INSTALLED_APK_SHA256=$INSTALLED_HASH"
      echo "LOCAL_APK_SHA256=$LOCAL_HASH"
      echo "UI_EVIDENCE=$UI_FILE"
      echo "ACTIVITY_EVIDENCE=$ACTIVITY_FILE"
      echo "LOG_EVIDENCE_PRESENT=$LOG_EVIDENCE_PRESENT"
      echo "VERIFY_PASSED=true"
    } > "$SUMMARY_FILE"
    echo "VERIFY_PASSED=true"
    echo "LOG_EVIDENCE_PRESENT=$LOG_EVIDENCE_PRESENT"
    echo "INSTALLED_APK_SHA256=$INSTALLED_HASH"
    echo "UI_EVIDENCE=$UI_FILE"
    echo "ACTIVITY_EVIDENCE=$ACTIVITY_FILE"
    echo "LOG_EVIDENCE=$LOG_FILE"
    echo "APK_SHA256_FILE=$EVIDENCE_DIR/apk-sha256.txt"
    echo "VERIFY_SUMMARY=$SUMMARY_FILE"
    ;;
  verify-signature)
    [[ -f "$APK" ]] || { echo "APK 不存在: $APK" >&2; exit 1; }
    "$BUILD_TOOLS/apksigner" verify --verbose "$APK"
    ;;
  verify-landing)
    need_adb
    mkdir -p "$EVIDENCE_DIR"
    LANDING_EVIDENCE_FILE="${LANDING_EVIDENCE_FILE:-$EVIDENCE_DIR/landing.log}"
    BEFORE_LINES=0
    if [[ -f "$LANDING_EVIDENCE_FILE" ]]; then
      BEFORE_LINES="$(wc -l < "$LANDING_EVIDENCE_FILE")"
    fi
    CLICK_RESULT="$(python3 "$ROOT/scripts/click_test_landing.py")"
    echo "$CLICK_RESULT"
    sleep 2
    [[ -f "$LANDING_EVIDENCE_FILE" ]] && tail -n "+$((BEFORE_LINES + 1))" "$LANDING_EVIDENCE_FILE" | grep -q 'LOCAL_TEST_LANDING /test-landing' || {
      echo "VERIFY_FAILED: 本机测试落地页未收到 /test-landing 请求" >&2
      exit 1
    }
    adb shell dumpsys activity activities | grep -Eq 'com.android.browser|com.google.android.apps.chrome' || {
      echo "VERIFY_FAILED: 本机测试落地页未被浏览器打开" >&2
      exit 1
    }
    LANDING_AFTER_LINES="$(wc -l < "$LANDING_EVIDENCE_FILE")"
    LANDING_SUMMARY="$EVIDENCE_DIR/landing-verify-$(date +%Y%m%d-%H%M%S).txt"
    {
      echo "TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')"
      echo "$CLICK_RESULT"
      echo "LANDING_LINES_BEFORE=$BEFORE_LINES"
      echo "LANDING_LINES_AFTER=$LANDING_AFTER_LINES"
      echo "NEW_REQUEST_MARKER=LOCAL_TEST_LANDING /test-landing"
      echo "BROWSER_ACTIVITY_PRESENT=true"
      echo "VERIFY_LANDING_PASSED=true"
    } > "$LANDING_SUMMARY"
    echo "LANDING_EVIDENCE=$LANDING_EVIDENCE_FILE"
    echo "LANDING_SUMMARY=$LANDING_SUMMARY"
    echo "VERIFY_LANDING_PASSED=true"
    ;;
  reopen)
    need_adb
    mkdir -p "$EVIDENCE_DIR"
    REOPEN_FILE="$EVIDENCE_DIR/reopen-$(date +%Y%m%d-%H%M%S).txt"
    echo "REOPEN_STARTED=$(date '+%Y-%m-%d %H:%M:%S %Z')" > "$REOPEN_FILE"
    adb shell am force-stop com.sdmc.homewoo
    echo "FORCE_STOP_COMPLETED=true" >> "$REOPEN_FILE"
    adb shell am start -n com.sdmc.homewoo/.MainActivity | tee -a "$REOPEN_FILE"
    sleep 3
    "$0" verify "$INPUT" "$APK" | tee -a "$REOPEN_FILE"
    echo "REOPEN_VERIFIED=true" | tee -a "$REOPEN_FILE"
    ;;
  verify-original)
    verify_original_state
    ;;
  restore-original)
    need_adb
    adb reverse --remove tcp:18080 >/dev/null 2>&1 || true
    adb shell am force-stop com.sdmc.homewoo
    [[ -f "$INPUT" ]] || { echo "原始 APK 不存在: $INPUT" >&2; exit 1; }
    adb shell su -mm -c 'pm uninstall com.sdmc.homewoo' || true
    adb push "$INPUT" /data/local/tmp/homewoo-original.apk
    adb shell su -mm -c 'pm install -r /data/local/tmp/homewoo-original.apk'
    adb shell monkey -p com.sdmc.homewoo 1
    sleep 2
    verify_original_state
    ;;
  help|*)
    if [[ "$ACTION" != "help" ]]; then
      echo "未知操作: $ACTION" >&2
      exit 2
    fi
    echo "用法:"
    echo "  $0 preflight [原始APK] [输出APK]"
    echo "  $0 build [原始APK] [输出APK]"
    echo "  $0 mock [原始APK] [输出APK]      # 启动本机落地页并建立 adb reverse"
    echo "  $0 install [原始APK] [输出APK]       # 保留应用数据"
    echo "  $0 clean-install [原始APK] [输出APK]  # 清除登录态后安装"
    echo "  $0 verify [原始APK] [输出APK]"
    echo "  $0 verify-signature [原始APK] [输出APK]"
    echo "  $0 verify-landing [原始APK] [输出APK]"
    echo "  $0 reopen [原始APK] [输出APK]"
    echo "  $0 verify-original [原始APK]"
    echo "  $0 restore-original [原始APK]"
    ;;
esac
