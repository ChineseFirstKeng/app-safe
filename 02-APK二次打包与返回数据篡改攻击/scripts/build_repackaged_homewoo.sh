#!/usr/bin/env bash
set -euo pipefail

# 仅对授权测试 APK 使用，不收集账号、密码、Token 或业务数据。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$SCRIPT_DIR/.."
DEFAULT_SOURCE="$SCRIPT_DIR/../../../app-arm64-v8a-release.apk"
DEFAULT_KEYSTORE="$SCRIPT_DIR/../keys/test-release-v2.jks"
SOURCE_APK="${1:-$DEFAULT_SOURCE}"
TARGET_URL="${2:-http://192.168.68.84:18443}"
OUTPUT_APK="${3:-$WORK_DIR/repackaged-signed-local.apk}"
ANDROID_SDK="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$ANDROID_SDK/build-tools/36.0.0}"
KEYSTORE="${KEYSTORE_PATH:-$DEFAULT_KEYSTORE}"
KEY_ALIAS="${KEY_ALIAS:-test-release}"

python3 "$SCRIPT_DIR/validate_test_target.py" "$TARGET_URL"

[[ -f "$SOURCE_APK" ]] || { echo "SOURCE_APK not found: $SOURCE_APK" >&2; exit 1; }
[[ -f "$KEYSTORE" ]] || { echo "KEYSTORE not found: $KEYSTORE" >&2; exit 1; }
command -v unzip >/dev/null
command -v zip >/dev/null
command -v python3 >/dev/null

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/homewoo-repackaged.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT
unzip -q "$SOURCE_APK" -d "$TEMP_DIR/apk"
rm -rf "$TEMP_DIR/apk/META-INF"

python3 "$SCRIPT_DIR/patch_libapp_url.py" \
  "$TEMP_DIR/apk/lib/arm64-v8a/libapp.so" \
  "https://xhome-dev.sdmc.tv:18443/aihome/cloud-api/cloud/v5.0/" \
  "$TARGET_URL/aihome/cloud-api/cloud/v5.0/"

(
  cd "$TEMP_DIR/apk"
  zip -qr -0 "$TEMP_DIR/unsigned.apk" .
)
"$BUILD_TOOLS/zipalign" -p -f 4096 "$TEMP_DIR/unsigned.apk" "$TEMP_DIR/aligned.apk"

KEYSTORE_PASS="${KEYSTORE_PASS:?Set KEYSTORE_PASS in the environment; do not write it in this script}"
"$BUILD_TOOLS/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "env:KEYSTORE_PASS" \
  --out "$OUTPUT_APK" \
  "$TEMP_DIR/aligned.apk"
"$BUILD_TOOLS/apksigner" verify --verbose "$OUTPUT_APK"
echo "OUTPUT_APK=$OUTPUT_APK"
