#!/usr/bin/env bash
set -euo pipefail

# 仅对授权测试 APK 使用，不收集账号、密码、Token 或业务数据。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$SCRIPT_DIR/.."
DEFAULT_SOURCE="$SCRIPT_DIR/../../../homewoo_1.0.0_202610191500_arm64.apk"
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
command -v python3 >/dev/null

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/homewoo-repackaged.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT
# 不整包解压：APK 里有大小写仅一位之差的资源名（如 res/9n.9.png 与
# res/9N.9.png），大小写不敏感的文件系统会把它们合并，zip 再打包时会提示
# “replace ...?”。这里只取出 libapp.so，其余条目用 Python zipfile 原样复制。
unzip -p "$SOURCE_APK" lib/arm64-v8a/libapp.so > "$TEMP_DIR/libapp.so"

# 31 字节前缀替换：主机名变短留下的差额由 patch_libapp_url.py 用 '/' 补足。
# 这样业务基地址和帮助页常量会一起被替换，且与主文档 7.3 的产物一致。
python3 "$SCRIPT_DIR/patch_libapp_url.py" \
  "$TEMP_DIR/libapp.so" \
  "https://xhome-dev.sdmc.tv:18443" \
  "$TARGET_URL"

python3 - "$SOURCE_APK" "$TEMP_DIR/libapp.so" "$TEMP_DIR/unsigned.apk" <<'PYEOF'
import sys, zipfile
src, patched, out = sys.argv[1:]
new_lib = open(patched, 'rb').read()
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, 'w') as zout:
    for info in zin.infolist():
        if info.filename.startswith('META-INF/'):
            continue
        data = zin.read(info.filename)
        if info.filename == 'lib/arm64-v8a/libapp.so':
            data = new_lib
            info.compress_type = zipfile.ZIP_STORED
        zout.writestr(info, data)
PYEOF
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
