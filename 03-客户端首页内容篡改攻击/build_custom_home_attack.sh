#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
INPUT="${1:-$ROOT/../app-arm64-v8a-release.apk}"
OUTPUT="${2:-$ROOT/artifacts/homewoo-custom-home-repackaged.apk}"
SDK="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
BT="${ANDROID_BUILD_TOOLS:-$SDK/build-tools/36.0.0}"
JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}"
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"
KEYSTORE="${KEYSTORE_PATH:-$ROOT/keys/test-release-v2.jks}"
KEY_ALIAS="${KEY_ALIAS:-test-release}"
KEYSTORE_PASS="${KEYSTORE_PASS:?Use the authorized test keystore password in the environment}"

[[ -f "$INPUT" ]] || { echo "Input APK not found: $INPUT" >&2; exit 1; }
[[ -f "$KEYSTORE" ]] || { echo "Keystore not found: $KEYSTORE" >&2; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/homewoo-custom-home.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

apktool d -f "$INPUT" -o "$WORK/decoded" >/dev/null
python3 "$ROOT/inject_custom_home.py" "$WORK/decoded"

mkdir -p "$WORK/classes" "$WORK/dex"
"$JAVA_HOME/bin/javac" -source 8 -target 8 \
  -classpath "$SDK/platforms/android-35/android.jar" \
  -d "$WORK/classes" "$ROOT/src/CustomHomeActivity.java" "$ROOT/src/RedirectWatcher.java"
"$BT/d8" --lib "$SDK/platforms/android-35/android.jar" --output "$WORK/dex" \
  $(find "$WORK/classes" -name '*.class' -print)

apktool b "$WORK/decoded" -o "$WORK/rebuilt-unsigned.apk" >/dev/null
cp "$WORK/dex/classes.dex" "$WORK/classes2.dex"
(cd "$WORK" && zip -q rebuilt-unsigned.apk classes2.dex)
"$BT/zipalign" -p -f 4 "$WORK/rebuilt-unsigned.apk" "$WORK/aligned.apk"
"$BT/apksigner" sign --min-sdk-version 24 \
  --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "env:KEYSTORE_PASS" --out "$OUTPUT" "$WORK/aligned.apk"
"$BT/apksigner" verify --verbose --min-sdk-version 24 "$OUTPUT"
echo "OUTPUT_APK=$OUTPUT"
