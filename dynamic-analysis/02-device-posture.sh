#!/usr/bin/env bash
#
# 02-device-posture.sh —— 通用动态分析：设备与安装包运行时基线
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   在动态分析开始前，记录"设备上实际在跑什么"，回答：
#     - 设备型号、Android 版本、构建类型 / 标签、安全补丁是什么？
#     - 是否 Root、是否模拟器、SELinux 状态如何？
#     - 目标包是否安装？版本、UID、ABI、安装来源是什么？
#     - debuggable、allowBackup 是否开启？run-as 是否可用？
#     - 设备上的 APK 与本地样本是否逐字节一致？
#     - 可选：读取设备安装包的签名证书。
#
#   本脚本只读设备状态：不安装、不卸载、不修改任何设置。
#
# 参数：
#   --package <包名>      可选。Android 包名；与 --apk 二选一。
#   --apk <路径>          可选。本地 APK；提供 --package 缺失时尝试用 aapt 推断包名，
#                         并与设备安装包比对 SHA-256。
#   --serial <序列号>     可选。多设备时指定目标设备。
#   --signature           可选。拉取设备安装包并读取签名证书（需要 apksigner）。
#   -h, --help            显示本帮助。
#
# 依赖：
#   adb 必需；提供 --apk 时需要 SHA-256 工具（shasum / sha256sum / openssl）；
#   提供 --signature 时需要 apksigner 和 java。
#   缺少时明确提示安装方式并退出，不会静默跳过。
#
# 用法：
#   ./02-device-posture.sh --package com.example.app
#   ./02-device-posture.sh --package com.example.app --apk ./app.apk
#   ./02-device-posture.sh --apk ./app.apk --signature
#   ./02-device-posture.sh --package com.example.app --serial ABC123
#
#   错误输入示例：
#     未提供 --package / --apk → exit 2；APK 不存在 → exit 2。
#
# 输出：
#   设备基线、Root / 模拟器 / SELinux、包版本与标志、哈希比对、签名证书，
#   以及 KEY=VALUE 形式的机器可读结果。
#
# 退出码：
#   0 = 完成检查，未发现高风险信号
#   1 = 发现高风险信号（debuggable、allowBackup、模拟器、Root、哈希不一致），
#       或目标包未安装 / 设备未就绪
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

PKG=""
APK=""
SERIAL=""
READ_SIGNATURE=false

usage() {
  cat <<'EOF'
用法: ./02-device-posture.sh --package <包名> [选项]
      ./02-device-posture.sh --apk <路径> [选项]

选项:
  --package <包名>   可选。Android 包名；与 --apk 二选一。
  --apk <路径>       可选。本地 APK，用于推断包名和比对 SHA-256。
  --serial <序列号>  可选。多设备时指定目标设备。
  --signature        可选。读取设备安装包的签名证书（需要 apksigner）。
  -h, --help         显示本帮助。

错误输入示例:
  未提供 --package / --apk → 打印本帮助并 exit 2

退出码:
  0 = 未发现高风险信号
  1 = 发现高风险信号或环境未就绪
  2 = 参数、依赖或输入错误
EOF
}

die_usage() {
  echo "[FAIL] $*" >&2
  usage >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package)
      [[ $# -ge 2 ]] || die_usage "--package 需要一个值"
      PKG="$2"
      shift 2
      ;;
    --apk)
      [[ $# -ge 2 ]] || die_usage "--apk 需要一个值"
      APK="$2"
      shift 2
      ;;
    --serial)
      [[ $# -ge 2 ]] || die_usage "--serial 需要一个值"
      SERIAL="$2"
      shift 2
      ;;
    --signature)
      READ_SIGNATURE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die_usage "未知参数: $1"
      ;;
  esac
done

if [[ -n "$APK" && ! -f "$APK" ]]; then
  echo "[FAIL] APK 不存在: $APK" >&2
  exit 2
fi

# ---------- 依赖检查 ----------
if ! command -v adb >/dev/null 2>&1; then
  echo "[FAIL] 缺少工具: adb" >&2
  echo "       macOS: brew install android-platform-tools" >&2
  echo "       Linux: sudo apt install android-tools-adb / sudo dnf install android-tools" >&2
  exit 2
fi

sha256_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  else
    return 1
  fi
}

if [[ -n "$APK" ]] && ! sha256_file "$APK" >/dev/null 2>&1; then
  echo "[FAIL] 缺少 SHA-256 工具（shasum / sha256sum / openssl 至少一个）。" >&2
  exit 2
fi

find_apksigner() {
  if command -v apksigner >/dev/null 2>&1; then
    command -v apksigner
    return 0
  fi

  local roots=()
  [[ -n "${ANDROID_HOME:-}" ]] && roots+=("$ANDROID_HOME")
  [[ -n "${ANDROID_SDK_ROOT:-}" ]] && roots+=("$ANDROID_SDK_ROOT")
  roots+=("$HOME/Library/Android/sdk" "$HOME/Android/Sdk")

  local root ver candidate
  for root in "${roots[@]}"; do
    [[ -d "$root/build-tools" ]] || continue
    while IFS= read -r ver; do
      candidate="$root/build-tools/$ver/apksigner"
      if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return 0
      fi
    done < <(ls -1 "$root/build-tools" 2>/dev/null \
      | sort -t. -k1,1nr -k2,2nr -k3,3nr)
  done
  return 1
}

APKSIGNER=""
if [[ "$READ_SIGNATURE" == true ]]; then
  APKSIGNER="$(find_apksigner || true)"
  if [[ -z "$APKSIGNER" ]]; then
    echo "[FAIL] 找不到 apksigner（--signature 需要）。" >&2
    echo "       安装方式：Android Studio → SDK Manager → SDK Tools → Android SDK Build-Tools" >&2
    echo "       或 sdkmanager \"build-tools;34.0.0\"，并把 build-tools/<版本> 加入 PATH。" >&2
    exit 2
  fi
  if ! command -v java >/dev/null 2>&1; then
    echo "[FAIL] 找不到 java；apksigner 需要 JDK/JRE。" >&2
    echo "       macOS: brew install openjdk@17" >&2
    echo "       Linux: sudo apt install openjdk-17-jdk" >&2
    exit 2
  fi
fi

# ---------- 包名推断 ----------
if [[ -z "$PKG" && -n "$APK" ]]; then
  if command -v aapt >/dev/null 2>&1; then
    PKG="$(aapt dump badging "$APK" 2>/dev/null \
      | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -1 || true)"
  fi
  if [[ -z "$PKG" ]]; then
    echo "[FAIL] 未提供 --package，且无法从 APK 推断包名（缺少 aapt 或 APK 无 Manifest）。" >&2
    echo "       请显式传入 --package <包名>。" >&2
    exit 2
  fi
fi
if [[ -z "$PKG" ]]; then
  die_usage "至少需要 --package 或 --apk"
fi

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
warn() { echo "[WARN] $*"; WARN_COUNT=$((WARN_COUNT + 1)); }
fail() { echo "[FAIL] $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo "[INFO] $*"; }

echo "============================================================"
echo "动态分析 02：设备与安装包运行时基线"
echo "目标包：$PKG"
echo "时间：$(date '+%Y-%m-%d %H:%M:%S %z')"
echo "============================================================"

# ---------- 1. 设备选择 ----------
echo
echo "== 1. 设备 =="

DEVICE_READY=false
DEVICE_LIST="$(adb devices | awk 'NR > 1 && $2 == "device" {print $1}')"
if [[ -n "$SERIAL" ]]; then
  if printf '%s\n' "$DEVICE_LIST" | grep -qx "$SERIAL"; then
    DEVICE_READY=true
    pass "指定设备在线：$SERIAL"
  else
    fail "指定设备不在线或未授权：$SERIAL"
  fi
else
  DEVICE_COUNT="$(printf '%s\n' "$DEVICE_LIST" | grep -c . || true)"
  if [[ "$DEVICE_COUNT" -eq 1 ]]; then
    SERIAL="$(printf '%s\n' "$DEVICE_LIST" | head -1)"
    DEVICE_READY=true
    pass "检测到一台在线设备：$SERIAL"
  elif [[ "$DEVICE_COUNT" -eq 0 ]]; then
    fail "没有在线 Android 设备"
  else
    fail "检测到多台在线设备，请用 --serial 指定"
  fi
fi

ADB=(adb)
if [[ -n "$SERIAL" ]]; then
  ADB=(adb -s "$SERIAL")
fi

dev_shell() {
  "${ADB[@]}" shell "$@" 2>/dev/null | tr -d '\r'
}

dev_getprop() {
  dev_shell getprop "$1"
}

MANUFACTURER=""
MODEL=""
ANDROID_RELEASE=""
ANDROID_SDK=""
BUILD_TYPE=""
BUILD_TAGS=""
SECURITY_PATCH=""
FINGERPRINT=""
PRIMARY_ABI=""
VERIFIED_BOOT=""
FLASH_LOCKED=""
SELINUX=""
ROOTED=false
EMULATOR=false

if [[ "$DEVICE_READY" == true ]]; then
  MANUFACTURER="$(dev_getprop ro.product.manufacturer)"
  MODEL="$(dev_getprop ro.product.model)"
  ANDROID_RELEASE="$(dev_getprop ro.build.version.release)"
  ANDROID_SDK="$(dev_getprop ro.build.version.sdk)"
  BUILD_TYPE="$(dev_getprop ro.build.type)"
  BUILD_TAGS="$(dev_getprop ro.build.tags)"
  SECURITY_PATCH="$(dev_getprop ro.build.version.security_patch)"
  FINGERPRINT="$(dev_getprop ro.build.fingerprint)"
  PRIMARY_ABI="$(dev_getprop ro.product.cpu.abi)"
  VERIFIED_BOOT="$(dev_getprop ro.boot.verifiedbootstate)"
  FLASH_LOCKED="$(dev_getprop ro.boot.flash.locked)"
  SELINUX="$(dev_shell getenforce || true)"

  info "设备：${MANUFACTURER:-?} ${MODEL:-?}"
  info "Android：${ANDROID_RELEASE:-?} (SDK ${ANDROID_SDK:-?})"
  info "构建：type=${BUILD_TYPE:-?} tags=${BUILD_TAGS:-?}"
  info "安全补丁：${SECURITY_PATCH:-?}"
  info "ABI：${PRIMARY_ABI:-?}"
  info "SELinux：${SELINUX:-?}"

  # Root
  ROOT_OUT="$("${ADB[@]}" shell 'su -c id' 2>&1 | tr -d '\r' || true)"
  if printf '%s' "$ROOT_OUT" | grep -q 'uid=0'; then
    ROOTED=true
    warn "设备已 Root：$(printf '%s' "$ROOT_OUT" | head -1)"
  else
    info "设备未 Root"
  fi

  # 模拟器
  QEMU_PROP="$(dev_getprop ro.kernel.qemu)"
  HARDWARE_PROP="$(dev_getprop ro.hardware)"
  if [[ "$QEMU_PROP" == "1" ]] \
    || [[ "$HARDWARE_PROP" =~ ^(goldfish|ranchu|qemu) ]] \
    || [[ "$MODEL" == *"Android SDK built for"* ]] \
    || [[ "$MODEL" == *"Emulator"* ]]; then
    EMULATOR=true
    warn "检测到模拟器特征（qemu=${QEMU_PROP:-?}, hardware=${HARDWARE_PROP:-?}）"
  else
    info "未发现明显模拟器特征"
  fi

  if [[ "$BUILD_TAGS" == *"test-keys"* ]]; then
    warn "设备使用 test-keys 构建（常见于测试机/自定义 ROM）"
  fi
else
  info "设备未就绪，跳过设备基线"
fi

# ---------- 2. 目标包 ----------
echo
echo "== 2. 目标包 =="

PACKAGE_INSTALLED=false
DEVICE_APK_PATH=""
VERSION_NAME=""
VERSION_CODE=""
MIN_SDK=""
TARGET_SDK=""
APP_UID=""
INSTALLER=""
FIRST_INSTALL=""
LAST_UPDATE=""
DEBUGGABLE="unknown"
ALLOW_BACKUP="unknown"
FLAGS_PARSED=false
RUN_AS=false
HASH_MATCH="unknown"
LOCAL_APK_SHA256=""
DEVICE_APK_SHA256=""
SIGNATURE_CAPTURED=false

if [[ "$DEVICE_READY" == true ]]; then
  PM_OUT="$("${ADB[@]}" shell pm path "$PKG" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$PM_OUT" == package:* ]]; then
    PACKAGE_INSTALLED=true
    DEVICE_APK_PATH="$(printf '%s\n' "$PM_OUT" | sed -n 's/^package://p' | grep -m1 '/base\.apk$' || true)"
    if [[ -z "$DEVICE_APK_PATH" ]]; then
      DEVICE_APK_PATH="$(printf '%s\n' "$PM_OUT" | sed -n 's/^package://p' | head -1)"
    fi
    pass "目标包已安装：$PKG"
    info "设备 APK：$DEVICE_APK_PATH"

    DUMP="$("${ADB[@]}" shell dumpsys package "$PKG" 2>/dev/null | tr -d '\r' || true)"
    VERSION_NAME="$(printf '%s\n' "$DUMP" | grep -m1 -E '^[[:space:]]*versionName=' | sed -E 's/^[[:space:]]*versionName=//' || true)"
    VERSION_CODE="$(printf '%s\n' "$DUMP" | grep -m1 -oE 'versionCode=[0-9]+' | head -1 | cut -d= -f2 || true)"
    MIN_SDK="$(printf '%s\n' "$DUMP" | grep -m1 -oE 'minSdk=[0-9]+' | head -1 | cut -d= -f2 || true)"
    TARGET_SDK="$(printf '%s\n' "$DUMP" | grep -m1 -oE 'targetSdk=[0-9]+' | head -1 | cut -d= -f2 || true)"
    APP_UID="$(printf '%s\n' "$DUMP" | grep -m1 -oE 'userId=[0-9]+' | head -1 | cut -d= -f2 || true)"
    INSTALLER="$(printf '%s\n' "$DUMP" | grep -m1 -E '^[[:space:]]*installerPackageName=' | sed -E 's/^[[:space:]]*installerPackageName=//' || true)"
    FIRST_INSTALL="$(printf '%s\n' "$DUMP" | grep -m1 -E '^[[:space:]]*firstInstallTime=' | sed -E 's/^[[:space:]]*firstInstallTime=//' || true)"
    LAST_UPDATE="$(printf '%s\n' "$DUMP" | grep -m1 -E '^[[:space:]]*lastUpdateTime=' | sed -E 's/^[[:space:]]*lastUpdateTime=//' || true)"

    info "版本：${VERSION_NAME:-?} (versionCode=${VERSION_CODE:-?})"
    info "SDK：min=${MIN_SDK:-?} target=${TARGET_SDK:-?}；UID=${APP_UID:-?}"
    info "安装来源：${INSTALLER:-?}；首次安装：${FIRST_INSTALL:-?}；最后更新：${LAST_UPDATE:-?}"

    FLAGS_LINE="$(printf '%s\n' "$DUMP" | grep -m1 -E '(^|[[:space:]])(pkgFlags|flags)=\[' || true)"
    if [[ -n "$FLAGS_LINE" ]]; then
      FLAGS_PARSED=true
      if printf '%s' "$FLAGS_LINE" | grep -qw 'DEBUGGABLE'; then
        DEBUGGABLE=true
      else
        DEBUGGABLE=false
      fi
      if printf '%s' "$FLAGS_LINE" | grep -qw 'ALLOW_BACKUP'; then
        ALLOW_BACKUP=true
      else
        ALLOW_BACKUP=false
      fi
      info "包标志：$FLAGS_LINE"
    else
      info "无法从 dumpsys 解析包标志（不同 Android 版本输出可能不同）"
    fi

    RUN_AS_OUT="$("${ADB[@]}" shell run-as "$PKG" id 2>&1 | tr -d '\r' || true)"
    if printf '%s' "$RUN_AS_OUT" | grep -q 'uid='; then
      RUN_AS=true
      info "run-as 可用：$(printf '%s' "$RUN_AS_OUT" | head -1)"
    else
      info "run-as 不可用（包不可调试，或设备未开启 ro.debuggable）"
    fi

    if [[ -n "$APK" ]]; then
      echo "[loading] 正在计算本地 APK SHA-256..."
      LOCAL_APK_SHA256="$(sha256_file "$APK")"
      echo "[done] 本地 APK SHA-256 计算完成"
      DEVICE_APK_SHA256="$("${ADB[@]}" shell sha256sum "$DEVICE_APK_PATH" 2>/dev/null | tr -d '\r' | awk '{print $1}' || true)"
      if [[ ! "$DEVICE_APK_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        WORKDIR="$(mktemp -d)"
        if "${ADB[@]}" pull "$DEVICE_APK_PATH" "$WORKDIR/base.apk" >/dev/null 2>&1; then
          DEVICE_APK_SHA256="$(sha256_file "$WORKDIR/base.apk" || true)"
        fi
        rm -rf "$WORKDIR"
      fi
      if [[ -n "$DEVICE_APK_SHA256" ]]; then
        if [[ "$(printf '%s' "$DEVICE_APK_SHA256" | tr 'A-F' 'a-f')" == "$(printf '%s' "$LOCAL_APK_SHA256" | tr 'A-F' 'a-f')" ]]; then
          HASH_MATCH=true
          pass "设备安装包与本地 APK 哈希一致"
        else
          HASH_MATCH=false
          warn "设备安装包与本地 APK 哈希不一致（可能是篡改包或不同版本）"
        fi
      else
        warn "无法读取设备 APK 哈希；跳过比对"
      fi
    fi

    if [[ "$READ_SIGNATURE" == true && -n "$DEVICE_APK_PATH" ]]; then
      echo "[loading] 正在读取设备安装包签名（大文件可能需要几十秒）..."
      WORKDIR="$(mktemp -d)"
      if "${ADB[@]}" pull "$DEVICE_APK_PATH" "$WORKDIR/base.apk" >/dev/null 2>&1; then
        SIG_OUT="$("$APKSIGNER" verify --print-certs "$WORKDIR/base.apk" 2>&1 || true)"
        if printf '%s' "$SIG_OUT" | grep -q '^Signer #1 certificate SHA-256 digest:'; then
          SIGNATURE_CAPTURED=true
          printf '%s\n' "$SIG_OUT" | grep -E '^Signer #1 certificate (DN|SHA-256 digest):' || true
        else
          warn "apksigner 未能读取签名证书"
          printf '%s\n' "$SIG_OUT" | head -5 | sed 's/^/       /'
        fi
      else
        warn "无法拉取设备 APK；跳过签名读取"
      fi
      rm -rf "$WORKDIR"
      echo "[done] 签名读取流程结束"
    fi
  else
    fail "目标包未安装：$PKG"
  fi
else
  info "设备未就绪，跳过包检查"
fi

# ---------- 3. 风险判定 ----------
echo
echo "------------------------------------------------------------"
echo "【结论】"

RISK=false
RISK_REASON=""
add_risk() {
  RISK=true
  if [[ -z "$RISK_REASON" ]]; then
    RISK_REASON="$1"
  else
    RISK_REASON="$RISK_REASON, $1"
  fi
}

if [[ "$DEBUGGABLE" == true ]]; then
  add_risk "debuggable=true"
fi
if [[ "$ALLOW_BACKUP" == true ]]; then
  add_risk "allowBackup=true"
fi
if [[ "$EMULATOR" == true ]]; then
  add_risk "emulator"
fi
if [[ "$ROOTED" == true ]]; then
  add_risk "rooted"
fi
if [[ "$HASH_MATCH" == false ]]; then
  add_risk "apk-hash-mismatch"
fi
if [[ "$DEVICE_READY" != true ]]; then
  add_risk "device-not-ready"
fi
if [[ "$PACKAGE_INSTALLED" != true ]]; then
  add_risk "package-not-installed"
fi
if [[ "$FAIL_COUNT" -gt 0 && "$RISK_REASON" == "" ]]; then
  add_risk "check-failed"
fi

echo "PASS_COUNT=$PASS_COUNT"
echo "WARN_COUNT=$WARN_COUNT"
echo "FAIL_COUNT=$FAIL_COUNT"
echo "DEVICE_SERIAL=${SERIAL:-}"
echo "DEVICE_MODEL=${MANUFACTURER:-} ${MODEL:-}"
echo "ANDROID_RELEASE=${ANDROID_RELEASE:-}"
echo "ANDROID_SDK=${ANDROID_SDK:-}"
echo "BUILD_TYPE=${BUILD_TYPE:-}"
echo "BUILD_TAGS=${BUILD_TAGS:-}"
echo "SECURITY_PATCH=${SECURITY_PATCH:-}"
echo "SELINUX=${SELINUX:-}"
echo "ROOTED=$ROOTED"
echo "EMULATOR=$EMULATOR"
echo "PACKAGE_NAME=$PKG"
echo "PACKAGE_INSTALLED=$PACKAGE_INSTALLED"
echo "VERSION_NAME=${VERSION_NAME:-}"
echo "VERSION_CODE=${VERSION_CODE:-}"
echo "MIN_SDK=${MIN_SDK:-}"
echo "TARGET_SDK=${TARGET_SDK:-}"
echo "APP_UID=${APP_UID:-}"
echo "INSTALLER=${INSTALLER:-}"
echo "DEBUGGABLE=$DEBUGGABLE"
echo "ALLOW_BACKUP=$ALLOW_BACKUP"
echo "FLAGS_PARSED=$FLAGS_PARSED"
echo "RUN_AS=$RUN_AS"
echo "HASH_MATCH=$HASH_MATCH"
echo "LOCAL_APK_SHA256=${LOCAL_APK_SHA256:-}"
echo "DEVICE_APK_SHA256=${DEVICE_APK_SHA256:-}"
echo "SIGNATURE_CAPTURED=$SIGNATURE_CAPTURED"
echo "POSTURE_RISK=$RISK"
echo "POSTURE_RISK_REASON=${RISK_REASON:-none}"

if [[ "$RISK" == true ]]; then
  echo "发现高风险或未就绪信号：${RISK_REASON}" >&2
  echo "注意：Root 与模拟器在授权测试环境中可能是预期条件，但仍应在报告中注明。"
  exit 1
fi

echo "未发现高风险信号。"
exit 0
