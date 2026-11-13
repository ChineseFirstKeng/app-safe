#!/usr/bin/env bash
#
# 01-preflight-env.sh —— 通用动态分析：环境与设备预检
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   在开始任何动态分析或攻击复现前，回答：
#     - 主机是否具备 adb、python3，以及可选的 frida / mitmproxy / apksigner？
#     - 是否有且仅有一台在线的授权测试设备？
#     - 设备是否已 Root（可选强制）？
#     - 目标包是否已安装？设备上的 APK 与本地样本是否逐字节一致？
#     - 设备与主机时间是否同步？屏幕是否唤醒？
#     - 主机到声明的测试端点是否可达（可选）？
#
#   本脚本只读设备状态：不安装、不卸载、不修改代理或系统设置。
#
# 参数：
#   --package <包名>      可选。格式：Android 包名，如 com.example.app。
#                         提供后检查安装状态与版本。
#   --apk <路径>          可选。格式：存在且可读的 APK 文件路径。
#                         提供后与设备安装包比对 SHA-256。
#   --serial <序列号>     可选。多设备时指定目标设备。
#   --require-root        可选。要求设备已 Root；未 Root 时预检失败。
#   --require-frida       可选。要求主机 frida 可用；缺失时预检失败。
#   --require-proxy       可选。要求主机 mitmproxy 可用；缺失时预检失败。
#   --endpoint <URL>      可选。检查主机到测试端点的连通性。
#                         注意：这是主机侧检查，不经过设备代理。
#   --time-tolerance <秒> 可选。设备与主机时间差容忍值，默认 300。
#   -h, --help            显示本帮助。
#
# 依赖：
#   adb 必需；python3 建议（后续动态脚本使用）；frida / mitmproxy /
#   apksigner 可选；提供 --apk 时需要 SHA-256 工具
#   （shasum / sha256sum / openssl 至少一个）。
#   缺少必需依赖时明确提示安装方式并退出，不会静默跳过。
#
# 用法：
#   ./01-preflight-env.sh
#   ./01-preflight-env.sh --package com.example.app --apk ./app.apk
#   ./01-preflight-env.sh --serial ABC123 --require-root --require-frida
#   ./01-preflight-env.sh --package com.example.app --apk ./app.apk \
#     --endpoint https://test.example.com:18443/health
#
#   错误输入示例：
#     --time-tolerance abc → exit 2；--apk 指向不存在的文件 → exit 2。
#
# 输出：
#   主机工具、设备连接、Root、包状态、APK 哈希、时间同步、屏幕状态，
#   以及 KEY=VALUE 形式的机器可读结果。
#
# 退出码：
#   0 = 所有必需检查通过（允许 WARN）
#   1 = 环境检查未通过（无设备、未授权、包缺失、哈希不一致、强制项缺失）
#   2 = 参数或依赖错误
#
set -euo pipefail
export LC_ALL=C

PKG=""
APK=""
SERIAL=""
REQUIRE_ROOT=false
REQUIRE_FRIDA=false
REQUIRE_PROXY=false
ENDPOINT=""
TIME_TOLERANCE=300

usage() {
  cat <<'EOF'
用法: ./01-preflight-env.sh [选项]

选项:
  --package <包名>       可选。检查安装状态与版本。
  --apk <路径>           可选。与设备安装包比对 SHA-256。
  --serial <序列号>      可选。多设备时指定目标设备。
  --require-root         可选。要求设备已 Root。
  --require-frida        可选。要求主机 frida 可用。
  --require-proxy        可选。要求主机 mitmproxy 可用。
  --endpoint <URL>       可选。检查主机到测试端点的连通性。
  --time-tolerance <秒>  可选。设备与主机时间差容忍值，默认 300。
  -h, --help             显示本帮助。

错误输入示例:
  --time-tolerance abc → 打印本帮助并 exit 2

退出码:
  0 = 所有必需检查通过
  1 = 环境检查未通过
  2 = 参数或依赖错误
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
    --require-root)
      REQUIRE_ROOT=true
      shift
      ;;
    --require-frida)
      REQUIRE_FRIDA=true
      shift
      ;;
    --require-proxy)
      REQUIRE_PROXY=true
      shift
      ;;
    --endpoint)
      [[ $# -ge 2 ]] || die_usage "--endpoint 需要一个值"
      ENDPOINT="$2"
      shift 2
      ;;
    --time-tolerance)
      [[ $# -ge 2 ]] || die_usage "--time-tolerance 需要一个值"
      TIME_TOLERANCE="$2"
      shift 2
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

if [[ ! "$TIME_TOLERANCE" =~ ^[0-9]+$ ]]; then
  die_usage "--time-tolerance 必须是非负整数: $TIME_TOLERANCE"
fi
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

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
warn() { echo "[WARN] $*"; WARN_COUNT=$((WARN_COUNT + 1)); }
fail() { echo "[FAIL] $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo "[INFO] $*"; }

echo "============================================================"
echo "动态分析 01：环境与设备预检"
echo "时间：$(date '+%Y-%m-%d %H:%M:%S %z')"
echo "============================================================"

# ---------- 1. 主机工具 ----------
echo
echo "== 1. 主机工具 =="

if command -v python3 >/dev/null 2>&1; then
  PYTHON3_VERSION="$(python3 --version 2>&1 | head -1)"
  pass "python3 可用：$PYTHON3_VERSION"
else
  PYTHON3_VERSION="(未安装)"
  warn "未找到 python3；后续动态脚本中的 Python 工具将不可用"
fi

FRIDA_VERSION="(未安装)"
if command -v frida >/dev/null 2>&1; then
  FRIDA_VERSION="$(frida --version 2>&1 | head -1 || true)"
  pass "frida 可用：$FRIDA_VERSION"
elif [[ "$REQUIRE_FRIDA" == true ]]; then
  fail "要求 frida，但主机未安装"
else
  info "未找到 frida（本项非强制）"
fi

PROXY_VERSION="(未安装)"
if command -v mitmproxy >/dev/null 2>&1; then
  PROXY_VERSION="$(mitmproxy --version 2>&1 | head -1 || true)"
  pass "mitmproxy 可用：$PROXY_VERSION"
elif [[ "$REQUIRE_PROXY" == true ]]; then
  fail "要求 mitmproxy，但主机未安装"
else
  info "未找到 mitmproxy（本项非强制）"
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

APKSIGNER="$(find_apksigner || true)"
if [[ -n "$APKSIGNER" ]]; then
  pass "apksigner 可用：$APKSIGNER"
else
  info "未找到 apksigner（签名检查会用到）"
fi

# ---------- 2. 设备连接 ----------
echo
echo "== 2. 设备连接 =="

DEVICE_READY=false
DEVICE_SERIAL=""
DEVICE_STATE="none"
DEVICE_LIST="$(adb devices | awk 'NR > 1 && $2 == "device" {print $1}')"
UNAUTHORIZED_LIST="$(adb devices | awk 'NR > 1 && $2 == "unauthorized" {print $1}')"
OFFLINE_LIST="$(adb devices | awk 'NR > 1 && $2 == "offline" {print $1}')"

if [[ -n "$UNAUTHORIZED_LIST" ]]; then
  fail "存在未授权设备：$(printf '%s' "$UNAUTHORIZED_LIST" | tr '\n' ' ')"
fi
if [[ -n "$OFFLINE_LIST" ]]; then
  fail "存在离线设备：$(printf '%s' "$OFFLINE_LIST" | tr '\n' ' ')"
fi

if [[ -n "$SERIAL" ]]; then
  if printf '%s\n' "$DEVICE_LIST" | grep -qx "$SERIAL"; then
    DEVICE_SERIAL="$SERIAL"
    DEVICE_READY=true
    pass "指定设备在线：$SERIAL"
  else
    fail "指定设备不在线或未授权：$SERIAL"
  fi
else
  DEVICE_COUNT="$(printf '%s\n' "$DEVICE_LIST" | grep -c . || true)"
  if [[ "$DEVICE_COUNT" -eq 1 ]]; then
    DEVICE_SERIAL="$(printf '%s\n' "$DEVICE_LIST" | head -1)"
    DEVICE_READY=true
    pass "检测到一台在线设备：$DEVICE_SERIAL"
  elif [[ "$DEVICE_COUNT" -eq 0 ]]; then
    fail "没有在线 Android 设备；请连接设备并开启 USB 调试"
  else
    fail "检测到多台在线设备，请用 --serial 指定目标设备"
  fi
fi

ADB=(adb)
if [[ -n "$DEVICE_SERIAL" ]]; then
  ADB=(adb -s "$DEVICE_SERIAL")
fi

dev_shell() {
  "${ADB[@]}" shell "$@" 2>/dev/null | tr -d '\r'
}

dev_getprop() {
  dev_shell getprop "$1"
}

if [[ "$DEVICE_READY" == true ]]; then
  DEVICE_STATE="$("${ADB[@]}" get-state 2>/dev/null | tr -d '\r' || true)"
  pass "设备状态：${DEVICE_STATE:-unknown}"

  MANUFACTURER="$(dev_getprop ro.product.manufacturer)"
  MODEL="$(dev_getprop ro.product.model)"
  ANDROID_RELEASE="$(dev_getprop ro.build.version.release)"
  ANDROID_SDK="$(dev_getprop ro.build.version.sdk)"
  BUILD_TAGS="$(dev_getprop ro.build.tags)"
  BUILD_TYPE="$(dev_getprop ro.build.type)"

  info "设备：${MANUFACTURER:-?} ${MODEL:-?}"
  info "Android：${ANDROID_RELEASE:-?} (SDK ${ANDROID_SDK:-?})"
  info "构建类型：${BUILD_TYPE:-?}；构建标签：${BUILD_TAGS:-?}"

  if [[ "$BUILD_TAGS" == *"test-keys"* ]]; then
    warn "设备使用 test-keys 构建（常见于测试机/自定义 ROM）"
  fi
else
  MANUFACTURER=""
  MODEL=""
  ANDROID_RELEASE=""
  ANDROID_SDK=""
  BUILD_TAGS=""
  BUILD_TYPE=""
fi

# ---------- 3. Root 状态 ----------
echo
echo "== 3. Root 状态 =="

ROOTED=false
if [[ "$DEVICE_READY" == true ]]; then
  ROOT_OUT="$("${ADB[@]}" shell 'su -c id' 2>&1 | tr -d '\r' || true)"
  if printf '%s' "$ROOT_OUT" | grep -q 'uid=0'; then
    ROOTED=true
    pass "设备已 Root：$(printf '%s' "$ROOT_OUT" | head -1)"
  else
    if [[ "$REQUIRE_ROOT" == true ]]; then
      fail "要求 Root，但 su -c id 未返回 uid=0"
      info "输出：$(printf '%s' "$ROOT_OUT" | head -1)"
    else
      info "设备未 Root（本项非强制）；依赖 Root 的脚本将无法运行"
    fi
  fi
else
  info "设备未就绪，跳过 Root 检查"
fi

# ---------- 4. 目标包与 APK 哈希 ----------
echo
echo "== 4. 目标包与 APK 哈希 =="

PACKAGE_INSTALLED=false
DEVICE_APK_PATH=""
VERSION_NAME=""
VERSION_CODE=""
TARGET_SDK=""
LOCAL_APK_SHA256=""
DEVICE_APK_SHA256=""
HASH_MATCH="unknown"

if [[ -n "$PKG" && "$DEVICE_READY" == true ]]; then
  PM_OUT="$("${ADB[@]}" shell pm path "$PKG" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$PM_OUT" == package:* ]]; then
    PACKAGE_INSTALLED=true
    DEVICE_APK_PATH="${PM_OUT#package:}"
    pass "目标包已安装：$PKG"
    info "设备 APK：$DEVICE_APK_PATH"

    DUMP="$("${ADB[@]}" shell dumpsys package "$PKG" 2>/dev/null | tr -d '\r' || true)"
    VERSION_NAME="$(printf '%s\n' "$DUMP" | grep -m1 -E '^[[:space:]]*versionName=' | sed -E 's/^[[:space:]]*versionName=//' || true)"
    VERSION_CODE="$(printf '%s\n' "$DUMP" | grep -m1 -oE 'versionCode=[0-9]+' | head -1 | cut -d= -f2 || true)"
    TARGET_SDK="$(printf '%s\n' "$DUMP" | grep -m1 -oE 'targetSdk=[0-9]+' | head -1 | cut -d= -f2 || true)"
    info "版本：${VERSION_NAME:-?} (versionCode=${VERSION_CODE:-?}, targetSdk=${TARGET_SDK:-?})"

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
          fail "设备安装包与本地 APK 哈希不一致（可能已安装篡改包或版本不同）"
        fi
      else
        warn "无法读取设备 APK 哈希；跳过比对"
      fi
    fi
  else
    fail "目标包未安装：$PKG"
  fi
elif [[ -n "$PKG" ]]; then
  info "设备未就绪，跳过包状态检查"
else
  info "未提供 --package，跳过包状态检查"
fi

# ---------- 5. 时间同步 ----------
echo
echo "== 5. 时间同步 =="

TIME_DIFF=""
if [[ "$DEVICE_READY" == true ]]; then
  DEVICE_EPOCH="$(dev_shell date +%s | tr -d '[:space:]')"
  HOST_EPOCH="$(date +%s)"
  if [[ "$DEVICE_EPOCH" =~ ^[0-9]+$ ]]; then
    TIME_DIFF=$((DEVICE_EPOCH - HOST_EPOCH))
    ABS_DIFF="${TIME_DIFF#-}"
    if [[ "$ABS_DIFF" -le "$TIME_TOLERANCE" ]]; then
      pass "设备与主机时间差 ${TIME_DIFF}s（容忍 ${TIME_TOLERANCE}s）"
    else
      fail "设备与主机时间差 ${TIME_DIFF}s，超过容忍值 ${TIME_TOLERANCE}s"
      info "时间不同步会影响 nonce / timestamp / 证书校验类测试"
    fi
  else
    warn "无法读取设备时间；跳过时间同步检查"
  fi
else
  info "设备未就绪，跳过时间同步检查"
fi

# ---------- 6. 屏幕状态 ----------
echo
echo "== 6. 屏幕状态 =="

if [[ "$DEVICE_READY" == true ]]; then
  POWER_OUT="$(dev_shell dumpsys power || true)"
  if printf '%s' "$POWER_OUT" | grep -qE 'mWakefulness=Awake|Display Power: state=ON'; then
    pass "屏幕已唤醒"
  else
    warn "屏幕可能熄屏或锁定；自动化操作前请解锁"
  fi
else
  info "设备未就绪，跳过屏幕检查"
fi

# ---------- 7. 测试端点（可选） ----------
echo
echo "== 7. 测试端点（可选） =="

HOST_ENDPOINT_HTTP_CODE=""
if [[ -n "$ENDPOINT" ]]; then
  if command -v curl >/dev/null 2>&1; then
    HOST_ENDPOINT_HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "$ENDPOINT" 2>/dev/null || true)"
    if [[ "$HOST_ENDPOINT_HTTP_CODE" =~ ^[0-9]{3}$ && "$HOST_ENDPOINT_HTTP_CODE" != "000" ]]; then
      pass "主机到测试端点可达：HTTP $HOST_ENDPOINT_HTTP_CODE"
    else
      warn "主机无法确认测试端点可达（HTTP ${HOST_ENDPOINT_HTTP_CODE:-000}）"
    fi
  else
    warn "缺少 curl，跳过 --endpoint 检查"
  fi
else
  info "未提供 --endpoint，跳过"
fi

# ---------- 8. 结论 ----------
echo
echo "------------------------------------------------------------"
echo "【结论】"
echo "PASS_COUNT=$PASS_COUNT"
echo "WARN_COUNT=$WARN_COUNT"
echo "FAIL_COUNT=$FAIL_COUNT"
echo "DEVICE_READY=$DEVICE_READY"
echo "DEVICE_SERIAL=${DEVICE_SERIAL:-}"
echo "DEVICE_MODEL=${MANUFACTURER:-} ${MODEL:-}"
echo "ANDROID_RELEASE=${ANDROID_RELEASE:-}"
echo "ANDROID_SDK=${ANDROID_SDK:-}"
echo "ROOTED=$ROOTED"
echo "PACKAGE_INSTALLED=$PACKAGE_INSTALLED"
echo "VERSION_NAME=${VERSION_NAME:-}"
echo "VERSION_CODE=${VERSION_CODE:-}"
echo "TARGET_SDK=${TARGET_SDK:-}"
echo "HASH_MATCH=$HASH_MATCH"
echo "LOCAL_APK_SHA256=${LOCAL_APK_SHA256:-}"
echo "DEVICE_APK_SHA256=${DEVICE_APK_SHA256:-}"
echo "TIME_DIFF_SECONDS=${TIME_DIFF:-unknown}"
echo "HOST_ENDPOINT_HTTP_CODE=${HOST_ENDPOINT_HTTP_CODE:-}"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "PREFLIGHT_PASSED=false"
  echo "预检未通过：$FAIL_COUNT 项必需检查失败，$WARN_COUNT 项警告。" >&2
  exit 1
fi

echo "PREFLIGHT_PASSED=true"
echo "预检通过：$PASS_COUNT 项通过，$WARN_COUNT 项警告。"
exit 0
