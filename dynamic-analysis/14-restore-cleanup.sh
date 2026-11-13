#!/usr/bin/env bash
#
# 14-restore-cleanup.sh —— 通用动态分析：恢复原包与清理测试环境
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   动态分析或攻击演示结束后，把测试设备恢复到可复核的干净状态：
#     - 核对设备上安装的包是否与本地原始 APK 逐字节一致；
#     - 必要时覆盖安装或卸载后重装原始 APK；
#     - 可选清除应用数据（显式 --clear-data，会删除登录态和本地数据）；
#     - 可选清理设备全局 HTTP 代理（显式 --clear-proxy）；
#     - 可选清理 adb reverse 隧道（显式 --clear-reverse）。
#
#   本脚本不修改本地 APK，也不删除证据文件。
#
# 用法：
#   ./14-restore-cleanup.sh verify --package <包名> --apk <原始APK>
#   ./14-restore-cleanup.sh restore --package <包名> --apk <原始APK>
#   ./14-restore-cleanup.sh restore --package <包名> --apk <原始APK> \
#     --clear-data --clear-proxy --clear-reverse
#   ./14-restore-cleanup.sh cleanup-proxy [--clear-reverse]
#
# 参数：
#   --package <包名>       verify / restore 必填。Android 包名。
#   --apk <路径>           verify / restore 必填。原始 APK 路径。
#   --serial <序列号>      可选。多设备时指定目标设备。
#   --clear-data           可选，仅 restore。卸载/重装后清除应用数据。
#   --clear-proxy          可选，仅 restore / cleanup-proxy。
#                          删除设备全局 http_proxy 设置。
#   --clear-reverse        可选。执行 adb reverse --remove-all。
#   -h, --help             显示本帮助。
#
#   错误输入示例：
#     verify 缺少 --apk → exit 2；--clear-data 用于非 restore → exit 2。
#
# 输出：
#   INSTALLED_SHA256 / EXPECTED_SHA256 / RESTORE_VERIFIED、PROXY_CLEARED、
#   【结论】。
#
# 依赖：
#   adb 必需；verify / restore 需要 SHA-256 工具
#   （shasum / sha256sum / openssl 至少一个）。
#   缺少时明确提示安装方式并退出，不会静默跳过。
#
# 退出码：
#   0 = 已恢复或已校验通过
#   1 = 安装失败、校验不一致，或设备未就绪
#   2 = 参数或依赖错误
#
set -euo pipefail
export LC_ALL=C

ACTION="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

PKG=""
APK=""
SERIAL=""
CLEAR_DATA=false
CLEAR_PROXY=false
CLEAR_REVERSE=false

usage() {
  cat <<'EOF'
用法:
  ./14-restore-cleanup.sh verify --package <包名> --apk <原始APK> [--serial <序列号>]
  ./14-restore-cleanup.sh restore --package <包名> --apk <原始APK> [选项]
  ./14-restore-cleanup.sh cleanup-proxy [--serial <序列号>] [--clear-reverse]
  ./14-restore-cleanup.sh help

选项:
  --package <包名>   verify / restore 必填。
  --apk <路径>       verify / restore 必填。原始 APK 路径。
  --serial <序列号>  可选。多设备时指定目标设备。
  --clear-data       可选，仅 restore。清除应用数据（删除登录态和本地数据）。
  --clear-proxy      可选。清理设备全局 HTTP 代理。
  --clear-reverse    可选。执行 adb reverse --remove-all。
  -h, --help         显示本帮助。

说明:
  restore 会先尝试 adb install -r 覆盖安装；如果签名或版本不兼容，
  会卸载后重装，此时应用数据必然被清除。执行前请确认这是测试设备。

错误输入示例:
  verify 缺少 --apk → 打印本帮助并 exit 2；--clear-data 用于非 restore → exit 2

退出码:
  0 = 已恢复或已校验通过
  1 = 安装失败、校验不一致，或设备未就绪
  2 = 参数或依赖错误
EOF
}

case "$ACTION" in
  help|-h|--help)
    usage
    exit 0
    ;;
  verify|restore|cleanup-proxy)
    ;;
  *)
    echo "[FAIL] 未知操作: $ACTION" >&2
    usage >&2
    exit 2
    ;;
esac

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
    --clear-data)
      CLEAR_DATA=true
      shift
      ;;
    --clear-proxy)
      CLEAR_PROXY=true
      shift
      ;;
    --clear-reverse)
      CLEAR_REVERSE=true
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

if [[ "$CLEAR_DATA" == true && "$ACTION" != "restore" ]]; then
  die_usage "--clear-data 只能用于 restore"
fi

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

need_sha256() {
  if ! command -v shasum >/dev/null 2>&1 \
    && ! command -v sha256sum >/dev/null 2>&1 \
    && ! command -v openssl >/dev/null 2>&1; then
    echo "[FAIL] 缺少 SHA-256 工具（shasum / sha256sum / openssl 至少一个）。" >&2
    exit 2
  fi
}

need_device() {
  ADB=(adb)
  if [[ -n "$SERIAL" ]]; then
    ADB=(adb -s "$SERIAL")
  fi
  if ! "${ADB[@]}" get-state >/dev/null 2>&1; then
    echo "[FAIL] 没有在线 Android 设备${SERIAL:+ (serial=$SERIAL)}" >&2
    exit 1
  fi
}

need_pkg_apk() {
  [[ -n "$PKG" ]] || die_usage "缺少 --package"
  [[ -n "$APK" ]] || die_usage "缺少 --apk"
  if [[ ! -f "$APK" ]]; then
    echo "[FAIL] APK 不存在: $APK" >&2
    exit 2
  fi
}

device_pkg_path() {
  local out base
  out="$("${ADB[@]}" shell pm path "$PKG" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$out" != package:* ]]; then
    return 1
  fi
  base="$(printf '%s\n' "$out" | sed -n 's/^package://p' | grep -m1 '/base\.apk$' || true)"
  if [[ -z "$base" ]]; then
    base="$(printf '%s\n' "$out" | sed -n 's/^package://p' | head -1 || true)"
  fi
  if [[ -z "$base" ]]; then
    return 1
  fi
  printf '%s\n' "$base"
  return 0
}

device_sha() {
  local path="$1" out work
  out="$("${ADB[@]}" shell sha256sum "$path" 2>/dev/null | tr -d '\r' | awk '{print $1}' || true)"
  if [[ "$out" =~ ^[0-9a-fA-F]{64}$ ]]; then
    printf '%s\n' "$out" | tr 'A-F' 'a-f'
    return 0
  fi

  work="$(mktemp -d)"
  if "${ADB[@]}" pull "$path" "$work/base.apk" >/dev/null 2>&1; then
    sha256_file "$work/base.apk"
    rm -rf "$work"
    return 0
  fi
  rm -rf "$work"
  return 1
}

verify_installed() {
  local dev_path dev_sha local_sha
  dev_path="$(device_pkg_path)" || {
    echo "[FAIL] 目标包未安装: $PKG" >&2
    echo "RESTORE_VERIFIED=false"
    return 1
  }
  echo "[loading] 正在读取设备 APK 哈希..." >&2
  dev_sha="$(device_sha "$dev_path" || true)"
  local_sha="$(sha256_file "$APK")"
  echo "[done] 设备 APK 哈希读取完成" >&2

  echo "INSTALLED_APK_PATH=$dev_path"
  echo "INSTALLED_SHA256=${dev_sha:-unknown}"
  echo "EXPECTED_SHA256=$local_sha"

  if [[ -n "$dev_sha" && "$dev_sha" == "$(printf '%s' "$local_sha" | tr 'A-F' 'a-f')" ]]; then
    echo "RESTORE_VERIFIED=true"
    return 0
  fi

  echo "RESTORE_VERIFIED=false"
  return 1
}

install_original() {
  local out rc
  echo "== 尝试覆盖安装原始 APK（保留应用数据） =="
  echo "[loading] 正在执行 adb install -r（大文件可能需要几十秒）..."
  set +e
  out="$("${ADB[@]}" install -r "$APK" 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out"
  echo "[done] 覆盖安装命令结束"

  if [[ $rc -eq 0 ]]; then
    return 0
  fi

  if printf '%s' "$out" | grep -qiE 'INSTALL_FAILED_UPDATE_INCOMPATIBLE|INSTALL_FAILED_ALREADY_EXISTS|INSTALL_FAILED_VERSION_DOWNGRADE|signature'; then
    echo "[WARN] 覆盖安装失败：签名或版本不兼容。"
    echo "[WARN] 接下来卸载并重装原始 APK，应用数据会被清除。"
    "${ADB[@]}" uninstall "$PKG" >/dev/null 2>&1 || true

    echo "[loading] 正在执行卸载后重装（应用数据会被清除）..."
    set +e
    out="$("${ADB[@]}" install "$APK" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out"
    echo "[done] 重装命令结束"
    return $rc
  fi

  return $rc
}

clear_proxy() {
  local proxy
  echo "== 清理设备全局 HTTP 代理 =="
  "${ADB[@]}" shell settings delete global http_proxy >/dev/null 2>&1 || true
  "${ADB[@]}" shell settings put global http_proxy :0 >/dev/null 2>&1 || true

  proxy="$("${ADB[@]}" shell settings get global http_proxy 2>/dev/null | tr -d '\r' || true)"
  echo "DEVICE_HTTP_PROXY=${proxy:-unknown}"

  case "$proxy" in
    ":0"|""|"null")
      echo "PROXY_CLEARED=true"
      return 0
      ;;
    *)
      echo "PROXY_CLEARED=false"
      return 1
      ;;
  esac
}

clear_reverse() {
  echo "== 清理 adb reverse 隧道 =="
  "${ADB[@]}" reverse --remove-all >/dev/null 2>&1 || true
  echo "REVERSE_TUNNELS_CLEARED=true"
}

echo "============================================================"
echo "动态分析 14：恢复与清理"
echo "操作：$ACTION"
echo "目标包：${PKG:-（未指定）}"
echo "原始 APK：${APK:-（未指定）}"
echo "时间：$(date '+%Y-%m-%d %H:%M:%S %z')"
echo "============================================================"

case "$ACTION" in
  verify)
    need_device
    need_pkg_apk
    need_sha256
    if verify_installed; then
      echo "------------------------------------------------------------"
      echo "【结论】"
      echo "设备上的 APK 与本地原始 APK 逐字节一致。"
      echo "RESULT=VERIFIED"
      exit 0
    fi
    echo "------------------------------------------------------------"
    echo "【结论】"
    echo "设备上的 APK 与本地原始 APK 不一致，需要先执行 restore。"
    echo "RESULT=MISMATCH"
    exit 1
    ;;

  restore)
    need_device
    need_pkg_apk
    need_sha256

    if verify_installed; then
      echo "ALREADY_ORIGINAL=true"
    else
      echo "ALREADY_ORIGINAL=false"
      if ! install_original; then
        echo "[FAIL] 原始 APK 安装失败" >&2
        echo "------------------------------------------------------------"
        echo "【结论】"
        echo "原始 APK 未能安装，恢复未完成。"
        echo "RESULT=INSTALL_FAILED"
        exit 1
      fi
    fi

    if [[ "$CLEAR_DATA" == true ]]; then
      echo "== 清除应用数据 =="
      "${ADB[@]}" shell pm clear "$PKG" >/dev/null 2>&1 || true
      echo "APP_DATA_CLEARED=true"
      echo "提示：清除数据后应用需要重新登录；这属于预期行为。"
    fi

    if [[ "$CLEAR_PROXY" == true ]]; then
      clear_proxy || echo "[WARN] 代理清理未确认成功，请手工检查设置。"
    fi

    if [[ "$CLEAR_REVERSE" == true ]]; then
      clear_reverse
    fi

    echo "------------------------------------------------------------"
    echo "【恢复后复核】"
    if ! verify_installed; then
      echo "------------------------------------------------------------"
      echo "【结论】"
      echo "恢复后校验未通过，设备上的 APK 仍与本地原始 APK 不一致。"
      echo "RESULT=RESTORE_MISMATCH"
      exit 1
    fi
    echo "------------------------------------------------------------"
    echo "【结论】"
    echo "已恢复原始 APK，并与本地样本逐字节一致。"
    echo "RESULT=RESTORED"
    exit 0
    ;;

  cleanup-proxy)
    need_device
    if clear_proxy; then
      PROXY_RESULT=true
    else
      PROXY_RESULT=false
    fi
    if [[ "$CLEAR_REVERSE" == true ]]; then
      clear_reverse
    fi
    echo "------------------------------------------------------------"
    echo "【结论】"
    echo "代理清理结果：PROXY_CLEARED=$PROXY_RESULT"
    echo "RESULT=CLEANED"
    exit 0
    ;;
esac
