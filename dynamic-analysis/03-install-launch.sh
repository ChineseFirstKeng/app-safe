#!/usr/bin/env bash
#
# 03-install-launch.sh —— 通用动态分析：安装、启动与运行状态基线
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   建立"能装、能起、前台是谁"的运行时基线，回答：
#     - 目标 APK 能否安装？安装后设备上的包是否与本地样本一致？
#     - 启动后前台 Activity 是哪个？进程 PID 是多少？
#     - 启动后是否出现崩溃（FATAL EXCEPTION）或 ANR？
#     - 当前前台是否仍是目标应用？进程是否还活着？
#     - 演示结束后能否恢复原始 APK？
#
#   本脚本会修改设备状态（安装 / 卸载 / 启动 / 强停）。所有写操作都在
#   显式子命令下执行，不会在 preflight / verify 中修改设备。
#
# 子命令：
#   preflight        只读检查 adb、设备、APK、包名、安装状态、启动入口
#   install          安装 APK（默认 -r 覆盖安装；--clean-install 先卸载）
#   launch           启动应用，记录前台 Activity、PID、崩溃 / ANR
#   verify           不启动，检查当前前台、PID 和最近日志中的崩溃 / ANR
#   stop             强制停止应用
#   restore-original 安装原始 APK 并核对哈希
#   help             显示帮助
#
# 参数：
#   --apk <路径>          install 必填；preflight 可选。
#   --package <包名>      可选。未提供时尝试用 aapt 从 APK 推断。
#   --activity <组件>     可选。格式：包名/.Activity；默认解析 Launcher 入口。
#   --original-apk <路径> restore-original 必填。原始 APK。
#   --serial <序列号>     可选。多设备时指定目标设备。
#   --wait <秒>           可选。launch 后等待时间，默认 5。
#   --clean-install       可选。install 前先卸载目标包。
#   --no-clear-logcat     可选。launch 前不清空 logcat。
#   --dry-run             可选。只打印将执行的命令，不修改设备。
#   -h, --help            显示帮助。
#
#   错误输入示例：
#     --wait abc → exit 2；install 缺少 --apk → exit 2。
#
# 输出：
#   安装 / 启动 / 验证 / 恢复的 KEY=VALUE、【结论】；不修改本地 APK，
#   临时文件放在 mktemp 目录并在退出时删除。
#
# 依赖：
#   adb 必需；安装 / 恢复时需要 SHA-256 工具
#   （shasum / sha256sum / openssl 至少一个）；从 APK 推断包名时需要 aapt。
#   缺少时明确提示并退出，不会静默跳过。
#
# 退出码：
#   0 = 操作完成且判定通过（preflight 通过 / 安装一致 / 启动正常 / 恢复一致）
#   1 = 判定未通过（安装失败、前台不是目标、崩溃 / ANR、恢复哈希不一致）
#   2 = 参数、依赖或设备错误
#
set -euo pipefail
export LC_ALL=C

ACTION="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

APK=""
PKG=""
ACTIVITY=""
ORIGINAL_APK=""
SERIAL=""
WAIT_SECONDS=5
CLEAN_INSTALL=false
CLEAR_LOGCAT=true
DRY_RUN=false

usage() {
  cat <<'EOF'
用法:
  ./03-install-launch.sh preflight --apk <APK> [--package <包名>]
  ./03-install-launch.sh install --apk <APK> [--package <包名>] [--clean-install]
  ./03-install-launch.sh launch --package <包名> [--activity <组件>] [--wait 5]
  ./03-install-launch.sh verify --package <包名>
  ./03-install-launch.sh stop --package <包名>
  ./03-install-launch.sh restore-original --package <包名> --original-apk <原始APK>
  ./03-install-launch.sh help

选项:
  --apk <路径>          install 必填；preflight 可选。
  --package <包名>      可选。未提供时尝试用 aapt 从 APK 推断。
  --activity <组件>     可选。默认解析 Launcher 入口。
  --original-apk <路径> restore-original 必填。
  --serial <序列号>     可选。多设备时指定目标设备。
  --wait <秒>           可选。launch 后等待时间，默认 5。
  --clean-install       可选。install 前先卸载目标包。
  --no-clear-logcat     可选。launch 前不清空 logcat。
  --dry-run             可选。只打印命令，不修改设备。
  -h, --help            显示帮助。

错误输入示例:
  --wait abc → 打印本帮助并 exit 2；install 缺少 --apk → exit 2

退出码:
  0 = 操作完成且判定通过
  1 = 判定未通过
  2 = 参数、依赖或设备错误
EOF
}

case "$ACTION" in
  help|-h|--help)
    usage
    exit 0
    ;;
  preflight|install|launch|verify|stop|restore-original)
    ;;
  *)
    echo "[FAIL] 未知子命令: $ACTION" >&2
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
    --apk)
      [[ $# -ge 2 ]] || die_usage "--apk 需要一个值"
      APK="$2"
      shift 2
      ;;
    --package)
      [[ $# -ge 2 ]] || die_usage "--package 需要一个值"
      PKG="$2"
      shift 2
      ;;
    --activity)
      [[ $# -ge 2 ]] || die_usage "--activity 需要一个值"
      ACTIVITY="$2"
      shift 2
      ;;
    --original-apk)
      [[ $# -ge 2 ]] || die_usage "--original-apk 需要一个值"
      ORIGINAL_APK="$2"
      shift 2
      ;;
    --serial)
      [[ $# -ge 2 ]] || die_usage "--serial 需要一个值"
      SERIAL="$2"
      shift 2
      ;;
    --wait)
      [[ $# -ge 2 ]] || die_usage "--wait 需要一个值"
      WAIT_SECONDS="$2"
      shift 2
      ;;
    --clean-install)
      CLEAN_INSTALL=true
      shift
      ;;
    --no-clear-logcat)
      CLEAR_LOGCAT=false
      shift
      ;;
    --dry-run)
      DRY_RUN=true
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

if [[ ! "$WAIT_SECONDS" =~ ^[0-9]+$ ]]; then
  die_usage "--wait 必须是非负整数: $WAIT_SECONDS"
fi

if [[ -n "$APK" && ! -f "$APK" ]]; then
  echo "[FAIL] APK 不存在: $APK" >&2
  exit 2
fi
if [[ -n "$ORIGINAL_APK" && ! -f "$ORIGINAL_APK" ]]; then
  echo "[FAIL] 原始 APK 不存在: $ORIGINAL_APK" >&2
  exit 2
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

ADB=(adb)
if [[ -n "$SERIAL" ]]; then
  ADB=(adb -s "$SERIAL")
fi

need_device() {
  if ! "${ADB[@]}" get-state >/dev/null 2>&1; then
    echo "[FAIL] 没有在线 Android 设备${SERIAL:+ (serial=$SERIAL)}" >&2
    exit 1
  fi
}

need_package() {
  [[ -n "$PKG" ]] || die_usage "缺少 --package（或提供 --apk 以便推断）"
}

need_apk() {
  [[ -n "$APK" ]] || die_usage "缺少 --apk"
  [[ -f "$APK" ]] || { echo "[FAIL] APK 不存在: $APK" >&2; exit 2; }
}

conclusion() {
  echo "------------------------------------------------------------"
  echo "【结论】"
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
  [[ -n "$base" ]] || return 1
  printf '%s\n' "$base"
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

installed_sha() {
  local dev_path
  dev_path="$(device_pkg_path)" || return 1
  device_sha "$dev_path"
}

get_pid() {
  local out
  out="$("${ADB[@]}" shell pidof "$PKG" 2>/dev/null | tr -d '\r' || true)"
  out="$(printf '%s\n' "$out" | awk '{print $1}')"
  if [[ "$out" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$out"
    return 0
  fi
  out="$("${ADB[@]}" shell ps -A 2>/dev/null | tr -d '\r' | awk -v pkg="$PKG" '$NF == pkg {print $2; exit}' || true)"
  if [[ "$out" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$out"
    return 0
  fi
  return 1
}

resolve_launcher() {
  local out line
  out="$("${ADB[@]}" shell cmd package resolve-activity --brief \
    -a android.intent.action.MAIN \
    -c android.intent.category.LAUNCHER "$PKG" 2>/dev/null | tr -d '\r' || true)"
  line="$(printf '%s\n' "$out" | grep -E '^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+$' | tail -1 || true)"
  if [[ -z "$line" ]]; then
    line="$(printf '%s\n' "$out" | grep '/' | tail -1 | awk '{print $NF}' || true)"
  fi
  printf '%s\n' "$line"
}

get_foreground() {
  local dump line
  dump="$("${ADB[@]}" shell dumpsys activity activities 2>/dev/null | tr -d '\r' || true)"
  line="$(printf '%s\n' "$dump" | grep -m1 -E 'mResumedActivity|topResumedActivity' \
    | grep -oE '[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+' | head -1 || true)"
  if [[ -z "$line" ]]; then
    dump="$("${ADB[@]}" shell dumpsys window 2>/dev/null | tr -d '\r' || true)"
    line="$(printf '%s\n' "$dump" | grep -m1 -E 'mCurrentFocus|mFocusedApp' \
      | grep -oE '[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+' | head -1 || true)"
  fi
  printf '%s\n' "$line"
}

get_logcat_tail() {
  "${ADB[@]}" logcat -d -v brief -t 800 2>/dev/null | tr -d '\r' || true
}

run_install() {
  local apk="$1" out rc
  if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] adb install -r \"$apk\""
    return 0
  fi
  if [[ "$CLEAN_INSTALL" == true ]]; then
    echo "== 卸载目标包（--clean-install） =="
    "${ADB[@]}" uninstall "$PKG" >/dev/null 2>&1 || true
  fi

  echo "== 安装 APK =="
  set +e
  out="$("${ADB[@]}" install -r "$apk" 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out"

  if [[ $rc -eq 0 ]]; then
    return 0
  fi

  if printf '%s' "$out" | grep -qiE 'INSTALL_FAILED_UPDATE_INCOMPATIBLE|INSTALL_FAILED_ALREADY_EXISTS|INSTALL_FAILED_VERSION_DOWNGRADE|signature'; then
    echo "[WARN] 覆盖安装失败：签名或版本不兼容。卸载后重装，应用数据会被清除。"
    "${ADB[@]}" uninstall "$PKG" >/dev/null 2>&1 || true
    set +e
    out="$("${ADB[@]}" install "$apk" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out"
    return $rc
  fi
  return $rc
}

echo "============================================================"
echo "动态分析 03：安装、启动与运行状态"
echo "子命令：$ACTION"
echo "目标包：${PKG:-（未指定）}"
echo "时间：$(date '+%Y-%m-%d %H:%M:%S %z')"
echo "============================================================"

case "$ACTION" in
  preflight)
    need_device
    need_sha256
    [[ -n "$APK" || -n "$PKG" ]] || die_usage "至少需要 --apk 或 --package"

    LOCAL_SHA=""
    if [[ -n "$APK" ]]; then
      echo "[loading] 正在计算本地 APK SHA-256..."
      LOCAL_SHA="$(sha256_file "$APK")"
      echo "[done] 本地 APK SHA-256 计算完成"
      echo "LOCAL_APK_SHA256=$LOCAL_SHA"
    fi

    PACKAGE_INSTALLED=false
    INST_SHA=""
    if [[ -n "$PKG" ]] && device_pkg_path >/dev/null 2>&1; then
      PACKAGE_INSTALLED=true
      INST_SHA="$(installed_sha || true)"
    fi

    LAUNCHER=""
    if [[ -n "$PKG" ]]; then
      LAUNCHER="$(resolve_launcher)"
    fi

    LOGCAT_OK=false
    if "${ADB[@]}" logcat -d -t 1 >/dev/null 2>&1; then
      LOGCAT_OK=true
    fi

    HASH_MATCH=unknown
    if [[ -n "$LOCAL_SHA" && -n "$INST_SHA" ]]; then
      if [[ "$LOCAL_SHA" == "$INST_SHA" ]]; then
        HASH_MATCH=true
      else
        HASH_MATCH=false
      fi
    fi

    conclusion
    echo "PACKAGE_NAME=${PKG:-}"
    echo "PACKAGE_INSTALLED=$PACKAGE_INSTALLED"
    echo "INSTALLED_SHA256=${INST_SHA:-}"
    echo "HASH_MATCH=$HASH_MATCH"
    echo "LAUNCHER_COMPONENT=${LAUNCHER:-}"
    echo "LOGCAT_ACCESSIBLE=$LOGCAT_OK"
    echo "PREFLIGHT_PASSED=true"
    exit 0
    ;;

  install)
    need_device
    need_package
    need_apk
    need_sha256

    echo "[loading] 正在安装 APK（大文件可能需要几十秒）..."
    if ! run_install "$APK"; then
      echo "INSTALL_OK=false"
      exit 1
    fi
    echo "[done] 安装命令结束"

    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi

    LOCAL_SHA="$(sha256_file "$APK")"
    INST_SHA="$(installed_sha || true)"
    if [[ -z "$INST_SHA" ]]; then
      echo "[FAIL] 安装后无法读取设备 APK 哈希" >&2
      echo "INSTALL_OK=false"
      exit 1
    fi
    if [[ "$INST_SHA" != "$LOCAL_SHA" ]]; then
      echo "[FAIL] 安装后哈希不一致：local=$LOCAL_SHA device=$INST_SHA" >&2
      echo "INSTALL_OK=false"
      exit 1
    fi

    conclusion
    echo "LOCAL_APK_SHA256=$LOCAL_SHA"
    echo "INSTALLED_SHA256=$INST_SHA"
    echo "INSTALL_OK=true"
    echo "安装完成，且设备上的 APK 与本地样本逐字节一致。"
    exit 0
    ;;

  launch)
    need_device
    need_package

    if ! device_pkg_path >/dev/null 2>&1; then
      echo "[FAIL] 目标包未安装: $PKG" >&2
      exit 1
    fi

    if [[ -z "$ACTIVITY" ]]; then
      ACTIVITY="$(resolve_launcher)"
    fi
    if [[ -z "$ACTIVITY" ]]; then
      echo "[FAIL] 无法解析 Launcher 入口；请用 --activity 指定组件" >&2
      exit 1
    fi

    if [[ "$CLEAR_LOGCAT" == true && "$DRY_RUN" != true ]]; then
      "${ADB[@]}" logcat -c >/dev/null 2>&1 || true
    fi

    if [[ "$DRY_RUN" == true ]]; then
      echo "[DRY-RUN] adb shell am start -W -n $ACTIVITY"
      echo "DRY_RUN=true"
      exit 0
    fi

    echo "== 启动 $ACTIVITY =="
    set +e
    START_OUT="$("${ADB[@]}" shell am start -W -n "$ACTIVITY" 2>&1 | tr -d '\r')"
    START_RC=$?
    set -e
    printf '%s\n' "$START_OUT"

    sleep "$WAIT_SECONDS"

    PID="$(get_pid || true)"
    FOREGROUND="$(get_foreground)"
    LOGCAT="$(get_logcat_tail || true)"
    PKG_RE="${PKG//./\\.}"

    CRASH=false
    ANR=false
    if printf '%s' "$LOGCAT" | grep -qE "FATAL EXCEPTION|Process: ${PKG_RE}([[:space:],]|$)"; then
      CRASH=true
    fi
    if printf '%s' "$LOGCAT" | grep -qE "ANR in ${PKG_RE}([[:space:]]|$)"; then
      ANR=true
    fi

    LAUNCH_OK=false
    if [[ $START_RC -eq 0 ]] \
      && ! printf '%s' "$START_OUT" | grep -qE '^Error:'; then
      if [[ -n "$PID" && "$FOREGROUND" == *"$PKG/"* ]]; then
        if [[ "$CRASH" != true && "$ANR" != true ]]; then
          LAUNCH_OK=true
        fi
      fi
    fi

    conclusion
    echo "START_EXIT_CODE=$START_RC"
    echo "PID=${PID:-}"
    echo "FOREGROUND_ACTIVITY=${FOREGROUND:-}"
    echo "CRASH_DETECTED=$CRASH"
    echo "ANR_DETECTED=$ANR"
    echo "LAUNCH_OK=$LAUNCH_OK"
    if [[ "$LAUNCH_OK" == true ]]; then
      echo "目标应用已启动，前台为 $FOREGROUND，未发现崩溃或 ANR。"
    else
      echo "启动判定未通过；请结合上方 am start 输出、PID 和日志排查。"
    fi

    if [[ "$LAUNCH_OK" == true ]]; then
      exit 0
    fi
    exit 1
    ;;

  verify)
    need_device
    need_package

    if ! device_pkg_path >/dev/null 2>&1; then
      echo "[FAIL] 目标包未安装: $PKG" >&2
      exit 1
    fi

    PID="$(get_pid || true)"
    FOREGROUND="$(get_foreground)"
    LOGCAT="$(get_logcat_tail || true)"
    PKG_RE="${PKG//./\\.}"

    CRASH=false
    ANR=false
    if printf '%s' "$LOGCAT" | grep -qE "FATAL EXCEPTION|Process: ${PKG_RE}([[:space:],]|$)"; then
      CRASH=true
    fi
    if printf '%s' "$LOGCAT" | grep -qE "ANR in ${PKG_RE}([[:space:]]|$)"; then
      ANR=true
    fi

    VERIFY_PASSED=false
    if [[ -n "$PID" && "$FOREGROUND" == *"$PKG/"* && "$CRASH" != true && "$ANR" != true ]]; then
      VERIFY_PASSED=true
    fi

    conclusion
    echo "PID=${PID:-}"
    echo "FOREGROUND_ACTIVITY=${FOREGROUND:-}"
    echo "CRASH_DETECTED=$CRASH"
    echo "ANR_DETECTED=$ANR"
    echo "VERIFY_PASSED=$VERIFY_PASSED"
    if [[ "$VERIFY_PASSED" == true ]]; then
      echo "目标应用仍在前台运行，未发现崩溃或 ANR。"
    else
      echo "目标应用不在前台、进程不存在，或日志中出现崩溃 / ANR。"
    fi

    if [[ "$VERIFY_PASSED" == true ]]; then
      exit 0
    fi
    exit 1
    ;;

  stop)
    need_device
    need_package

    if [[ "$DRY_RUN" == true ]]; then
      echo "[DRY-RUN] adb shell am force-stop $PKG"
      exit 0
    fi

    "${ADB[@]}" shell am force-stop "$PKG" >/dev/null 2>&1 || true
    sleep 1
    PID="$(get_pid || true)"
    conclusion
    echo "PID_AFTER_STOP=${PID:-}"
    if [[ -z "$PID" ]]; then
      echo "STOPPED=true"
      echo "目标进程已停止。"
      exit 0
    fi
    echo "STOPPED=false"
    echo "目标进程仍在运行；可能有前台服务或系统拉活。"
    exit 1
    ;;

  restore-original)
    need_device
    need_package
    [[ -n "$ORIGINAL_APK" ]] || die_usage "restore-original 需要 --original-apk"
    need_sha256

    if [[ "$DRY_RUN" == true ]]; then
      echo "[DRY-RUN] adb install -r \"$ORIGINAL_APK\""
      echo "DRY_RUN=true"
      exit 0
    fi

    LOCAL_SHA="$(sha256_file "$ORIGINAL_APK")"
    INST_SHA="$(installed_sha || true)"
    if [[ -n "$INST_SHA" && "$INST_SHA" == "$LOCAL_SHA" ]]; then
      conclusion
      echo "ALREADY_ORIGINAL=true"
      echo "RESTORE_VERIFIED=true"
      echo "设备上已经是原始 APK。"
      exit 0
    fi

    # 复用安装逻辑；恢复场景必须允许签名不兼容时卸载重装
    APK_SAVED="$APK"
    APK="$ORIGINAL_APK"
    if ! run_install "$ORIGINAL_APK"; then
      APK="$APK_SAVED"
      conclusion
      echo "RESTORE_VERIFIED=false"
      echo "原始 APK 安装失败，恢复未完成。"
      exit 1
    fi
    APK="$APK_SAVED"

    INST_SHA="$(installed_sha || true)"
    conclusion
    if [[ -n "$INST_SHA" && "$INST_SHA" == "$LOCAL_SHA" ]]; then
      echo "RESTORE_VERIFIED=true"
      echo "已恢复原始 APK，并与本地样本逐字节一致。"
      exit 0
    fi
    echo "RESTORE_VERIFIED=false"
    echo "恢复后哈希仍不一致，请检查安装输出。"
    exit 1
    ;;
esac
