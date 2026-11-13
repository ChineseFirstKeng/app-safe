#!/usr/bin/env bash
#
# 12-ios-runtime.sh —— 通用动态分析：iOS 运行时入口与容器检查
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   - 检查 Xcode / simctl / devicectl 是否可用，列出模拟器与真机；
#   - 在模拟器上安装 .app 或 .ipa、启动、终止、读取容器路径；
#   - 用 simctl openurl 验证 URL Scheme / 深链入口是否被系统接受；
#   - 在已授权的真机上用 devicectl 安装与启动（实验性）。
#
#   重要：
#     - simctl openurl 返回 0 只代表命令被模拟器接受，不证明 App 处理了参数；
#     - App Store 加密的 IPA 不能直接在模拟器运行，需要已解密的 .app；
#     - 真机命令依赖 Xcode 15+ 的 devicectl，部分子命令可能因版本不同而失败。
#
# 子命令：
#   preflight        只读检查 macOS / xcrun / 模拟器 / 真机
#   sim-list         列出模拟器
#   sim-install      安装 .app 或 .ipa 到模拟器
#   sim-launch       启动模拟器上的 App
#   sim-openurl      向模拟器发送 URL Scheme
#   sim-terminate    终止模拟器上的 App
#   sim-container    读取模拟器 App 容器路径
#   device-list      列出已连接真机
#   device-install   安装 .app 到真机（实验性）
#   device-launch    启动真机 App，可选 --url（实验性）
#   help             显示帮助
#
# 参数：
#   --device <ID>     可选。模拟器 UDID 或 booted，默认 booted。
#   --app <路径>      sim-install / device-install 必填。.app 或 .ipa。
#   --bundle <ID>     sim-launch / sim-openurl 之外的 App bundle id。
#   --url <URL>       sim-openurl / device-launch 可选。待打开的 URL。
#   --udid <UDID>     device-install / device-launch 必填。真机 UDID。
#   --console         可选。sim-launch 时附加 --console（可能阻塞）。
#   --evidence-dir <目录> 证据目录，默认 evidence。
#   --dry-run         可选。只打印命令，不执行。
#   -h, --help        显示帮助。
#
#   错误输入示例：
#     sim-openurl 缺少 --url → exit 2；--app 路径不存在 → exit 2。
#
# 输出：
#   simctl / devicectl 输出、SIM_*_OK / URL_DELIVERED 等 KEY=VALUE、
#   【结论】；可选证据文本。临时解压目录退出时删除。
#
# 依赖：
#   macOS、xcrun、simctl；真机命令还需要 devicectl（Xcode 15+）。
#   缺少时明确提示安装方式并 exit 2。
#
# 退出码：
#   0 = 命令成功 / preflight 通过
#   1 = 运行环境不满足，或命令执行失败
#   2 = 参数、依赖或输入错误
#
set -euo pipefail
export LC_ALL=C

ACTION="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

DEVICE="booted"
APP=""
BUNDLE=""
URL=""
UDID=""
CONSOLE=false
EVIDENCE_DIR="evidence"
DRY_RUN=false
APP_WORKDIR=""

cleanup() {
  if [[ -n "$APP_WORKDIR" && -d "$APP_WORKDIR" ]]; then
    rm -rf "$APP_WORKDIR"
  fi
}
trap cleanup EXIT INT TERM

usage() {
  cat <<'EOF'
用法:
  ./12-ios-runtime.sh preflight
  ./12-ios-runtime.sh sim-list
  ./12-ios-runtime.sh sim-install --app <app/ipa> [--device booted]
  ./12-ios-runtime.sh sim-launch --bundle <bundle-id> [--device booted] [--console]
  ./12-ios-runtime.sh sim-openurl --url <scheme://...> [--device booted]
  ./12-ios-runtime.sh sim-terminate --bundle <bundle-id> [--device booted]
  ./12-ios-runtime.sh sim-container --bundle <bundle-id> [--device booted]
  ./12-ios-runtime.sh device-list
  ./12-ios-runtime.sh device-install --app <app> --udid <udid>
  ./12-ios-runtime.sh device-launch --bundle <bundle-id> --udid <udid> [--url <url>]
  ./12-ios-runtime.sh help

选项:
  --device <ID>     模拟器 UDID 或 booted，默认 booted。
  --app <路径>      .app 或 .ipa。
  --bundle <ID>     App bundle id。
  --url <URL>       URL Scheme / 深链。
  --udid <UDID>     真机 UDID。
  --console         sim-launch 时附加 --console（可能阻塞）。
  --evidence-dir <目录> 证据目录，默认 evidence。
  --dry-run         只打印命令。
  -h, --help        显示帮助。

错误输入示例:
  sim-openurl 缺少 --url → 打印本帮助并 exit 2；--app 路径不存在 → exit 2

退出码:
  0 = 成功 / preflight 通过
  1 = 环境不满足或命令失败
  2 = 参数、依赖或输入错误
EOF
}

case "$ACTION" in
  help|-h|--help)
    usage
    exit 0
    ;;
  preflight|sim-list|sim-install|sim-launch|sim-openurl|sim-terminate|sim-container|device-list|device-install|device-launch)
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
    --device)
      [[ $# -ge 2 ]] || die_usage "--device 需要一个值"
      DEVICE="$2"
      shift 2
      ;;
    --app)
      [[ $# -ge 2 ]] || die_usage "--app 需要一个值"
      APP="$2"
      shift 2
      ;;
    --bundle)
      [[ $# -ge 2 ]] || die_usage "--bundle 需要一个值"
      BUNDLE="$2"
      shift 2
      ;;
    --url)
      [[ $# -ge 2 ]] || die_usage "--url 需要一个值"
      URL="$2"
      shift 2
      ;;
    --udid)
      [[ $# -ge 2 ]] || die_usage "--udid 需要一个值"
      UDID="$2"
      shift 2
      ;;
    --console)
      CONSOLE=true
      shift
      ;;
    --evidence-dir)
      [[ $# -ge 2 ]] || die_usage "--evidence-dir 需要一个值"
      EVIDENCE_DIR="$2"
      shift 2
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

need_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "[FAIL] 本脚本依赖 macOS 的 xcrun / simctl / devicectl。" >&2
    exit 2
  fi
}

need_xcrun() {
  if ! command -v xcrun >/dev/null 2>&1; then
    echo "[FAIL] 缺少工具: xcrun" >&2
    echo "       安装提示: xcode-select --install" >&2
    exit 2
  fi
  if ! xcrun simctl help >/dev/null 2>&1; then
    echo "[FAIL] xcrun simctl 不可用；请安装 Xcode 或 Command Line Tools。" >&2
    echo "       安装提示: xcode-select --install" >&2
    exit 2
  fi
}

need_file() {
  local path="$1"
  [[ -n "$path" ]] || die_usage "缺少文件路径"
  [[ -f "$path" || -d "$path" ]] || {
    echo "[FAIL] 路径不存在: $path" >&2
    exit 2
  }
}

redact_url() {
  printf '%s' "$1" | sed -E \
    's/([?&](code|state|token|access_token|refresh_token|signature|sig|password)=)[^&]*/\1<REDACTED>/g'
}

write_evidence() {
  [[ "$DRY_RUN" == true ]] && return 0
  [[ -n "$EVIDENCE_DIR" ]] || return 0
  mkdir -p "$EVIDENCE_DIR"
  local file="$EVIDENCE_DIR/12-ios-runtime-$(date +%Y%m%d-%H%M%S).txt"
  {
    echo "ACTION=$ACTION"
    echo "DEVICE=${DEVICE:-}"
    echo "BUNDLE=${BUNDLE:-}"
    echo "UDID=${UDID:-}"
    echo "URL_REDACTED=$(redact_url "${URL:-}")"
    for line in "$@"; do
      echo "$line"
    done
  } > "$file"
  chmod 600 "$file"
  echo "EVIDENCE_FILE=$file"
}

run_cmd() {
  if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] $*"
    return 0
  fi
  set +e
  OUTPUT="$("$@" 2>&1)"
  RC=$?
  set -e
  printf '%s\n' "$OUTPUT"
  return $RC
}

conclusion() {
  echo "------------------------------------------------------------"
  echo "【结论】"
}

prepare_app_path() {
  local input="$1" workdir=""
  if [[ -d "$input" ]]; then
    printf '%s\n' "$input"
    return 0
  fi
  if [[ "$input" == *.ipa ]]; then
    if ! command -v unzip >/dev/null 2>&1; then
      echo "[FAIL] 缺少工具: unzip" >&2
      exit 2
    fi
    workdir="$(mktemp -d)"
    APP_WORKDIR="$workdir"
    echo "[loading] 正在解压 IPA（文件较大时可能需要几十秒）..." >&2
    if ! unzip -oq "$input" -d "$workdir"; then
      echo "[FAIL] IPA 解压失败: $input" >&2
      rm -rf "$workdir"
      APP_WORKDIR=""
      exit 2
    fi
    local app
    app="$(find "$workdir/Payload" -maxdepth 1 -name '*.app' -type d | head -1 || true)"
    if [[ -z "$app" ]]; then
      echo "[FAIL] IPA 中没有 Payload/*.app: $input" >&2
      rm -rf "$workdir"
      APP_WORKDIR=""
      exit 2
    fi
    echo "[done] IPA 解压完成" >&2
    printf '%s\n' "$app"
    return 0
  fi
  echo "[FAIL] --app 需要 .app 目录或 .ipa 文件: $input" >&2
  exit 2
}

case "$ACTION" in
  preflight)
    need_macos
    need_xcrun
    BOOTED_COUNT="$(xcrun simctl list devices booted 2>/dev/null | grep -c 'Booted' || true)"
    DEVICE_COUNT=""
    if command -v devicectl >/dev/null 2>&1; then
      DEVICE_COUNT="$(xcrun devicectl list devices 2>/dev/null | grep -c 'connected' || true)"
    fi
    echo "MACOS=true"
    echo "XCRUN_AVAILABLE=true"
    echo "BOOTED_SIMULATORS=$BOOTED_COUNT"
    echo "DEVICECTL_AVAILABLE=$([[ -n "$DEVICE_COUNT" ]] && echo true || echo false)"
    echo "CONNECTED_DEVICES=${DEVICE_COUNT:-unknown}"
    if [[ "$BOOTED_COUNT" -eq 0 ]] \
      && { [[ -z "$DEVICE_COUNT" ]] || [[ "$DEVICE_COUNT" -eq 0 ]]; }; then
      conclusion
      echo "运行环境未就绪：没有 booted 模拟器或已连接真机。"
      echo "PREFLIGHT_PASSED=false"
      echo "没有 booted 模拟器或已连接真机；请先启动模拟器或连接授权设备。" >&2
      exit 1
    fi
    conclusion
    echo "Xcode 工具链可用，且存在可用的模拟器或真机目标。"
    echo "PREFLIGHT_PASSED=true"
    exit 0
    ;;

  sim-list)
    need_macos
    need_xcrun
    run_cmd xcrun simctl list devices
    RC=$?
    conclusion
    echo "模拟器列表已输出；本命令未启动或修改任何模拟器。"
    exit $RC
    ;;

  sim-install)
    need_macos
    need_xcrun
    need_file "$APP"
    APP_PATH="$(prepare_app_path "$APP")"
    echo "INSTALL_TARGET=${DEVICE}"
    echo "APP_PATH=$APP_PATH"
    run_cmd xcrun simctl install "$DEVICE" "$APP_PATH"
    RC=$?
    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi
    if [[ $RC -eq 0 ]]; then
      echo "SIM_INSTALL_OK=true"
      write_evidence "SIM_INSTALL_OK=true" "APP_PATH=$APP_PATH"
    else
      echo "SIM_INSTALL_OK=false"
    fi
    conclusion
    if [[ $RC -eq 0 ]]; then
      echo "安装命令成功；是否可启动仍需 sim-launch 验证。"
    else
      echo "安装失败；检查 .app 架构、签名和模拟器版本。"
    fi
    exit $RC
    ;;

  sim-launch)
    need_macos
    need_xcrun
    [[ -n "$BUNDLE" ]] || die_usage "sim-launch 需要 --bundle"
    if [[ "$CONSOLE" == true ]]; then
      echo "[WARN] --console 会附加到 App 输出，可能长时间阻塞；可用 Ctrl-C 结束。" >&2
      run_cmd xcrun simctl launch --console "$DEVICE" "$BUNDLE"
    else
      run_cmd xcrun simctl launch "$DEVICE" "$BUNDLE"
    fi
    RC=$?
    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi
    if [[ $RC -eq 0 ]]; then
      echo "SIM_LAUNCH_OK=true"
      write_evidence "SIM_LAUNCH_OK=true" "BUNDLE=$BUNDLE"
    else
      echo "SIM_LAUNCH_OK=false"
    fi
    conclusion
    if [[ $RC -eq 0 ]]; then
      echo "启动命令成功；是否保持前台仍需结合 App 行为或截图确认。"
    else
      echo "启动失败；检查 bundle id、安装状态和模拟器版本。"
    fi
    exit $RC
    ;;

  sim-openurl)
    need_macos
    need_xcrun
    [[ -n "$URL" ]] || die_usage "sim-openurl 需要 --url"
    echo "URL_REDACTED=$(redact_url "$URL")"
    echo "OPENURL_TARGET=${DEVICE}"
    run_cmd xcrun simctl openurl "$DEVICE" "$URL"
    RC=$?
    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi
    if [[ $RC -eq 0 ]]; then
      echo "URL_DELIVERED=true"
      echo "说明：simctl 接受 URL 只代表系统尝试打开，不证明 App 处理了参数或漏洞成立。"
      write_evidence "URL_DELIVERED=true"
    else
      echo "URL_DELIVERED=false"
    fi
    conclusion
    if [[ $RC -eq 0 ]]; then
      echo "系统已接受 URL；这不证明 App 处理了参数或深链漏洞成立。"
    else
      echo "URL 未被系统接受；检查 scheme、目标 App 是否安装和设备状态。"
    fi
    exit $RC
    ;;

  sim-terminate)
    need_macos
    need_xcrun
    [[ -n "$BUNDLE" ]] || die_usage "sim-terminate 需要 --bundle"
    run_cmd xcrun simctl terminate "$DEVICE" "$BUNDLE"
    RC=$?
    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi
    echo "SIM_TERMINATED=$([[ $RC -eq 0 ]] && echo true || echo false)"
    conclusion
    echo "终止命令结果见 SIM_TERMINATED；未验证 App 内部状态。"
    exit $RC
    ;;

  sim-container)
    need_macos
    need_xcrun
    [[ -n "$BUNDLE" ]] || die_usage "sim-container 需要 --bundle"
    run_cmd xcrun simctl get_app_container "$DEVICE" "$BUNDLE" data
    RC=$?
    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi
    conclusion
    echo "容器路径已输出；未读取或复制容器内容。"
    exit $RC
    ;;

  device-list)
    need_macos
    if ! command -v devicectl >/dev/null 2>&1; then
      echo "[FAIL] 缺少 devicectl（Xcode 15+）。" >&2
      exit 2
    fi
    echo "[loading] 正在枚举真机（devicectl 可能需要几秒）..."
    run_cmd xcrun devicectl list devices
    RC=$?
    echo "[done] 真机枚举结束"
    conclusion
    echo "真机列表已输出；devicectl 输出格式随 Xcode 版本可能不同。"
    exit $RC
    ;;

  device-install)
    need_macos
    [[ -n "$UDID" ]] || die_usage "device-install 需要 --udid"
    need_file "$APP"
    if ! command -v devicectl >/dev/null 2>&1; then
      echo "[FAIL] 缺少 devicectl（Xcode 15+）。" >&2
      exit 2
    fi
    run_cmd xcrun devicectl device install app --device "$UDID" "$APP"
    RC=$?
    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi
    echo "DEVICE_INSTALL_OK=$([[ $RC -eq 0 ]] && echo true || echo false)"
    conclusion
    echo "真机安装结果见 DEVICE_INSTALL_OK；安装成功不证明 App 可运行。"
    exit $RC
    ;;

  device-launch)
    need_macos
    [[ -n "$UDID" ]] || die_usage "device-launch 需要 --udid"
    [[ -n "$BUNDLE" ]] || die_usage "device-launch 需要 --bundle"
    if ! command -v devicectl >/dev/null 2>&1; then
      echo "[FAIL] 缺少 devicectl（Xcode 15+）。" >&2
      exit 2
    fi
    if [[ -n "$URL" ]]; then
      echo "URL_REDACTED=$(redact_url "$URL")"
      run_cmd xcrun devicectl device process launch --device "$UDID" \
        --payload-url "$URL" "$BUNDLE"
    else
      run_cmd xcrun devicectl device process launch --device "$UDID" "$BUNDLE"
    fi
    RC=$?
    if [[ "$DRY_RUN" == true ]]; then
      echo "DRY_RUN=true"
      exit 0
    fi
    echo "DEVICE_LAUNCH_OK=$([[ $RC -eq 0 ]] && echo true || echo false)"
    echo "说明：真机 URL 启动为实验性能力；失败时请以 Xcode / devicectl 版本输出为准。"
    conclusion
    echo "真机启动结果见 DEVICE_LAUNCH_OK；URL 传递能力依赖 devicectl 版本。"
    exit $RC
    ;;
esac
