#!/usr/bin/env bash
#
# 05-traffic-capture.sh —— 通用动态分析：代理抓包与 TLS 行为观察
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   通过 mitmproxy 观察授权测试 App 的实际网络行为，回答：
#     - 是否发出了请求？请求了哪些 host / endpoint？
#     - 是否存在明文 HTTP？
#     - 是否出现 TLS 握手 / 证书错误（可能意味着证书绑定或未安装 CA）？
#     - "抓不到"到底是没请求、代理没生效，还是 TLS 无法解密？
#
#   重要：抓不到包不等于证书绑定，也不等于安全。脚本只报告观察到的现象。
#
#   实现方式：
#     - 用 adb reverse 把设备流量转到主机 mitmproxy，避免依赖同一网段；
#     - 抓包写入临时 flow 文件，再用 mitmproxy 的 FlowReader 汇总；
#     - 默认删除原始 flow（含完整请求/响应）；--keep-flow 才保留，
#       并以 0600 权限写入 evidence，同时打印警告。
#
# 子命令：
#   preflight        只读检查 adb、设备、mitmdump、Python mitmproxy 模块、当前代理
#   capture          启动 mitmproxy，配置设备代理，采集 N 秒后恢复并汇总
#   analyze          分析已有 flow 文件，不连接设备
#   help             显示帮助
#
# 参数：
#   --flow <路径>      analyze 必填。mitmproxy flow 文件。
#   --seconds <秒>     capture 采集时长，默认 30，范围 1–300。
#   --proxy-port <N>   mitmproxy 监听端口，默认 8080。
#   --package <包名>   可选。capture 前检查包是否安装。
#   --serial <序列号>  可选。多设备时指定目标设备。
#   --evidence-dir <目录> 证据目录，默认 evidence。
#   --label <标签>     可选。证据标签。
#   --keep-flow        可选。保留原始 flow（敏感，默认删除）。
#   --dry-run          可选。只打印将执行的命令，不修改设备。
#   -h, --help         显示帮助。
#
# 依赖：
#   capture：adb、mitmdump；若 CLI 不在 PATH，则回退到
#            python3 -m mitmproxy.tools.dump（需要 mitmproxy 模块）。
#   analyze：python3 + mitmproxy 模块。
#   缺失时明确提示安装方式并 exit 2，不会静默跳过。
#
# 用法：
#   ./05-traffic-capture.sh preflight --package com.example.app
#   ./05-traffic-capture.sh capture --package com.example.app --seconds 30
#   ./05-traffic-capture.sh analyze --flow ./evidence/flows.mitm
#   ./05-traffic-capture.sh --help
#
#   错误输入示例：
#     --seconds 0 → exit 2；analyze 缺少 --flow → exit 2。
#
# 输出：
#   FLOW_COUNT、HOST_COUNT、CLEARTEXT_COUNT、TLS_ERROR_COUNT、
#   PINNING_SUSPECTED、NO_TRAFFIC、endpoint 列表、证据 JSON 路径。
#
# 退出码：
#   0 = 抓包/分析完成，未发现明文或 TLS 错误
#   1 = 没有流量、存在明文 HTTP、或存在 TLS 错误（需人工判断）
#   2 = 参数、依赖或设备错误
#
set -euo pipefail
export LC_ALL=C

ACTION="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

FLOW=""
SECONDS_TO_CAPTURE=30
PROXY_PORT=8080
PKG=""
SERIAL=""
EVIDENCE_DIR="evidence"
LABEL="dynamic-analysis"
KEEP_FLOW=false
DRY_RUN=false

usage() {
  cat <<'EOF'
用法:
  ./05-traffic-capture.sh preflight [--package <包名>] [--serial <序列号>]
  ./05-traffic-capture.sh capture --package <包名> [--seconds 30] [选项]
  ./05-traffic-capture.sh analyze --flow <flow文件> [选项]
  ./05-traffic-capture.sh help

选项:
  --flow <路径>       analyze 必填。mitmproxy flow 文件。
  --seconds <秒>      capture 采集时长，默认 30，范围 1–300。
  --proxy-port <N>    mitmproxy 监听端口，默认 8080。
  --package <包名>    可选。capture 前检查包是否安装。
  --serial <序列号>   可选。多设备时指定目标设备。
  --evidence-dir <目录> 证据目录，默认 evidence。
  --label <标签>      可选。证据标签。
  --keep-flow         可选。保留原始 flow（含请求/响应，默认删除）。
  --dry-run           可选。只打印命令，不修改设备。
  -h, --help          显示帮助。

说明:
  capture 会临时设置设备全局 http_proxy 并执行 adb reverse，
  退出时（包括异常）自动恢复代理、移除 reverse、停止 mitmdump。
  抓不到流量不代表证书绑定；只代表本次观察没有拿到可解密的请求。

错误输入示例:
  --seconds 0 → 打印本帮助并 exit 2；analyze 缺少 --flow → exit 2

退出码:
  0 = 未发现明文或 TLS 错误
  1 = 没有流量、存在明文 HTTP、或存在 TLS 错误
  2 = 参数、依赖或设备错误
EOF
}

case "$ACTION" in
  help|-h|--help)
    usage
    exit 0
    ;;
  preflight|capture|analyze)
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
    --flow)
      [[ $# -ge 2 ]] || die_usage "--flow 需要一个值"
      FLOW="$2"
      shift 2
      ;;
    --seconds)
      [[ $# -ge 2 ]] || die_usage "--seconds 需要一个值"
      SECONDS_TO_CAPTURE="$2"
      shift 2
      ;;
    --proxy-port)
      [[ $# -ge 2 ]] || die_usage "--proxy-port 需要一个值"
      PROXY_PORT="$2"
      shift 2
      ;;
    --package)
      [[ $# -ge 2 ]] || die_usage "--package 需要一个值"
      PKG="$2"
      shift 2
      ;;
    --serial)
      [[ $# -ge 2 ]] || die_usage "--serial 需要一个值"
      SERIAL="$2"
      shift 2
      ;;
    --evidence-dir)
      [[ $# -ge 2 ]] || die_usage "--evidence-dir 需要一个值"
      EVIDENCE_DIR="$2"
      shift 2
      ;;
    --label)
      [[ $# -ge 2 ]] || die_usage "--label 需要一个值"
      LABEL="$2"
      shift 2
      ;;
    --keep-flow)
      KEEP_FLOW=true
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

if [[ ! "$SECONDS_TO_CAPTURE" =~ ^[0-9]+$ ]] || [[ "$SECONDS_TO_CAPTURE" -lt 1 || "$SECONDS_TO_CAPTURE" -gt 300 ]]; then
  die_usage "--seconds 必须是 1–300 的整数: $SECONDS_TO_CAPTURE"
fi
if [[ ! "$PROXY_PORT" =~ ^[0-9]+$ ]] || [[ "$PROXY_PORT" -lt 1 || "$PROXY_PORT" -gt 65535 ]]; then
  die_usage "--proxy-port 必须是 1–65535 的整数: $PROXY_PORT"
fi

need_adb() {
  if ! command -v adb >/dev/null 2>&1; then
    echo "[FAIL] 缺少工具: adb" >&2
    echo "       macOS: brew install android-platform-tools" >&2
    echo "       Linux: sudo apt install android-tools-adb" >&2
    exit 2
  fi
}

need_py_mitm() {
  if ! python3 -c 'import mitmproxy' >/dev/null 2>&1; then
    echo "[FAIL] python3 无法导入 mitmproxy 模块。" >&2
    echo "       安装提示: python3 -m pip install --user mitmproxy" >&2
    exit 2
  fi
}

MITMDUMP_CMD=()

need_mitm() {
  if command -v mitmdump >/dev/null 2>&1; then
    MITMDUMP_CMD=(mitmdump)
  elif python3 -c 'import mitmproxy.tools.dump' >/dev/null 2>&1; then
    MITMDUMP_CMD=(python3 -m mitmproxy.tools.dump)
  else
    echo "[FAIL] 缺少工具: mitmdump" >&2
    echo "       安装提示: brew install mitmproxy" >&2
    echo "       或: python3 -m pip install --user mitmproxy" >&2
    exit 2
  fi
  need_py_mitm
}

adb_cmd() {
  if [[ -n "$SERIAL" ]]; then
    printf 'adb -s %s' "$SERIAL"
  else
    printf 'adb'
  fi
}

need_device() {
  need_adb
  if [[ -n "$SERIAL" ]]; then
    if ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
      echo "[FAIL] 指定设备不在线: $SERIAL" >&2
      exit 1
    fi
  else
    if ! adb get-state >/dev/null 2>&1; then
      echo "[FAIL] 没有在线 Android 设备" >&2
      exit 1
    fi
  fi
}

ADB=(adb)
if [[ -n "$SERIAL" ]]; then
  ADB=(adb -s "$SERIAL")
fi

PROXY_SET=false
REVERSE_SET=false
MITM_PID=""
WORKDIR=""

cleanup() {
  if [[ "$PROXY_SET" == true ]]; then
    "${ADB[@]}" shell settings put global http_proxy :0 >/dev/null 2>&1 || true
  fi
  if [[ "$REVERSE_SET" == true ]]; then
    "${ADB[@]}" reverse --remove "tcp:${PROXY_PORT}" >/dev/null 2>&1 || true
  fi
  if [[ -n "$MITM_PID" ]]; then
    kill "$MITM_PID" >/dev/null 2>&1 || true
    wait "$MITM_PID" 2>/dev/null || true
  fi
  if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT INT TERM

analyze_flow() {
  local flow_file="$1"
  mkdir -p "$EVIDENCE_DIR"
  python3 - "$flow_file" "$EVIDENCE_DIR" "$LABEL" <<'PY'
import json
import os
import re
import sys
from datetime import datetime, timezone

flow_path, evidence_dir, label = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    from mitmproxy.io import FlowReader
except Exception as exc:
    print("[FAIL] 无法导入 mitmproxy.io: {}".format(exc), file=sys.stderr)
    sys.exit(2)

SENSITIVE_QUERY = re.compile(
    r"(?i)([?&](?:token|access_token|refresh_token|signature|sig|code|state|password)=)[^&\s]+"
)


def redact(text):
    text = SENSITIVE_QUERY.sub(r"\1<REDACTED>", text)
    text = re.sub(
        r"(?i)((?:proxy-)?authorization\s*[:=]\s*)[^,;]*",
        r"\1<REDACTED>", text,
    )
    text = re.sub(r"(?i)(\bBearer\s+)\S+", r"\1<REDACTED>", text)
    text = re.sub(
        r"(?i)((?:access[_-]?token|refresh[_-]?token|token|password|secret|"
        r"signature)\s*[:=]\s*)[^\s&;]+",
        r"\1<REDACTED>", text,
    )
    return text


flows = []
try:
    print("[loading] 正在解析 flow 文件（大文件可能需要一段时间）...", file=sys.stderr)
    with open(flow_path, "rb") as fh:
        reader = FlowReader(fh)
        for flow in reader.stream():
            flows.append(flow)
    print("[done] 已读取 {} 个 flow".format(len(flows)), file=sys.stderr)
except Exception as exc:
    print("[FAIL] 无法读取 flow 文件: {}".format(exc), file=sys.stderr)
    sys.exit(2)

hosts = {}
endpoints = []
errors = []
cleartext_count = 0
tls_error_count = 0

for flow in flows:
    request = getattr(flow, "request", None)
    response = getattr(flow, "response", None)
    error = getattr(flow, "error", None)

    if error:
        message = redact(str(error))
        errors.append(message)
        if re.search(r"(?i)tls|handshake|certificate|ssl", message):
            tls_error_count += 1

    if request is None:
        continue

    scheme = getattr(request, "scheme", "") or ""
    host = getattr(request, "pretty_host", None) or getattr(request, "host", "") or ""
    method = getattr(request, "method", "") or ""
    path = getattr(request, "path", "") or ""
    status = getattr(response, "status_code", None) if response else None

    if scheme == "http":
        cleartext_count += 1

    hosts[host] = hosts.get(host, 0) + 1
    endpoint = {
        "method": method,
        "scheme": scheme,
        "host": host,
        "path": redact(path),
        "status": status,
    }
    key = (method, scheme, host, endpoint["path"], status)
    if key not in {(e["method"], e["scheme"], e["host"], e["path"], e["status"])
                   for e in endpoints}:
        endpoints.append(endpoint)

flow_count = len(flows)
no_traffic = flow_count == 0
pinning_suspected = (tls_error_count > 0 and cleartext_count == 0)
result = {
    "schema": "app-safe/traffic-capture/v1",
    "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "label": label,
    "flow_count": flow_count,
    "host_count": len(hosts),
    "hosts": sorted(hosts.items(), key=lambda item: (-item[1], item[0])),
    "cleartext_count": cleartext_count,
    "tls_error_count": tls_error_count,
    "error_count": len(errors),
    "pinning_suspected": pinning_suspected,
    "no_traffic": no_traffic,
    "endpoints": endpoints[:100],
    "errors": errors[:20],
    "notes": [
        "抓不到流量不等于证书绑定，也不等于安全。",
        "TLS 错误可能来自证书绑定、未安装 CA、代理配置或网络问题。",
        "明文 HTTP 只说明观察到明文请求，需结合业务判断影响。",
    ],
}

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
evidence_path = os.path.join(evidence_dir, "05-traffic-capture-{}.json".format(stamp))
temp_path = evidence_path + ".tmp"
with open(temp_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
os.replace(temp_path, evidence_path)
os.chmod(evidence_path, 0o600)

print("============================================================")
print("动态分析 05：代理抓包与 TLS 行为观察")
print("Flow 文件：{}".format(flow_path))
print("============================================================")
print("FLOW_COUNT={}".format(flow_count))
print("HOST_COUNT={}".format(len(hosts)))
print("HOSTS={}".format(", ".join(host for host, _count in result["hosts"])))
print("CLEARTEXT_COUNT={}".format(cleartext_count))
print("TLS_ERROR_COUNT={}".format(tls_error_count))
print("ERROR_COUNT={}".format(len(errors)))
print("PINNING_SUSPECTED={}".format(str(pinning_suspected).lower()))
print("NO_TRAFFIC={}".format(str(no_traffic).lower()))
print("------------------------------------------------------------")
print("【结论】")
if no_traffic:
    print("没有捕获到流量：可能是 App 未运行/未触发请求、未使用系统代理，"
          "或 TLS 无法解密。不能据此判定存在证书绑定。")
elif cleartext_count > 0:
    print("观察到 {} 个明文 HTTP 请求；这是明确的传输层风险信号。".format(cleartext_count))
elif tls_error_count > 0:
    print("观察到 {} 个 TLS 错误；可能是证书绑定、CA 未安装或代理配置问题，"
          "需结合日志和 App 行为判断。".format(tls_error_count))
else:
    print("已捕获流量，未观察到明文 HTTP 或 TLS 错误。")
print("------------------------------------------------------------")
for index, endpoint in enumerate(result["endpoints"][:20], 1):
    print("ENDPOINT_{}={} {}://{}{} status={}".format(
        index, endpoint["method"], endpoint["scheme"], endpoint["host"],
        endpoint["path"], endpoint["status"],
    ))
print("EVIDENCE_JSON={}".format(evidence_path))

if no_traffic or cleartext_count > 0 or tls_error_count > 0 or errors:
    sys.exit(1)
sys.exit(0)
PY
}

case "$ACTION" in
  preflight)
    need_adb
    PKG_INSTALLED=unknown
    if [[ -n "$PKG" ]]; then
      need_device
      PKG_PATH="$("${ADB[@]}" shell pm path "$PKG" 2>/dev/null | tr -d '\r' || true)"
      if [[ "$PKG_PATH" == package:* ]]; then
        PKG_INSTALLED=true
      else
        PKG_INSTALLED=false
        echo "[FAIL] 目标包未安装: $PKG" >&2
      fi
      echo "PACKAGE_INSTALLED=$PKG_INSTALLED"
    else
      echo "PACKAGE_INSTALLED=unknown"
    fi

    MITM_VERSION=""
    if command -v mitmdump >/dev/null 2>&1; then
      MITM_VERSION="$(mitmdump --version 2>&1 | head -1 || true)"
      echo "MITMDUMP_AVAILABLE=true"
      echo "MITMDUMP_MODE=cli"
      echo "MITMDUMP_VERSION=$MITM_VERSION"
    elif python3 -c 'import mitmproxy.tools.dump' >/dev/null 2>&1; then
      MITM_VERSION="python-module"
      echo "MITMDUMP_AVAILABLE=true"
      echo "MITMDUMP_MODE=python-module"
      echo "MITMDUMP_VERSION=$MITM_VERSION"
    else
      echo "MITMDUMP_AVAILABLE=false"
      echo "MITMDUMP_MODE=none"
    fi

    PY_MODULE=false
    if python3 -c 'import mitmproxy' >/dev/null 2>&1; then
      PY_MODULE=true
    fi
    echo "PYTHON_MITMPROXY_MODULE=$PY_MODULE"

    if [[ -n "$SERIAL" ]]; then
      DEVICE_PROXY="$(adb -s "$SERIAL" shell settings get global http_proxy 2>/dev/null | tr -d '\r' || true)"
    else
      DEVICE_PROXY="$(adb shell settings get global http_proxy 2>/dev/null | tr -d '\r' || true)"
    fi
    echo "DEVICE_HTTP_PROXY=${DEVICE_PROXY:-unknown}"

    if [[ "$MITM_VERSION" == "" || "$PY_MODULE" != true ]]; then
      echo "[FAIL] mitmproxy 未安装或 Python 模块不可用；capture 无法执行。" >&2
      echo "       brew install mitmproxy" >&2
      echo "       python3 -m pip install --user mitmproxy" >&2
      echo "PREFLIGHT_PASSED=false"
      exit 2
    fi
    if [[ "$PKG_INSTALLED" == false ]]; then
      echo "PREFLIGHT_PASSED=false"
      exit 1
    fi
    echo "PREFLIGHT_PASSED=true"
    exit 0
    ;;

  capture)
    need_device
    need_mitm
    [[ -n "$PKG" ]] || die_usage "capture 需要 --package"

    if [[ "$DRY_RUN" == true ]]; then
      echo "[DRY-RUN] ${MITMDUMP_CMD[*]} -q -w <flow> --listen-host 127.0.0.1 --listen-port $PROXY_PORT"
      echo "[DRY-RUN] adb reverse tcp:$PROXY_PORT tcp:$PROXY_PORT"
      echo "[DRY-RUN] adb shell settings put global http_proxy 127.0.0.1:$PROXY_PORT"
      echo "DRY_RUN=true"
      exit 0
    fi

    if ! "${ADB[@]}" shell pm path "$PKG" >/dev/null 2>&1; then
      echo "[FAIL] 目标包未安装: $PKG" >&2
      exit 1
    fi

    WORKDIR="$(mktemp -d)"
    FLOW_FILE="$WORKDIR/flows.mitm"
    MITM_LOG="$WORKDIR/mitm.log"

    echo "[loading] 正在启动 mitmdump（端口 $PROXY_PORT）..."
    "${MITMDUMP_CMD[@]}" -q -w "$FLOW_FILE" --listen-host 127.0.0.1 \
      --listen-port "$PROXY_PORT" --set block_global=false >"$MITM_LOG" 2>&1 &
    MITM_PID=$!

    READY=false
    for _ in $(seq 1 40); do
      if (echo >/dev/tcp/127.0.0.1/"$PROXY_PORT") >/dev/null 2>&1; then
        READY=true
        break
      fi
      sleep 0.25
    done
    if [[ "$READY" != true ]]; then
      echo "[FAIL] mitmdump 未能监听 127.0.0.1:$PROXY_PORT" >&2
      tail -20 "$MITM_LOG" >&2 || true
      exit 2
    fi
    echo "[done] mitmdump 已就绪"

    "${ADB[@]}" reverse "tcp:${PROXY_PORT}" "tcp:${PROXY_PORT}" >/dev/null
    REVERSE_SET=true
    "${ADB[@]}" shell settings put global http_proxy "127.0.0.1:${PROXY_PORT}" >/dev/null
    PROXY_SET=true

    echo "[loading] 正在采集流量（${SECONDS_TO_CAPTURE} 秒）；请现在操作 App..."
    sleep "$SECONDS_TO_CAPTURE"
    echo "[done] 采集结束"

    # 先恢复设备状态，再分析，避免异常时残留代理
    "${ADB[@]}" shell settings put global http_proxy :0 >/dev/null 2>&1 || true
    PROXY_SET=false
    "${ADB[@]}" reverse --remove "tcp:${PROXY_PORT}" >/dev/null 2>&1 || true
    REVERSE_SET=false
    kill "$MITM_PID" >/dev/null 2>&1 || true
    wait "$MITM_PID" 2>/dev/null || true
    MITM_PID=""

    if [[ ! -s "$FLOW_FILE" ]]; then
      echo "[WARN] flow 文件为空；可能没有流量或代理未生效。" >&2
    fi

    if [[ "$KEEP_FLOW" == true ]]; then
      mkdir -p "$EVIDENCE_DIR"
      DEST="$EVIDENCE_DIR/05-traffic-capture-$(date +%Y%m%d-%H%M%S).mitm"
      cp "$FLOW_FILE" "$DEST"
      chmod 600 "$DEST"
      echo "RAW_FLOW=$DEST"
      echo "[WARN] 原始 flow 包含完整请求/响应，可能含 Token/业务数据，请按授权范围保管。" >&2
    fi

    set +e
    analyze_flow "$FLOW_FILE"
    RC=$?
    set -e
    exit "$RC"
    ;;

  analyze)
    [[ -n "$FLOW" ]] || die_usage "analyze 需要 --flow"
    [[ -f "$FLOW" ]] || { echo "[FAIL] flow 文件不存在: $FLOW" >&2; exit 2; }
    need_py_mitm
    set +e
    analyze_flow "$FLOW"
    RC=$?
    set -e
    exit "$RC"
    ;;
esac
