#!/usr/bin/env python3
#
# 10-replay-runtime.py —— 通用动态分析：受控请求重放与业务结果对比
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   把"在 App 外重放请求"做成受控、可留证的动作：
#     - 从 JSON 请求文件或命令行构造请求；
#     - 只允许访问显式声明的授权测试主机；
#     - 重放后记录 HTTP 状态、业务码、响应哈希和脱敏预览；
#     - 对比重放前后的业务 JSON，判断数据是否真的发生变化。
#
#   安全边界：
#     - 必须用 --allow-host 声明授权测试主机，否则拒绝发送；
#     - 只允许 http/https；
#     - 默认不保存完整请求体 / 响应体，只保存脱敏预览；
#     - HTTP 200 不等于业务成功，业务变化请用 compare 子命令判断。
#
# 子命令：
#   preflight        只读校验请求文件、URL 与主机白名单
#   replay           发送一次请求并记录脱敏结果
#   compare          对比前后两份 JSON，判断业务数据是否变化
#   help             显示帮助
#
# 用法：
#   ./10-replay-runtime.py preflight --request-file request.json \
#     --allow-host test.example.com
#   ./10-replay-runtime.py replay --url https://test.example.com/api \
#     --allow-host test.example.com --expect-status 200
#   ./10-replay-runtime.py compare --before before.json --after after.json \
#     --path items --expect changed
#   ./10-replay-runtime.py --help
#
#   错误输入示例：
#     未声明 --allow-host，或 URL 主机不在白名单 → exit 2。
#
# 输出：
#   REPLAY_HTTP_STATUS、BUSINESS_CODE、RESPONSE_PREVIEW_SHA256、
#   CHANGED、【结论】、证据 JSON 路径。
#
# 请求文件格式（JSON）：
#   {
#     "method": "POST",
#     "url": "https://test.example.com/api/items",
#     "headers": {"Content-Type": "application/json"},
#     "body": "{\"title\":\"demo\"}",
#     "allow_hosts": ["test.example.com"]
#   }
#
# 参数：
#   --request-file <路径>  可选。格式：JSON 文件。示例：./request.json
#   --url <URL>            可选。示例：https://test.example.com/api
#   --method <方法>        可选，默认 GET。枚举：GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS。
#                          示例：--method POST
#   --header <Name: Value> 可选，可重复。示例：--header 'Content-Type: application/json'
#   --body <文本>          可选。示例：--body '{"title":"demo"}'
#   --body-file <路径>     可选。示例：--body-file ./body.json
#   --allow-host <主机>    可选，可重复；支持 *.example.com。
#                          示例：--allow-host test.example.com
#                          必须至少有一个来源（命令行或请求文件 allow_hosts）。
#   --timeout <秒>         可选，默认 15。示例：--timeout 30
#   --insecure             可选布尔开关；跳过 TLS 证书校验（仅授权测试环境）。
#   --expect-status <码>   可选。示例：--expect-status 200
#   --expect-business-code <码> 可选。示例：--expect-business-code 0
#   --before <JSON>        compare 必填。示例：./before.json
#   --after <JSON>         compare 必填。示例：./after.json
#   --path <a.b.0.c>       compare 可选。示例：--path data.items
#   --expect <changed|same> compare 可选。示例：--expect changed
#   --evidence-dir <目录>  可选，默认 evidence。示例：./evidence
#   --max-body <字节>      可选，默认 4096。示例：--max-body 8192
#   --label <标签>         可选，默认 dynamic-analysis。示例：--label lab-replay
#   --dry-run              可选布尔开关；只打印请求，不连接网络。
#   -h, --help             显示帮助。
#
# 依赖：
#   python3（标准库）。
#
# 退出码：
#   0 = 请求完成且期望满足 / 对比完成
#   1 = 网络错误、期望不匹配，或对比结果不符合 --expect
#   2 = 参数、依赖或文件错误
#
import argparse
import fnmatch
import hashlib
import json
import os
import re
import ssl
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SCHEMA = "app-safe/replay-runtime/v1"
SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(?:authorization|cookie|set-cookie|x-api-key|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|"
    r"secret|signature|sig|code|state)$"
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?i)^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|"
    r"x-auth-token|token|signature)$"
)


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact_value(value):
    if isinstance(value, dict):
        return {
            key: ("<REDACTED>" if SENSITIVE_KEY_RE.search(str(key))
                  else redact_value(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def redact_text_body(text):
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        text = re.sub(
            r"(?i)((?:proxy-)?authorization\s*[:=]\s*)[^,;]*",
            r"\1<REDACTED>", text,
        )
        text = re.sub(r"(?i)(\bBearer\s+)\S+", r"\1<REDACTED>", text)
        text = re.sub(
            r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)[^;]*",
            r"\1<REDACTED>", text,
        )
        text = re.sub(
            r"(?i)((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
            r"password|passwd|secret|signature|code|state)"
            r"\s*[\"']?\s*[:=]\s*[\"']?)[^\s\"'&,;}]+",
            r"\1<REDACTED>", text,
        )
        return text
    return json.dumps(redact_value(parsed), ensure_ascii=False)


def redact_headers(headers):
    result = {}
    for key, value in headers.items():
        if SENSITIVE_HEADER_RE.match(key):
            result[key] = "<REDACTED>"
        else:
            result[key] = value
    return result


def truncate(text, limit):
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def unique_path(directory, stem, suffix):
    candidate = os.path.join(directory, stem + suffix)
    index = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, "{}-{}{}".format(stem, index, suffix))
        index += 1
    return candidate


def write_json(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(temp, path)
    os.chmod(path, 0o600)


def parse_header(text):
    if ":" not in text:
        raise ValueError("请求头格式应为 Name: Value: {}".format(text))
    name, value = text.split(":", 1)
    name = name.strip()
    if not name:
        raise ValueError("请求头名称为空")
    return name, value.strip()


def load_request(args):
    request = {}
    if args.request_file:
        with open(args.request_file, "r", encoding="utf-8") as fh:
            request = json.load(fh)
        if not isinstance(request, dict):
            raise ValueError("请求文件顶层必须是 JSON 对象")

    method = (args.method or request.get("method") or "GET").upper()
    url = args.url or request.get("url") or ""

    headers = {}
    file_headers = request.get("headers") or {}
    if not isinstance(file_headers, dict):
        raise ValueError("请求文件 headers 必须是对象")
    headers.update({str(k): str(v) for k, v in file_headers.items()})
    for item in args.header or []:
        name, value = parse_header(item)
        headers[name] = value

    body = args.body
    if args.body_file:
        with open(args.body_file, "r", encoding="utf-8") as fh:
            body = fh.read()
    if body is None:
        body = request.get("body")
    if isinstance(body, (dict, list)):
        body = json.dumps(body, ensure_ascii=False)

    allow_hosts = list(args.allow_host or [])
    file_hosts = request.get("allow_hosts") or []
    if isinstance(file_hosts, list):
        allow_hosts += [str(item) for item in file_hosts]

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body or "",
        "allow_hosts": allow_hosts,
    }


def validate_request(request):
    url = request["url"]
    if not url:
        raise ValueError("缺少 URL（--url 或请求文件 url）")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("只允许 http/https URL: {}".format(url))
    if not parsed.hostname:
        raise ValueError("URL 缺少主机名: {}".format(url))

    allow_hosts = request["allow_hosts"]
    if not allow_hosts:
        raise ValueError(
            "必须用 --allow-host 声明授权测试主机（或请求文件 allow_hosts）"
        )
    host = parsed.hostname.lower()
    if not any(fnmatch.fnmatch(host, pattern.lower()) for pattern in allow_hosts):
        raise ValueError(
            "主机 {} 不在授权白名单中: {}".format(host, ", ".join(allow_hosts))
        )
    if request["method"] not in (
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    ):
        raise ValueError("不支持的 HTTP 方法: {}".format(request["method"]))


def extract_business_code(payload):
    if not isinstance(payload, dict):
        return ""
    for key in ("code", "errcode", "error_code", "ret", "status"):
        if key in payload and isinstance(payload[key], (str, int, float)):
            return str(payload[key])
    return ""


def cmd_preflight(args):
    request = load_request(args)
    validate_request(request)
    parsed = urlparse(request["url"])
    print("METHOD={}".format(request["method"]))
    print("URL_HOST={}".format(parsed.hostname))
    print("URL_SCHEME={}".format(parsed.scheme))
    print("ALLOW_HOSTS={}".format(", ".join(request["allow_hosts"])))
    print("HEADER_COUNT={}".format(len(request["headers"])))
    print("BODY_BYTES={}".format(len(request["body"].encode("utf-8"))))
    print("PREFLIGHT_PASSED=true")
    return 0


def cmd_replay(args):
    request = load_request(args)
    validate_request(request)

    parsed = urlparse(request["url"])
    port = ":{}".format(parsed.port) if parsed.port else ""
    body_bytes = request["body"].encode("utf-8") if request["body"] else None
    headers_redacted = redact_headers(request["headers"])

    print("============================================================")
    print("动态分析 10：受控请求重放")
    print("方法：{}".format(request["method"]))
    print("URL：{}://{}{}{}".format(
        parsed.scheme, parsed.hostname, port, parsed.path or "/"
    ))
    print("============================================================")
    print("REQUEST_HEADERS={}".format(json.dumps(headers_redacted, ensure_ascii=False)))
    print("REQUEST_BODY_BYTES={}".format(len(body_bytes or b"")))
    print("REQUEST_BODY_PREVIEW={}".format(
        truncate(redact_text_body(request["body"]), 512)[0]
    ))

    if args.dry_run:
        print("DRY_RUN=true")
        print("REPLAY_PASSED=false")
        return 0

    http_request = Request(
        request["url"],
        data=body_bytes,
        headers=request["headers"],
        method=request["method"],
    )

    context = None
    if args.insecure:
        context = ssl._create_unverified_context()
        print("[WARN] 已跳过 TLS 证书校验（--insecure，仅限授权测试环境）",
              file=sys.stderr)

    response = None
    error_text = ""
    print("[loading] 正在发送请求（超时 {} 秒）...".format(args.timeout),
          file=sys.stderr)
    try:
        response = urlopen(http_request, timeout=args.timeout, context=context)
    except HTTPError as exc:
        response = exc
    except (URLError, OSError, ValueError) as exc:
        error_text = str(exc)

    if response is None:
        print("[done] 请求失败", file=sys.stderr)
    else:
        print("[done] 收到响应", file=sys.stderr)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(args.evidence_dir, exist_ok=True)
    evidence_path = unique_path(
        args.evidence_dir, "10-replay-runtime-{}".format(timestamp), ".json"
    )

    if response is None:
        evidence = {
            "schema": SCHEMA,
            "captured_at": iso_now(),
            "label": args.label,
            "request": {
                "method": request["method"],
                "url_redacted": request["url"],
                "headers_redacted": headers_redacted,
                "body_redacted": redact_text_body(request["body"]),
                "body_sha256": sha256_bytes(body_bytes or b""),
            },
            "response": None,
            "error": error_text,
            "expect_status": args.expect_status,
            "expect_business_code": args.expect_business_code,
        }
        write_json(evidence_path, evidence)
        print("[FAIL] 请求失败: {}".format(error_text), file=sys.stderr)
        print("REPLAY_PASSED=false")
        print("EVIDENCE_JSON={}".format(evidence_path))
        return 1

    try:
        raw_body = response.read(args.max_body + 1)
        truncated = len(raw_body) > args.max_body
        raw_body = raw_body[:args.max_body]
    except OSError as exc:
        raw_body = b""
        truncated = False
        error_text = "读取响应失败: {}".format(exc)

    status = getattr(response, "status", None) or response.getcode()
    final_url = response.geturl()
    response_headers = dict(response.headers.items())
    response_headers_redacted = redact_headers(response_headers)

    charset = response.headers.get_content_charset() or "utf-8"
    body_text = raw_body.decode(charset, errors="replace")
    try:
        parsed_body = json.loads(body_text)
        is_json = True
    except (ValueError, TypeError):
        parsed_body = None
        is_json = False

    business_code = extract_business_code(parsed_body)
    body_preview = redact_text_body(body_text)
    body_preview, preview_truncated = truncate(body_preview, args.max_body)

    expect_status_match = (
        args.expect_status is None or status == args.expect_status
    )
    expect_code_match = (
        not args.expect_business_code
        or business_code == args.expect_business_code
    )
    replay_ok = 200 <= status < 300
    passed = expect_status_match and expect_code_match and not error_text

    evidence = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "label": args.label,
        "request": {
            "method": request["method"],
            "url_redacted": redact_text_body(request["url"]),
            "headers_redacted": headers_redacted,
            "body_redacted": redact_text_body(request["body"]),
            "body_sha256": sha256_bytes(body_bytes or b""),
        },
        "response": {
            "status": status,
            "final_url_redacted": redact_text_body(final_url),
            "headers_redacted": response_headers_redacted,
            "body_preview_redacted": body_preview,
            "body_preview_sha256": sha256_bytes(raw_body),
            "body_truncated": truncated or preview_truncated,
            "json": is_json,
            "business_code": business_code,
        },
        "expect_status": args.expect_status,
        "expect_business_code": args.expect_business_code,
        "expect_status_match": expect_status_match,
        "expect_business_code_match": expect_code_match,
        "replay_ok": replay_ok,
        "passed": passed,
        "error": error_text,
    }
    write_json(evidence_path, evidence)

    print("REPLAY_HTTP_STATUS={}".format(status))
    print("REPLAY_FINAL_URL={}".format(redact_text_body(final_url)))
    print("REPLAY_OK={}".format(str(replay_ok).lower()))
    print("RESPONSE_JSON={}".format(str(is_json).lower()))
    print("BUSINESS_CODE={}".format(business_code))
    print("RESPONSE_PREVIEW_SHA256={}".format(sha256_bytes(raw_body)))
    print("RESPONSE_BODY_PREVIEW={}".format(body_preview))
    print("RESPONSE_BODY_TRUNCATED={}".format(str(truncated).lower()))
    print("EXPECT_STATUS_MATCH={}".format(str(expect_status_match).lower()))
    print("EXPECT_BUSINESS_CODE_MATCH={}".format(str(expect_code_match).lower()))
    print("REPLAY_PASSED={}".format(str(passed).lower()))
    print("------------------------------------------------------------")
    print("【结论】")
    if passed:
        print("请求已完成且期望满足；HTTP 200 仍不等于业务成功，"
              "业务数据是否变化请用 compare 子命令判断。")
    else:
        print("请求完成但期望不匹配或发生错误；请检查状态码、业务码"
              "和错误信息，不要仅凭 HTTP 响应下结论。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))

    if error_text:
        print("[WARN] {}".format(error_text), file=sys.stderr)
    return 0 if passed else 1


def json_path_get(data, path):
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            index = int(part)
            current = current[index]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise KeyError(part)
    return current


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def cmd_compare(args):
    if not args.before or not args.after:
        print("[FAIL] compare 需要 --before 和 --after", file=sys.stderr)
        return 2

    try:
        with open(args.before, "r", encoding="utf-8") as fh:
            before = json.load(fh)
        with open(args.after, "r", encoding="utf-8") as fh:
            after = json.load(fh)
    except (OSError, ValueError) as exc:
        print("[FAIL] 无法读取 JSON: {}".format(exc), file=sys.stderr)
        return 2

    try:
        before_value = json_path_get(before, args.path) if args.path else before
        after_value = json_path_get(after, args.path) if args.path else after
    except (KeyError, IndexError, ValueError) as exc:
        print("[FAIL] JSON 路径不存在: {}".format(exc), file=sys.stderr)
        return 2

    before_canonical = canonical(before_value)
    after_canonical = canonical(after_value)
    changed = before_canonical != after_canonical

    expect_match = True
    if args.expect == "changed":
        expect_match = changed
    elif args.expect == "same":
        expect_match = not changed

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(args.evidence_dir, exist_ok=True)
    evidence_path = unique_path(
        args.evidence_dir, "10-replay-runtime-compare-{}".format(timestamp), ".json"
    )
    evidence = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "label": args.label,
        "before_file": args.before,
        "after_file": args.after,
        "path": args.path,
        "changed": changed,
        "expect": args.expect,
        "expect_match": expect_match,
        "before_sha256": sha256_file(args.before),
        "after_sha256": sha256_file(args.after),
        "before_value_redacted": truncate(
            redact_text_body(canonical(before_value)), 512
        )[0],
        "after_value_redacted": truncate(
            redact_text_body(canonical(after_value)), 512
        )[0],
    }
    write_json(evidence_path, evidence)

    print("============================================================")
    print("动态分析 10：业务结果对比")
    print("Before：{}".format(args.before))
    print("After ：{}".format(args.after))
    if args.path:
        print("Path  ：{}".format(args.path))
    print("============================================================")
    print("BEFORE_SHA256={}".format(evidence["before_sha256"]))
    print("AFTER_SHA256={}".format(evidence["after_sha256"]))
    print("CHANGED={}".format(str(changed).lower()))
    print("BEFORE_VALUE={}".format(evidence["before_value_redacted"]))
    print("AFTER_VALUE={}".format(evidence["after_value_redacted"]))
    if args.expect:
        print("EXPECT_MATCH={}".format(str(expect_match).lower()))
    print("------------------------------------------------------------")
    print("【结论】")
    if changed:
        print("前后业务数据存在差异；需人工确认差异是否由本次重放造成。")
    else:
        print("前后业务数据一致；可能没有产生业务效果，或对比路径不对。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))
    return 0 if expect_match else 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="受控重放 HTTP 请求并对比业务 JSON。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./10-replay-runtime.py preflight --request-file request.json "
            "--allow-host test.example.com\n"
            "  ./10-replay-runtime.py replay --url https://test.example.com/api "
            "--allow-host test.example.com --expect-status 200\n"
            "  ./10-replay-runtime.py compare --before before.json --after after.json "
            "--path items --expect changed\n"
            "\n退出码:\n"
            "  0 = 请求完成且期望满足 / 对比完成\n"
            "  1 = 网络错误或期望不匹配\n"
            "  2 = 参数、依赖或文件错误"
        ),
    )
    parser.add_argument("mode", choices=["preflight", "replay", "compare", "help"],
                        help="操作")
    parser.add_argument("--request-file", default="", help="JSON 请求文件")
    parser.add_argument("--url", default="", help="请求 URL，覆盖请求文件")
    parser.add_argument("--method", default="", help="HTTP 方法，默认 GET")
    parser.add_argument("--header", action="append", default=[],
                        help="请求头 Name: Value，可重复")
    parser.add_argument("--body", default=None, help="请求体文本")
    parser.add_argument("--body-file", default="", help="从文件读取请求体")
    parser.add_argument("--allow-host", action="append", default=[],
                        help="授权测试主机，可重复；支持 *.example.com")
    parser.add_argument("--timeout", type=int, default=15, help="超时秒数，默认 15")
    parser.add_argument("--insecure", action="store_true",
                        help="跳过 TLS 证书校验（仅授权测试环境）")
    parser.add_argument("--expect-status", type=int, default=None,
                        help="期望 HTTP 状态码")
    parser.add_argument("--expect-business-code", default="",
                        help="期望业务码")
    parser.add_argument("--before", default="", help="compare 的前置 JSON")
    parser.add_argument("--after", default="", help="compare 的后置 JSON")
    parser.add_argument("--path", default="", help="compare 的 JSON 路径，如 data.0.title")
    parser.add_argument("--expect", choices=["changed", "same"], default="",
                        help="compare 的期望结果")
    parser.add_argument("--evidence-dir", default="evidence", help="证据目录，默认 evidence")
    parser.add_argument("--max-body", type=int, default=4096,
                        help="响应预览上限，默认 4096 字节")
    parser.add_argument("--label", default="dynamic-analysis", help="证据标签")
    parser.add_argument("--dry-run", action="store_true", help="只打印请求，不发送")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.mode == "help":
        parse_args(["--help"])
        return 0
    if args.timeout <= 0 or args.max_body <= 0:
        print("[FAIL] --timeout 和 --max-body 必须是正整数", file=sys.stderr)
        return 2
    try:
        if args.mode == "preflight":
            return cmd_preflight(args)
        if args.mode == "replay":
            return cmd_replay(args)
        return cmd_compare(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("[FAIL] {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        sys.exit(2)
