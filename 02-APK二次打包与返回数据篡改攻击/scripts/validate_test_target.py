#!/usr/bin/env python3
"""Allow only localhost or RFC1918 HTTP(S) test endpoints."""

import ipaddress
import sys
from urllib.parse import urlparse


def main():
    if len(sys.argv) != 2:
        print("用法: validate_test_target.py <url>", file=sys.stderr)
        return 2
    value = sys.argv[1]
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        print("目标必须是无凭据的 http/https URL", file=sys.stderr)
        return 1
    if not parsed.hostname or not parsed.port:
        print("目标必须包含主机和端口", file=sys.stderr)
        return 1
    host = parsed.hostname.lower()
    if host == "localhost":
        return 0
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        print("目标主机必须是 localhost 或私有 IP", file=sys.stderr)
        return 1
    if not (address.is_private or address.is_loopback):
        print("目标主机不是本机或私有测试网络", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
