#!/usr/bin/env python3
"""在授权实验 APK 的 libapp.so 中替换接口基地址。仅用于隔离测试包。"""

import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=Path)
parser.add_argument("old_url")
parser.add_argument("new_url")
args = parser.parse_args()

raw = args.binary.read_bytes()
old = args.old_url.encode()
new = args.new_url.encode()
if old not in raw:
    raise SystemExit("old URL not found in binary")
if len(new) > len(old):
    raise SystemExit(f"new URL is too long: {len(new)} > {len(old)} bytes")
replacement = new + b"/" * (len(old) - len(new))
args.binary.write_bytes(raw.replace(old, replacement))
print(f"PATCHED={args.binary}")
print(f"OLD_LEN={len(old)} NEW_LEN={len(new)}")
