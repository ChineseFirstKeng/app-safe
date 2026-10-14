#!/usr/bin/env python3
"""Compare redacted before/after replay evidence for a test object."""

import json
import hashlib
import sys
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def main():
    if len(sys.argv) not in {4, 5}:
        print("用法: verify_replay_result.py {create|update|delete} before.json after.json [event_id]")
        return 2
    action, before_path, after_path = sys.argv[1:4]
    event_id = sys.argv[4] if len(sys.argv) == 5 else None
    before = load(before_path)
    after = load(after_path)
    before_events = {str(e.get("event_key")): e for e in before.get("events", [])}
    after_events = {str(e.get("event_key")): e for e in after.get("events", [])}
    if action == "create":
        if after.get("action") == "create":
            created_key = str(after.get("event_key"))
            passed = bool(after.get("event_key")) and created_key not in before_events
        else:
            created_keys = set(after_events) - set(before_events)
            passed = len(created_keys) == 1
            if event_id:
                passed = passed and digest(event_id) in created_keys
    elif not event_id:
        print("FAIL: update/delete 必须提供 event_id", file=sys.stderr)
        return 2
    elif action == "delete":
        key = digest(event_id)
        passed = key in before_events and key not in after_events
    elif action == "update":
        key = digest(event_id)
        passed = key in before_events and key in after_events and before_events[key] != after_events[key]
    else:
        print(f"FAIL: 不支持的操作 {action}", file=sys.stderr)
        return 2
    print(f"COMPARE_ACTION={action}")
    print(f"EVENT_ID={event_id or '<created>'}")
    print(f"BUSINESS_STATE_CHANGED={str(passed).lower()}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
