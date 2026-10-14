#!/usr/bin/env python3
"""授权测试：对原包发送无效 OAuth 回调，临时阻断目标 App 的出站流量。"""

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PACKAGE = "com.sdmc.homewoo"
URI = "homewoo://calendar/google/complete?code=lab-invalid-code&state=lab-invalid-state"
RULE_COMMENT = "HOMEWOO_OAUTH_04_TEST"


def adb(*args, check=True):
    result = subprocess.run(["adb", *args], capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f"adb 命令失败 ({' '.join(args[:3])}): {result.stderr.strip()[:250]}")
    return result


def root(command, check=True):
    return adb("shell", "su", "-c", command, check=check)


def installed_apk_hash(apk):
    local_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    paths = adb("shell", "pm", "path", PACKAGE).stdout.strip().splitlines()
    if len(paths) != 1 or not paths[0].startswith("package:/data/app/"):
        raise RuntimeError("无法唯一定位已安装的原包；请先安装原包")
    device_path = paths[0].removeprefix("package:")
    device_hash = root(f"sha256sum '{device_path}'").stdout.split()[0]
    if device_hash != local_hash:
        raise RuntimeError("设备安装包与给定原包 SHA-256 不一致；不对其他 APK 执行测试")
    return local_hash, device_hash


def app_uid():
    dump = adb("shell", "dumpsys", "package", PACKAGE).stdout
    match = re.search(r"\buserId=(\d+)\b", dump)
    if not match:
        raise RuntimeError("无法取得目标 App UID")
    return match.group(1)


def rule(binary, uid):
    return f"{binary} -m owner --uid-owner {uid} -m comment --comment {RULE_COMMENT} -j REJECT"


def firewall_restore(uid):
    for binary in ("iptables", "ip6tables"):
        spec = rule(binary, uid)
        if root(spec.replace(binary, f"{binary} -C OUTPUT", 1), check=False).returncode == 0:
            result = root(spec.replace(binary, f"{binary} -D OUTPUT", 1), check=False)
            if result.returncode:
                raise RuntimeError(f"未能清理 {binary} 临时规则；请执行 restore-original")


def firewall_enable(uid):
    for binary in ("iptables", "ip6tables"):
        if root(f"command -v {binary}", check=False).returncode:
            raise RuntimeError(f"设备缺少 {binary}；拒绝在线发送测试回调")
        spec = rule(binary, uid)
        if root(spec.replace(binary, f"{binary} -C OUTPUT", 1), check=False).returncode == 0:
            raise RuntimeError(f"已存在 {binary} 测试规则；先运行 restore-original")
    try:
        for binary in ("iptables", "ip6tables"):
            spec = rule(binary, uid)
            root(spec.replace(binary, f"{binary} -I OUTPUT 1", 1))
    except Exception:
        firewall_restore(uid)
        raise


def main():
    if len(sys.argv) != 4:
        raise RuntimeError("用法: forge_invalid_callback.py preflight|forge-invalid|verify|restore-original APK EVIDENCE_DIR")
    action, apk_string, evidence_string = sys.argv[1:]
    apk = Path(apk_string).resolve()
    evidence = Path(evidence_string).resolve()
    if not apk.is_file():
        raise RuntimeError(f"APK 不存在: {apk}")
    adb("get-state")
    if "uid=0" not in root("id").stdout:
        raise RuntimeError("设备未确认 Root")
    local_hash, device_hash = installed_apk_hash(apk)
    uid = app_uid()
    if action == "preflight":
        print(f"DEVICE_APK_SHA256={device_hash}")
        print(f"APP_UID={uid}")
        print("PREFLIGHT_PASSED=true")
        return 0
    if action == "restore-original":
        firewall_restore(uid)
        print("RESTORE_SCOPE=移除本测试的目标 App 出站阻断规则；不清除账号数据")
        print("RESTORE_VERIFIED=true")
        return 0
    if action == "verify":
        files = sorted(evidence.glob("forged-invalid-*.json"))
        if not files:
            raise RuntimeError("没有现场证据；先执行 forge-invalid")
        record = json.loads(files[-1].read_text(encoding="utf-8"))
        print(f"EVIDENCE_FILE={files[-1]}")
        print(f"CALLBACK_DELIVERED={str(record['callback_delivered']).lower()}")
        print("OAUTH_BYPASS_PROVEN=false")
        print("说明：无效回调到达 Activity 不等于绑定成功；需对比服务端绑定状态。")
        return 0 if record["callback_delivered"] else 1
    if action != "forge-invalid":
        raise RuntimeError(f"未知操作: {action}")

    evidence.mkdir(parents=True, exist_ok=True)
    result = None
    firewall_enable(uid)
    try:
        command = (
            "am start -W -a android.intent.action.VIEW "
            "-c android.intent.category.BROWSABLE "
            f"-d '{URI}' -p {PACKAGE}"
        )
        result = adb("shell", command, check=False)
    finally:
        firewall_restore(uid)
    output = result.stdout + result.stderr
    status = re.search(r"^Status:\s*(\S+)", output, re.M)
    activity = re.search(r"^Activity:\s*(\S+)", output, re.M)
    uri_parameters_present = "code=lab-invalid-code" in output and "state=lab-invalid-state" in output
    delivered = result.returncode == 0 and uri_parameters_present and status is not None and status.group(1) == "ok" and activity is not None and PACKAGE in activity.group(1)
    record = {
        "timestamp": datetime.now().astimezone().isoformat(),
        "apk_sha256": local_hash,
        "device_apk_sha256": device_hash,
        "uri_scheme": "homewoo",
        "uri_host": "calendar",
        "uri_path": "/google/complete",
        "callback_values": "obviously invalid lab markers; not persisted",
        "app_network_blocked_during_delivery": True,
        "app_network_block_restored": True,
        "am_start_status": status.group(1) if status else "missing",
        "adb_exit_code": result.returncode,
        "uri_parameters_in_am_output": uri_parameters_present,
        "activity": activity.group(1) if activity else "missing",
        "callback_delivered": delivered,
        "oauth_bypass_proven": False,
        "business_binding_verified": False,
    }
    path = evidence / f"forged-invalid-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"EVIDENCE_FILE={path}")
    print(f"CALLBACK_DELIVERED={str(delivered).lower()}")
    print("OAUTH_BYPASS_PROVEN=false")
    return 0 if delivered else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        raise SystemExit(1)
