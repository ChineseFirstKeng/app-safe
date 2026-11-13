"""Actual AAPT2 positive/negative configuration verification, not DEX/code analysis."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

from native_security.artifacts import import_artifact
from native_security.jobs_store import JobStore, TERMINAL
from native_security.native_config import sdk_tool
from native_security.reporting import export_report
from native_security.scheduler import Scheduler
from native_security.storage import Store

project = Path(__file__).resolve().parents[1]
root = project / "runtime/android-manifest-verification"
root.mkdir(mode=0o700, parents=True, exist_ok=True)
tool = sdk_tool("aapt2")
if not tool:
    raise SystemExit("aapt2 missing; real configuration verification not performed")
frameworks = sorted((tool.parents[2] / "platforms").glob("*/android.jar"), reverse=True)
if not frameworks:
    raise SystemExit("Android platform framework missing")
store = Store(root / "data")
jobs = JobStore(store)
scheduler = Scheduler(store.root)
records = []
try:
    with patch.dict(os.environ, {"NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""}):
        for name, enabled in [("positive", True), ("negative", False)]:
            folder = root / name
            folder.mkdir(mode=0o700, exist_ok=True)
            manifest = folder / "AndroidManifest.xml"
            manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="example.native.fixture" android:versionCode="1" android:versionName="1.0">
                <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />
                <application android:label="Native configuration fixture" android:debuggable="%s"
                    android:usesCleartextTraffic="%s" android:allowBackup="false">
                    <activity android:name=".MainActivity" android:exported="%s">
                        <intent-filter><action android:name="android.intent.action.VIEW" />
                            <category android:name="android.intent.category.DEFAULT" />
                            <category android:name="android.intent.category.BROWSABLE" />
                            <data android:scheme="nativefixture" android:host="callback" />
                        </intent-filter>
                    </activity>
                </application></manifest>''' % (("true" if enabled else "false",) * 3))
            package = folder / "fixture.apk"
            subprocess.run([str(tool), "link", "--manifest", str(manifest), "-I", str(frameworks[0]),
                            "-o", str(package)], check=True, capture_output=True, timeout=30)
            artifact = import_artifact(store, str(package))
            job = scheduler.submit(artifact["artifact_id"], 30)
            until = time.monotonic() + 35
            while job["state"] not in TERMINAL and time.monotonic() < until:
                time.sleep(.05)
                job = jobs.get(job["analysis_id"])
            findings = jobs.results(job["analysis_id"], "finding")["items"]
            expected = {"AND-CONFIG-001", "AND-CONFIG-002"} if enabled else set()
            if job["coverage"]["configuration"] != "complete_within_explicit_manifest_checks" or {r["rule_id"] for r in findings} != expected:
                raise AssertionError("actual AAPT2 check did not match the compiled fixture")
            report = export_report(store, jobs, job["analysis_id"])
            records.append({"fixture": name, "artifact_sha256": artifact["sha256"],
                            "analysis_id": job["analysis_id"], "state": job["state"], "coverage": job["coverage"],
                            "matched_rules": sorted(expected), "report_path": report["path"]})
finally:
    scheduler.close()
summary = {"passed": True, "scope": "real_aapt2_compiled_manifest_positive_negative",
           "dex_or_native_function_analysis": False, "mobsf_executed": False, "records": records}
path = root / "summary.json"
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as output:
    json.dump(summary, output, ensure_ascii=False, indent=2)
print(json.dumps(summary, ensure_ascii=False, indent=2))
