import os
import plistlib
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from native_security.artifacts import import_artifact
from native_security.jobs_store import JobStore, TERMINAL
from native_security.scheduler import Scheduler
from native_security.storage import Store


class EngineLifecycleTests(unittest.TestCase):
    def test_normal_completion_stops_an_owned_engine_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pidfile = root / "helper.pid"
            tool = root / "controlled-objdump"
            tool.write_text(f'''#!{sys.executable}
import pathlib, subprocess, sys
if '--version' in sys.argv:
    helper = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pathlib.Path({str(pidfile)!r}).write_text(str(helper.pid))
    print('controlled LLVM fixture')
elif '--syms' in sys.argv:
    print('00000010 g F .text 00000004 cleanup_fixture')
else:
    print('00000010 <cleanup_fixture>:\\n10: ret')
''')
            tool.chmod(0o700)
            package = root / "fixture.ipa"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Payload/App.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.cleanup"}))
                archive.writestr("Payload/App.app/App", struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
            store = Store(root / "data")
            artifact = import_artifact(store, str(package))
            jobs, scheduler = JobStore(store), Scheduler(store.root)
            try:
                with patch.dict(os.environ, {"NATIVE_SECURITY_NATIVE_ENGINE": "llvm", "NATIVE_SECURITY_OBJDUMP": str(tool),
                        "NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""}):
                    aid = scheduler.submit(artifact["artifact_id"], 15)["analysis_id"]
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        record = jobs.get(aid)
                        if record["state"] in TERMINAL:
                            break
                        time.sleep(.03)
                    self.assertEqual("partial", record["state"])
                    self.assertTrue(pidfile.exists())
                    pid = int(pidfile.read_text())
                    deadline = time.monotonic() + 3
                    state = ""
                    while time.monotonic() < deadline:
                        state = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "state="], capture_output=True, text=True).stdout.strip()
                        if not state or state.startswith("Z"):
                            break
                        time.sleep(.03)
                    self.assertTrue(not state or state.startswith("Z"), "owned engine helper outlived the completed worker")
            finally:
                scheduler.close()
                if pidfile.exists():
                    pid = int(pidfile.read_text())
                    command = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout.strip()
                    if command == sys.executable + " -c import time; time.sleep(30)":
                        try:os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:pass
