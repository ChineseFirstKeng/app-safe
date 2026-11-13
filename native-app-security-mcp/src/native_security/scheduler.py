"""One kernel-locked controller per data directory; kill only owned Popen groups."""
import os
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

from .errors import AnalysisError
from .jobs_store import JobStore, TERMINAL
from .storage import Store


class Scheduler:
    def __init__(self, root, concurrency=2):
        if type(concurrency) is not int or not 1 <= concurrency <= 4:
            raise AnalysisError("invalid_scheduler_capacity")
        self.root = root
        self.concurrency = concurrency
        self.owner = uuid.uuid4().hex
        self._mutex = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._lock_fd = None
        self._active = {}
        self.jobs = None
        self._fault = False

    def start(self):
        with self._mutex:
            if self._thread:
                if self._fault or not self._thread.is_alive():
                    raise AnalysisError("analysis_scheduler_unavailable")
                return
            try:
                import fcntl
            except ImportError:
                raise AnalysisError("scheduler_platform_unsupported") from None
            store = Store(self.root)
            fd = os.open(store.root / "scheduler.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise AnalysisError("unsafe_scheduler_lock")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, AnalysisError):
                os.close(fd)
                raise AnalysisError("analysis_controller_busy") from None
            try:
                self.jobs = JobStore(store)
                self.jobs.recover()
            except BaseException:
                os.close(fd)
                raise
            self._lock_fd = fd
            self._stop.clear()
            self._fault = False
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def submit(self, artifact_id, wall_seconds=600):
        self.start()
        with self._mutex:
            return self.jobs.create(artifact_id, wall_seconds)

    @staticmethod
    def _kill(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)

    def _loop(self):
        try:
            while not self._stop.wait(.05):
                with self._mutex:
                    for analysis_id, (process, started, budget) in list(self._active.items()):
                        if process.poll() is not None:
                            process.wait()
                            self.jobs.transition(analysis_id, "failed", "worker_exited_without_result",
                                                 {"running"}, owner=self.owner)
                            del self._active[analysis_id]
                        elif time.monotonic() - started >= budget:
                            self.jobs.transition(analysis_id, "timed_out", "analysis_wall_budget_exceeded",
                                                 {"running"}, owner=self.owner)
                            self._kill(process)
                            del self._active[analysis_id]
                    while len(self._active) < self.concurrency and not self._stop.is_set():
                        record = self.jobs.claim(self.owner)
                        if record is None:
                            break
                        analysis_id = record["analysis_id"]
                        env = {k: v for k, v in os.environ.items() if k in {
                            "PATH", "LANG", "LC_ALL", "TMPDIR", "ANDROID_HOME", "ANDROID_SDK_ROOT",
                            "NATIVE_SECURITY_MOBSF_URL", "NATIVE_SECURITY_MOBSF_API_KEY"}}
                        for key in ("NATIVE_SECURITY_TOOLS_DIR", "NATIVE_SECURITY_JAVA_HOME", "NATIVE_SECURITY_NATIVE_ENGINE", "NATIVE_SECURITY_OBJDUMP"):
                            if key in os.environ:
                                env[key] = os.environ[key]
                        # HOME is used for documented default SDK discovery, never changed.
                        env["HOME"] = os.path.expanduser("~")
                        env["PYTHONNOUSERSITE"] = "1"
                        try:
                            process = subprocess.Popen([sys.executable, "-m", "native_security.worker",
                                "--data-dir", str(self.jobs.store.root), "--analysis-id", analysis_id,
                                "--owner", self.owner, "--parent-pid", str(os.getpid())],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=env, close_fds=True, start_new_session=True)
                        except OSError:
                            self.jobs.transition(analysis_id, "failed", "worker_spawn_failed", {"running"}, owner=self.owner)
                            continue
                        self._active[analysis_id] = (process, time.monotonic(), record["wall_seconds"])
        except Exception:
            # Leave a visible interrupted state instead of an indefinitely running record.
            with self._mutex:
                self._fault = True
                self._abort_owned("scheduler_internal_error")

    def cancel(self, analysis_id):
        self.start()
        with self._mutex:
            record = self.jobs.get(analysis_id)
            if record["state"] in TERMINAL:
                return record
            if record["state"] == "queued":
                return self.jobs.transition(analysis_id, "cancelled", "cancelled_before_start", {"queued"})
            record = self.jobs.transition(analysis_id, "cancelling", "cancellation_requested", {"running"}, owner=self.owner)
            handle = self._active.pop(analysis_id, None)
            if handle:
                self._kill(handle[0])
            return self.jobs.transition(analysis_id, "cancelled", "local_worker_stopped_remote_state_unknown",
                                        {"cancelling"}, owner=self.owner)

    def _abort_owned(self, reason):
        for analysis_id, (process, _, _) in list(self._active.items()):
            self.jobs.transition(analysis_id, "interrupted", reason, {"running", "cancelling"}, owner=self.owner)
            self._kill(process)
        self._active.clear()

    def close(self):
        self._stop.set()
        thread = self._thread
        if thread:
            thread.join(timeout=10)
        with self._mutex:
            if self.jobs:
                self._abort_owned("controller_shutdown")
            if self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None
            self._thread = None
