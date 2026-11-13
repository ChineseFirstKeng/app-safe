"""Operator-controlled engine paths and bounded execution, no target commands."""
import hashlib
import json
import os
import platform
import time
import tempfile
import shutil
from pathlib import Path

from .errors import AnalysisError
from .native_config import run_tool

SCRIPTS = Path(__file__).resolve().parent / "engine_scripts"


def tools_root():
    return Path(os.environ.get("NATIVE_SECURITY_TOOLS_DIR", str(Path(__file__).resolve().parents[2] / ".tools")))


def java_home():
    if value := os.environ.get("NATIVE_SECURITY_JAVA_HOME"):
        return Path(value)
    root = tools_root() / "jdk"
    bundled = root / "Contents/Home" if (root / "Contents/Home").is_dir() else root
    if (bundled / "bin/java").is_file():
        return bundled
    studio = Path("/Applications/Android Studio.app/Contents/jbr/Contents/Home")
    return studio if (studio / "bin/java").is_file() else bundled


def java():
    path = java_home() / "bin/java"
    if not path.is_file():
        raise AnalysisError("index_java_missing")
    return path


def environment(directory):
    env = dict(os.environ)
    env["JAVA_HOME"] = str(java_home())
    env["PATH"] = str(java_home() / "bin") + os.pathsep + env.get("PATH", "")
    private_home = directory / "engine-home"
    private_home.mkdir(mode=0o700, exist_ok=True)
    temporary = directory / "engine-tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    def prop(key, value):
        return '"-D' + key + '=' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'
    env["JAVA_TOOL_OPTIONS"] = prop("user.home", private_home) + " " + prop("java.io.tmpdir", temporary)
    env.pop("_JAVA_OPTIONS", None)
    env.pop("JDK_JAVA_OPTIONS", None)
    return env


def execute(arguments, directory, deadline, name="engine", limit=4 * 1024 * 1024):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_tool([str(x) for x in arguments], directory / (name + ".stdout"), directory / (name + ".stderr"),
             deadline, limit, env=environment(directory))


def build_jadx_indexer(deadline):
    compiler = java_home() / "bin/javac"
    libraries = tools_root() / "jadx/lib"
    if not compiler.is_file() or not libraries.is_dir():
        raise AnalysisError("jadx_indexer_dependencies_missing")
    source = SCRIPTS / "JadxIndex.java"
    manifest = tools_root() / "jadx/.installed.json"
    stamp = hashlib.sha256(source.read_bytes() + (manifest.read_bytes() if manifest.is_file() else b"unverified-install")).hexdigest()
    base = tools_root() / "indexer-classes"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = base / stamp
    import fcntl
    fd = os.open(base / "compile.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise AnalysisError("indexer_compile_lock_timeout")
                time.sleep(.05)
        if (output / "JadxIndex.class").is_file():
            return output
        staging = Path(tempfile.mkdtemp(dir=base, prefix="build-"))
        execute([compiler, "-J-Xmx256m", "--release", "17", "-cp", str(libraries / "*"), "-d", staging, source], staging, deadline, "compile")
        if not (staging / "JadxIndex.class").is_file():
            raise AnalysisError("jadx_indexer_compile_failed")
        os.rename(staging, output)
        return output
    finally:
        os.close(fd)


def jadx_index(input_file, directory, deadline):
    classes = build_jadx_indexer(deadline)
    output = directory / "index.json"
    cp = str(classes) + os.pathsep + str(tools_root() / "jadx/lib/*")
    execute([java(), "-Xmx768m", "-cp", cp, "JadxIndex", input_file, output], directory, deadline, "jadx")
    return output


def ghidra_index(input_file, directory, deadline):
    launcher = tools_root() / "ghidra/support/analyzeHeadless"
    if not launcher.is_file():
        raise AnalysisError("ghidra_indexer_missing")
    java()
    projects = directory / "projects"
    projects.mkdir(mode=0o700, exist_ok=True)
    output = directory / "index.json"
    remaining = max(1, deadline - time.monotonic())
    seconds = max(1, min(30, int(remaining / 3)))
    export_deadline = int((time.time() + remaining - 1) * 1000)
    execute([launcher, projects, "NativeIndex", "-import", input_file, "-scriptPath", SCRIPTS,
             "-postScript", "ExportNativeIndex.java", output, str(export_deadline), "-analysisTimeoutPerFile", str(seconds),
             "-max-cpu", "1"], directory, deadline, "ghidra")
    return output


def checked_index(path, schema):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise AnalysisError("index_output_missing_or_over_budget")
    os.chmod(path, 0o600)
    raw = path.read_bytes()
    try:
        result = json.loads(raw)
    except (ValueError, RecursionError):
        raise AnalysisError("invalid_index_output") from None
    if not isinstance(result, dict) or result.get("schema") != schema:
        raise AnalysisError("invalid_index_schema")
    return result, hashlib.sha256(raw).hexdigest()
