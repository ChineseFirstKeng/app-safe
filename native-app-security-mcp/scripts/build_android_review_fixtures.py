"""Build explicit-export, disabled and constant-argument review controls."""
import json
import zipfile

from build_code_fixtures import PROJECT, run
from native_security.engine_runtime import java, java_home
from native_security.native_config import sdk_tool


def build():
    root = PROJECT / "runtime/android-review-fixtures"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    aapt = sdk_tool("aapt2")
    framework = sorted((aapt.parents[2] / "platforms").glob("*/android.jar"), reverse=True)[0]
    classes, dex = root / "classes", root / "dex"
    classes.mkdir(exist_ok=True); dex.mkdir(exist_ok=True)
    run([java_home() / "bin/javac", "--release", "8", "-cp", framework, "-d", classes,
         *sorted((PROJECT / "fixtures/review/android").glob("*.java"))])
    run([java(), "-cp", aapt.parent / "lib/d8.jar", "com.android.tools.r8.D8", "--min-api", "24",
         "--lib", framework, "--output", dex, *sorted(classes.rglob("*.class"))])
    result = {}
    for name, component, exported, enabled in [("external", "Entry", True, True), ("private", "Entry", False, True),
            ("disabled", "Entry", True, False), ("constant", "ConstantEntry", True, True),
            ("overwrite", "OverwriteEntry", True, True), ("mixed", "MixedEntry", True, True),
            ("merge", "MergeEntry", True, True), ("unknown", "UnknownEntry", True, True),
            ("non_exact", "NonExactEntry", True, True), ("internal_intent", "InternalIntentEntry", True, True)]:
        manifest = root / (name + ".xml")
        manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.review">
            <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
            <application android:label="Entry review fixture"><activity android:name=".{component}"
            android:exported="{str(exported).lower()}" android:enabled="{str(enabled).lower()}"/></application></manifest>''')
        apk = root / (name + ".apk")
        run([aapt, "link", "--manifest", manifest, "-I", framework, "-o", apk])
        with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(dex / "classes.dex", "classes.dex")
        result[name] = str(apk)
    (root / "build.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    print(json.dumps(build(), indent=2))
