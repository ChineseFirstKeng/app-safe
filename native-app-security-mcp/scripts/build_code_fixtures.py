"""Compile source-owned APK/IPA fixtures without executing or installing them."""
import json
import plistlib
import subprocess
import zipfile
from pathlib import Path

from native_security.engine_runtime import java, java_home
from native_security.native_config import sdk_tool

PROJECT = Path(__file__).resolve().parents[1]


def run(args, timeout=90):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[-5000:])
    return result.stdout.decode().strip()


def build():
    root = PROJECT / "runtime/code-fixtures"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    aapt = sdk_tool("aapt2")
    if not aapt:
        raise RuntimeError("AAPT2 is required for compiled fixtures")
    sdk = aapt.parents[2]
    framework = sorted((sdk / "platforms").glob("*/android.jar"), reverse=True)[0]
    android = root / "android"
    classes, dex = android / "classes", android / "dex"
    classes.mkdir(parents=True, exist_ok=True); dex.mkdir(exist_ok=True)
    source = PROJECT / "fixtures/code/android/Entry.java"
    run([java_home() / "bin/javac", "--release", "8", "-cp", framework, "-d", classes, source])
    run([java(), "-cp", aapt.parent / "lib/d8.jar", "com.android.tools.r8.D8", "--min-api", "24",
         "--lib", framework, "--output", dex, *classes.rglob("*.class")])
    manifest = android / "AndroidManifest.xml"
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.nativefixture">
        <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
        <application android:label="Native code fixture"><activity android:name=".Entry" android:exported="false"/></application>
        </manifest>''')
    apk = android / "fixture.apk"
    run([aapt, "link", "--manifest", manifest, "-I", framework, "-o", apk])
    compilers = sorted((sdk / "ndk").glob("*/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"), reverse=True)
    if not compilers:
        raise RuntimeError("Android NDK arm64 compiler is required for ELF fixture")
    elf = android / "libfixture.so"
    run([compilers[0], "-shared", "-fPIC", "-O0", "-fno-inline", "-Wl,-Bsymbolic",
         PROJECT / "fixtures/code/android/native.c", "-o", elf])
    with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex / "classes.dex", "classes.dex")
        archive.write(elf, "lib/arm64-v8a/libfixture.so")
    ios = root / "ios"
    ios.mkdir(exist_ok=True)
    sdk_path = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"])
    clang = run(["/usr/bin/xcrun", "--find", "clang"])
    swift = run(["/usr/bin/xcrun", "--find", "swiftc"])
    executable = ios / "FixtureApp"
    run([clang, "-target", "arm64-apple-ios15.0", "-isysroot", sdk_path, "-O0", "-fno-inline",
         PROJECT / "fixtures/code/ios/main.m", "-framework", "Foundation", "-o", executable])
    library = ios / "FixtureSwift"
    run([swift, "-target", "arm64-apple-ios15.0", "-sdk", sdk_path, "-Onone", "-emit-library",
         "-module-name", "FixtureSwift", PROJECT / "fixtures/code/ios/FixtureSwift.swift", "-o", library])
    ipa = ios / "fixture.ipa"
    with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.nativefixture.ios", "CFBundleExecutable": "FixtureApp"}))
        archive.write(executable, "Payload/Fixture.app/FixtureApp")
        archive.writestr("Payload/Fixture.app/Frameworks/FixtureSwift.framework/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.fixture.swift", "CFBundleExecutable": "FixtureSwift"}))
        archive.write(library, "Payload/Fixture.app/Frameworks/FixtureSwift.framework/FixtureSwift")
    result = {"apk": str(apk), "ipa": str(ipa), "executed": False,
              "installed": False, "signed_for_distribution": False,
              "source": "fixtures/code", "purpose": "compiled static indexing and reference ground truth"}
    (root / "build.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    print(json.dumps(build(), indent=2))
