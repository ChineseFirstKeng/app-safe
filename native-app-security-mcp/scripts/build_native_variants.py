"""Compile stripped, fat and Extension carriers; never install or run targets."""
import json
import plistlib
import zipfile

from build_code_fixtures import build, run, PROJECT
from native_security.native_config import sdk_tool
from native_security.native_slices import slices


def build_variants():
    original = build()
    root = PROJECT / "runtime/native-variants"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    sdk_path = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"])
    clang = run(["/usr/bin/xcrun", "--find", "clang"])
    strip = run(["/usr/bin/xcrun", "--find", "strip"])
    lipo = run(["/usr/bin/xcrun", "--find", "lipo"])
    source = PROJECT / "fixtures/code/native/stripped.c"
    common = [clang, "-isysroot", sdk_path, "-O0", "-fno-inline"]
    arm64 = root / "StrippedApp.original"
    run([*common, "-target", "arm64-apple-ios15.0", "-DFIXTURE_EXECUTABLE", source, "-o", arm64])
    stripped = root / "StrippedApp"
    run([strip, "-o", stripped, arm64])
    arm64e = root / "FixtureApp.arm64e"
    run([*common, "-target", "arm64e-apple-ios15.0", PROJECT / "fixtures/code/ios/main.m",
         "-framework", "Foundation", "-o", arm64e])
    fat = root / "FatApp"
    run([lipo, "-create", PROJECT / "runtime/code-fixtures/ios/FixtureApp", arm64e, "-output", fat])
    extension = root / "FixtureExtension"
    run([*common, "-target", "arm64-apple-ios15.0", "-fapplication-extension",
         PROJECT / "fixtures/code/ios/Extension.m", "-framework", "Foundation", "-o", extension])
    sdk = sdk_tool("aapt2").parents[2]
    compiler = sorted((sdk / "ndk").glob("*/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"), reverse=True)[0]
    elf = root / "stripped.so"
    run([compiler, "-shared", "-fPIC", "-O0", "-fno-inline", "-Wl,-Bsymbolic", "-Wl,--strip-all", source, "-o", elf])
    apk = root / "stripped.apk"
    with zipfile.ZipFile(original["apk"]) as incoming, zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr("AndroidManifest.xml", incoming.read("AndroidManifest.xml"))
        out.write(elf, "lib/arm64-v8a/libstripped.so")
    ipa = root / "stripped.ipa"
    with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.stripped", "CFBundleExecutable": "StrippedApp"}))
        out.write(stripped, "Payload/Fixture.app/StrippedApp")
    multi = root / "fat-extension.ipa"
    with zipfile.ZipFile(multi, "w", compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.fat", "CFBundleExecutable": "FatApp"}))
        out.write(fat, "Payload/Fixture.app/FatApp")
        base = "Payload/Fixture.app/PlugIns/Fixture.appex/"
        out.writestr(base + "Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.extension", "CFBundleExecutable": "FixtureExtension",
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.share-services", "NSExtensionPrincipalClass": "FixtureExtension"}}))
        out.write(extension, base + "FixtureExtension")
    result = {"apk": str(apk), "ipa": str(ipa), "fat_extension_ipa": str(multi), "original": original,
              "fat_slices": slices(fat.read_bytes()), "executed": False, "installed": False,
              "installability_verified": False, "purpose": "static carrier coverage, not functional Extension validation"}
    (root / "build.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    print(json.dumps(build_variants(), indent=2))
