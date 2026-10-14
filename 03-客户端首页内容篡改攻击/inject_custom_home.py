#!/usr/bin/env python3
"""向解包后的 Homewoo APK 注入登录成功后的自定义 Activity 跳转。"""

from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest = root / "AndroidManifest.xml"
activity = '        <activity android:name="com.sdmc.homewoo.CustomHomeActivity" android:exported="false" android:theme="@style/CustomHomeTheme" />\n'
text = manifest.read_text()
if "com.sdmc.homewoo.CustomHomeActivity" not in text:
    text = text.replace("    </application>", activity + "    </application>")
manifest.write_text(text)

styles = root / "res" / "values" / "custom_home_styles.xml"
styles.write_text('''<resources>\n    <style name="CustomHomeTheme" parent="android:style/Theme.Material.Light.NoActionBar">\n        <item name="android:windowActionModeOverlay">true</item>\n        <item name="android:windowNoTitle">true</item>\n        <item name="android:windowDisablePreview">true</item>\n        <item name="android:windowAnimationStyle">@null</item>\n    </style>\n</resources>\n''')

smali = root / "smali" / "com" / "sdmc" / "homewoo" / "MainActivity.smali"
body = smali.read_text()
if "RedirectWatcher;->start" in body:
    print("ALREADY_PATCHED")
    raise SystemExit(0)

needle = ".method public final m()Ljava/lang/String;\n    .locals 2"
replacement = needle + "\n\n    invoke-static {p0}, Lcom/sdmc/homewoo/RedirectWatcher;->start(Landroid/app/Activity;)V"
if needle not in body:
    raise SystemExit("MainActivity route method not found")
smali.write_text(body.replace(needle, replacement, 1))
print("PATCHED_MANIFEST_AND_MAIN_ACTIVITY")
