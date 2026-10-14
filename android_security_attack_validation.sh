#!/usr/bin/env bash
set -u

PKG="com.sdmc.homewoo"
SCHEME_URI="homewoo://calendar/google/complete?code=lab-invalid-code&state=lab-invalid-state"
ADB="adb"

if [ "$#" -ge 1 ]; then PKG="$1"; fi
if [ "$#" -ge 2 ]; then SCHEME_URI="$2"; fi

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

command -v "$ADB" >/dev/null 2>&1 || die "adb not found"
"$ADB" get-state >/dev/null 2>&1 || die "no Android device connected"

echo "== Device =="
"$ADB" devices -l
echo
echo "== Root =="
"$ADB" shell su -c id 2>&1 || true
echo
echo "== Package =="
"$ADB" shell dumpsys package "$PKG" 2>&1 | \
  rg -m 1 'versionCode=|versionName=|targetSdk=|primaryCpuAbi=' || true
"$ADB" shell pm path "$PKG"
echo

echo "== Check 1: debuggable =="
RUNAS_OUTPUT=$("$ADB" shell run-as "$PKG" id 2>&1 || true)
if echo "$RUNAS_OUTPUT" | rg -q 'not debuggable'; then
  echo "[PASS] run-as is rejected; package is not debuggable"
else
  echo "[FAIL] run-as result: $RUNAS_OUTPUT"
fi
echo

echo "== Check 2: backup flag =="
PACKAGE_DUMP=$("$ADB" shell dumpsys package "$PKG" 2>&1 || true)
if echo "$PACKAGE_DUMP" | rg -q 'ALLOW_BACKUP'; then
  echo "[WARN] ALLOW_BACKUP is present; inspect backup rules and sensitive files"
else
  echo "[PASS] ALLOW_BACKUP not shown in package flags"
fi
echo

echo "== Check 3: external OAuth/deep-link resolution =="
RESOLVE=$("$ADB" shell cmd package resolve-activity --brief \
  -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE \
  -d "$SCHEME_URI" 2>&1 || true)
echo "$RESOLVE"
if echo "$RESOLVE" | rg -q "$PKG/"; then
  echo "[WARN] external deep link resolves to $PKG; OAuth state/PKCE must be tested"
else
  echo "[PASS] URI did not resolve to target package"
fi
echo

echo "== Check 4: controlled deep-link launch =="
LAUNCH=$("$ADB" shell am start -W \
  -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE \
  -d "$SCHEME_URI" 2>&1 || true)
echo "$LAUNCH"
if echo "$LAUNCH" | rg -q "Activity: $PKG/"; then
  echo "[WARN] controlled invalid callback reached the app; this is not OAuth bypass proof"
else
  echo "[PASS] callback did not reach target Activity"
fi
echo

echo "== Check 5: exported/permission summary =="
"$ADB" shell dumpsys package "$PKG" 2>&1 | \
  sed -n '/Activity Resolver Table:/,/Key Set Manager:/p' | \
  rg 'Scheme:|Authority:|Path:|Activity|Receiver|Service|Provider|Permission' | head -160 || true
echo

echo "== Check 6: process debug ports =="
PID=$("$ADB" shell pidof "$PKG" 2>/dev/null | tr -d '\r')
if [ -n "$PID" ]; then
  PORTS=$("$ADB" shell su -c "cat /proc/$PID/net/tcp /proc/$PID/net/tcp6 2>/dev/null" | \
    rg ':1F90|:1F91|:D000|:D001|:D002' || true)
  if [ -n "$PORTS" ]; then
    echo "[WARN] possible debug-related listening port found:"
    echo "$PORTS"
  else
    echo "[PASS] no common Flutter debug port observed for process $PID"
  fi
else
  echo "[INFO] target process is not running"
fi
echo

echo "== Check 7: sensitive local storage inventory =="
"$ADB" shell su -c "find /data/user/0/$PKG -type f 2>/dev/null" | \
  rg 'shared_prefs|databases|files|cache|no_backup' | \
  sed -E 's#^#FILE #g' | head -200 || true
echo
echo "[INFO] file names only are printed; file contents are not dumped"
echo

echo "== Check 8: log keyword scan =="
LOGS=$("$ADB" logcat -d -b main -b system -b crash -v brief 2>/dev/null | \
  rg -i "com\\.sdmc\\.homewoo|authorization|access.?token|refresh.?token|password|secret" | \
  tail -80 || true)
if [ -n "$LOGS" ]; then
  echo "[WARN] matching log lines exist; manually inspect after redaction"
  echo "$LOGS"
else
  echo "[PASS] no matching log lines found in current buffers"
fi
echo

echo "== End =="
echo "This script is read-only except for launching the supplied test deep link."
echo "A warning is not proof of account takeover; it identifies the next validation step."
