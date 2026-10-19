#!/usr/bin/env bash
#
# 06-manifest-audit.sh —— 通用静态分析：Manifest / 组件 / 深链审计
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用框架或样本。
#
# 用途：
#   读取 APK 里的 AndroidManifest.xml（二进制 XML），回答：
#     - 包名、版本、minSdk、targetSdk 是什么？
#     - 申请了哪些权限？
#     - 哪些组件是 exported=true？是否有 permission 保护？
#     - 哪些组件没有显式写 android:exported？
#     - 有哪些 deeplink（scheme/host/path）？是否 autoVerify？
#     - debuggable / allowBackup / usesCleartextTraffic /
#       networkSecurityConfig / dataExtractionRules 等安全开关是什么状态？
#
#   注意：
#     exported=true 本身不等于漏洞。需要结合 permission、intent-filter、
#     组件类型和业务逻辑判断。本脚本只做结构化审计，不执行代码。
#
# 参数：
#   <APK>          必填
#                  格式：存在且可读的 APK 文件路径；ZIP 根目录必须包含 AndroidManifest.xml
#                  示例：./app.apk
#                  说明：AAB/APKS/IPA/JAR/普通 ZIP 会被识别并提示不适用，exit 2
#   --all          可选
#                  格式：布尔开关，不带值；可放在 <APK> 前后
#                  默认：关闭（只输出已导出/未声明 exported 的组件）
#                  示例：--all
#                  说明：输出全部组件
#
# 依赖：
#   unzip，以及 aapt 或 aapt2（Android SDK Build-Tools）。
#   缺少时明确提示安装方式并退出，不会静默跳过。
#
# 用法：
#   ./06-manifest-audit.sh <APK>
#   ./06-manifest-audit.sh <APK> --all
#   ./06-manifest-audit.sh --all <APK>
#   ./06-manifest-audit.sh --help
#
#   错误输入示例：
#     ./06-manifest-audit.sh app.ipa
#       → 识别为 iOS IPA，提示不适用，exit 2
#     ./06-manifest-audit.sh missing.apk
#       → 文件不存在，exit 2
#
# 输出：
#   包名/版本/SDK、权限、安全开关、已导出组件、未声明 exported 组件、
#   --all 时的全部组件、深链、【结论】。
#   不修改输入；临时文件放在 mktemp 目录，退出时删除。
#
# 退出码：
#   0 = 完成分析，未发现需要优先关注的 Manifest 风险
#   1 = 发现导出组件无权限保护、debuggable=true、明文流量等风险信号
#   2 = 参数/依赖/输入错误（包括输入不是 APK）
#
set -euo pipefail
export LC_ALL=C

SHOW_ALL=false
TARGET=""

usage() {
  cat <<'EOF'
用法:
  ./06-manifest-audit.sh <APK>
  ./06-manifest-audit.sh <APK> --all
  ./06-manifest-audit.sh --all <APK>
  ./06-manifest-audit.sh --help

参数:
  <APK>   必填。格式: 存在且可读的 APK 文件路径。示例: ./app.apk
  --all   可选。布尔开关。默认: 关闭（只输出已导出/未声明 exported 的组件）。示例: --all

输出:
  包信息、权限、安全开关、导出/未声明组件、深链、【结论】。

退出码:
  0 = 完成分析，未发现需要优先关注的风险
  1 = 发现风险信号
  2 = 参数/依赖/输入错误（包括输入不是 APK）
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      SHOW_ALL=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "[FAIL] 未知参数: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$TARGET" ]]; then
        echo "[FAIL] 只能指定一个 APK。" >&2
        usage >&2
        exit 2
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[FAIL] 缺少必填参数 <APK>。" >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] 文件不存在: $TARGET" >&2
  exit 2
fi

need_tool() {
  local tool="$1"
  local hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[FAIL] 缺少工具: $tool" >&2
    echo "       安装提示: $hint" >&2
    exit 2
  fi
}

need_tool unzip "macOS 通常自带；Linux: sudo apt install unzip / sudo dnf install unzip"

# 优先 PATH；否则在常见 Android SDK 目录中查找 Build-Tools
find_android_tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi

  local roots=()
  [[ -n "${ANDROID_HOME:-}" ]] && roots+=("$ANDROID_HOME")
  [[ -n "${ANDROID_SDK_ROOT:-}" ]] && roots+=("$ANDROID_SDK_ROOT")
  roots+=("$HOME/Library/Android/sdk" "$HOME/Android/Sdk")

  local root ver candidate
  for root in "${roots[@]}"; do
    [[ -d "$root/build-tools" ]] || continue
    while IFS= read -r ver; do
      candidate="$root/build-tools/$ver/$name"
      if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return 0
      fi
    done < <(ls -1 "$root/build-tools" 2>/dev/null \
      | sort -t. -k1,1nr -k2,2nr -k3,3nr)
  done
  return 1
}

AAPT="$(find_android_tool aapt || true)"
AAPT2="$(find_android_tool aapt2 || true)"

if [[ -z "$AAPT" && -z "$AAPT2" ]]; then
  echo "[FAIL] 找不到 aapt 或 aapt2。" >&2
  echo "       AndroidManifest.xml 是二进制 XML，需要 Build-Tools 解析。" >&2
  echo "       安装方式：" >&2
  echo "         1) Android Studio → SDK Manager → SDK Tools → Android SDK Build-Tools" >&2
  echo "         2) 或命令行：sdkmanager \"build-tools;34.0.0\"" >&2
  echo "         3) 安装后设置 ANDROID_HOME / ANDROID_SDK_ROOT，或把 build-tools/<版本> 加入 PATH" >&2
  exit 2
fi

# 调试用：PREFER_AAPT2=1 可强制走 aapt2 解析路径。
if [[ "${PREFER_AAPT2:-0}" == "1" && -n "$AAPT2" ]]; then
  AAPT=""
fi

# ---------- 1. 预检：确认是 APK ----------
ENTRIES="$(unzip -Z1 "$TARGET" 2>/dev/null || true)"
if ! grep -qx 'AndroidManifest.xml' <<<"$ENTRIES"; then
  echo "============================================================"
  echo "静态分析 06：Manifest / 组件 / 深链审计"
  echo "目标：$TARGET"
  echo "============================================================"
  echo "【结论】"
  if grep -qx 'BundleConfig.pb' <<<"$ENTRIES" || grep -q '^base/manifest/AndroidManifest\.xml$' <<<"$ENTRIES"; then
    echo "这是 AAB，不是可直接分析的 APK。请先用 bundletool 生成 APK。"
  elif grep -qx 'toc.pb' <<<"$ENTRIES"; then
    echo "这是 APKS，请先解出 base.apk / split APK 后再分析。"
  elif grep -qE '^Payload/[^/]+\.app/Info\.plist$' <<<"$ENTRIES"; then
    echo "这是 iOS IPA，AndroidManifest 审计不适用。"
  else
    echo "这不是 APK：ZIP 根目录没有 AndroidManifest.xml。"
  fi
  exit 2
fi

# ---------- 2. 准备临时目录 ----------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/manifest-audit.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
TREE_RAW="$TMP_DIR/manifest.raw.txt"
TREE="$TMP_DIR/manifest.txt"
COMP_FILE="$TMP_DIR/components.tsv"

# ---------- 3. 获取 badging 与 Manifest 树 ----------
echo "[loading] 正在解析 AndroidManifest.xml（aapt/aapt2 dump，大包可能需要几秒钟）..."
BADGING=""
if [[ -n "$AAPT" ]]; then
  BADGING="$("$AAPT" dump badging "$TARGET" 2>/dev/null || true)"
  "$AAPT" dump xmltree "$TARGET" AndroidManifest.xml > "$TREE_RAW" 2>/dev/null || true
else
  BADGING="$("$AAPT2" dump badging "$TARGET" 2>/dev/null || true)"
  "$AAPT2" dump xmltree --file AndroidManifest.xml "$TARGET" > "$TREE_RAW" 2>/dev/null || true
fi

if [[ ! -s "$TREE_RAW" ]]; then
  echo "[done] Manifest 解析结束：未得到有效结果"
  echo "[FAIL] 无法解析 AndroidManifest.xml。" >&2
  echo "       请确认 APK 未损坏，且 aapt/aapt2 版本可用。" >&2
  exit 2
fi
echo "[done] Manifest 解析完成"

# aapt2 的属性名是完整 URI，统一成 android:xxx，便于后续解析。
sed -E 's#A: http://schemas\.android\.com/apk/res/android:#A: android:#g' \
  "$TREE_RAW" > "$TREE"

# ---------- 4. 包信息 ----------
PACKAGE_NAME="$(sed -n "s/^package: name='\([^']*\)'.*/\1/p" <<<"$BADGING" || true)"
VERSION_CODE="$(sed -n "s/^package:.*versionCode='\([^']*\)'.*/\1/p" <<<"$BADGING" || true)"
VERSION_NAME="$(sed -n "s/^package:.*versionName='\([^']*\)'.*/\1/p" <<<"$BADGING" || true)"
MIN_SDK="$(sed -n "s/^sdkVersion:'\([^']*\)'.*/\1/p" <<<"$BADGING" || true)"
TARGET_SDK="$(sed -n "s/^targetSdkVersion:'\([^']*\)'.*/\1/p" <<<"$BADGING" || true)"
LAUNCHABLE="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<<"$BADGING" || true)"

# badging 不可用时，从 Manifest 树兜底取包名
if [[ -z "$PACKAGE_NAME" ]]; then
  PACKAGE_NAME="$(awk '
    /A: package="/ {
      if (match($0, /package="[^"]*"/)) {
        s = substr($0, RSTART + 9, RLENGTH - 10)
        print s
        exit
      }
    }' "$TREE" || true)"
fi

# ---------- 5. 权限 ----------
PERMISSIONS=""
if [[ -n "$BADGING" ]]; then
  PERMISSIONS="$(grep "^uses-permission: name=" <<<"$BADGING" \
    | sed -E "s/^uses-permission: name='([^']+)'.*/\1/" \
    | sort -u || true)"
fi
if [[ -z "$PERMISSIONS" ]]; then
  PERMISSIONS="$(awk '
    /E: uses-permission/ { want = 1; next }
    want && /A: android:name\(/ {
      if (match($0, /"[^"]+"/)) print substr($0, RSTART + 1, RLENGTH - 2)
      want = 0
    }' "$TREE" | sort -u || true)"
fi
PERMISSION_COUNT="$(printf '%s\n' "$PERMISSIONS" | grep -c . || true)"

# ---------- 6. 解析组件与深链 ----------
# 输出：
#   COMP|tag|name|exported|permission|authorities|grant|actions|categories
#   DEEPLINK|name|uri|autoVerify
#   用 | 而不是 TAB 作为分隔符：bash 的 read 会把连续的 TAB 当成一个分隔符，
#   导致空字段（例如没有 permission）后面的字段整体错位。
awk '
function leading_spaces(s,   n) {
  n = 0
  while (substr(s, n + 1, 1) == " ") n++
  return n
}
function first_quoted(s) {
  if (match(s, /"[^"]*"/)) return substr(s, RSTART + 1, RLENGTH - 2)
  return ""
}
function bool_value(s) {
  if (s ~ /=true([^A-Za-z]|$)/ || s ~ /0xffffffff/) return "true"
  if (s ~ /=false([^A-Za-z]|$)/ || s ~ /0x0([^0-9a-fA-F]|$)/) return "false"
  return "?"
}
function flush_deeplink() {
  if (scheme_val == "" || name == "") {
    scheme_val = ""; host_val = ""; host_seen = 0; path_val = ""; auto_verify = ""
    return
  }
  uri = scheme_val
  if (host_seen) uri = uri "://" host_val
  uri = uri path_val
  print "DEEPLINK|" name "|" uri "|" auto_verify
  scheme_val = ""; host_val = ""; host_seen = 0; path_val = ""; auto_verify = ""
}
function finalize() {
  if (!in_comp) return
  flush_deeplink()
  if (name == "") name = "(未命名)"
  print "COMP|" ctag "|" name "|" exported "|" permission "|" authorities "|" grant "|" actions "|" categories
  in_comp = 0
}
{
  line = $0
  ind = leading_spaces(line)

  if (line ~ /^[[:space:]]*E: /) {
    e = line
    sub(/^[[:space:]]*E: /, "", e)
    sub(/[[:space:]].*$/, "", e)

    if (e == "activity" || e == "activity-alias" || e == "service" || e == "receiver" || e == "provider") {
      finalize()
      in_comp = 1
      comp_indent = ind
      ctag = e
      name = ""; exported = "未声明"; permission = ""; authorities = ""; grant = "未声明"
      actions = ""; categories = ""
      scheme_val = ""; host_val = ""; host_seen = 0; path_val = ""; auto_verify = ""
      last_elem = e
    } else if (in_comp && ind <= comp_indent) {
      finalize()
      last_elem = e
    } else {
      if (e == "data" && in_comp) flush_deeplink()
      last_elem = e
    }
    next
  }

  if (!in_comp) next

  if (line ~ /^[[:space:]]*A: /) {
    attr = line
    sub(/^[[:space:]]*A: /, "", attr)
    val = first_quoted(attr)

    if (ind == comp_indent + 2) {
      if (attr ~ /^android:name\(/) name = val
      else if (attr ~ /^android:exported\(/) exported = bool_value(attr)
      else if (attr ~ /^android:permission\(/) permission = val
      else if (attr ~ /^android:authorities\(/) authorities = val
      else if (attr ~ /^android:grantUriPermissions\(/) grant = bool_value(attr)
    } else {
      if (last_elem == "action" && attr ~ /^android:name\(/) {
        if (actions == "") actions = val
        else actions = actions "," val
      } else if (last_elem == "category" && attr ~ /^android:name\(/) {
        if (categories == "") categories = val
        else categories = categories "," val
      } else if (attr ~ /^android:scheme\(/) {
        scheme_val = val
      } else if (attr ~ /^android:host\(/) {
        host_val = val
        host_seen = 1
      } else if (attr ~ /^android:pathPrefix\(/ || attr ~ /^android:pathPattern\(/) {
        path_val = path_val val
      } else if (attr ~ /^android:autoVerify\(/) {
        auto_verify = bool_value(attr)
      }
    }
    next
  }
}
END { finalize() }
' "$TREE" > "$COMP_FILE"

TOTAL_COMPONENTS="$(grep -c '^COMP|' "$COMP_FILE" || true)"
EXPORTED_COMPONENTS="$(grep '^COMP|' "$COMP_FILE" | awk -F'|' '$4 == "true"' | wc -l | tr -d ' ')"
UNSPECIFIED_COMPONENTS="$(grep '^COMP|' "$COMP_FILE" | awk -F'|' '$4 == "未声明"' | wc -l | tr -d ' ')"
DEEPLINK_COUNT="$(grep -c '^DEEPLINK|' "$COMP_FILE" || true)"

# ---------- 7. Application 级安全开关 ----------
app_attr_line() {
  local attr="$1"
  awk -v k="A: android:$attr(" 'index($0, k) > 0 { print; exit }' "$TREE" || true
}

line_bool() {
  local line="$1"
  local default="$2"
  if [[ -z "$line" ]]; then
    echo "$default"
    return
  fi
  if grep -q '0xffffffff' <<<"$line" || grep -qE '=true([^A-Za-z]|$)' <<<"$line"; then
    echo "true"
  elif grep -qE '0x0([^0-9a-fA-F]|$)' <<<"$line" || grep -qE '=false([^A-Za-z]|$)' <<<"$line"; then
    echo "false"
  else
    echo "?"
  fi
}

DEBUGGABLE_LINE="$(app_attr_line debuggable)"
BACKUP_LINE="$(app_attr_line allowBackup)"
CLEARTEXT_LINE="$(app_attr_line usesCleartextTraffic)"
NSC_LINE="$(app_attr_line networkSecurityConfig)"
FULL_BACKUP_LINE="$(app_attr_line fullBackupContent)"
DATA_EXTRACTION_LINE="$(app_attr_line dataExtractionRules)"
EXTRACT_NATIVE_LINE="$(app_attr_line extractNativeLibs)"
LEGACY_STORAGE_LINE="$(app_attr_line requestLegacyExternalStorage)"

DEBUGGABLE="$(line_bool "$DEBUGGABLE_LINE" "false")"
BACKUP="$(line_bool "$BACKUP_LINE" "未声明（默认 true）")"
EXTRACT_NATIVE="$(line_bool "$EXTRACT_NATIVE_LINE" "未声明（默认 true）")"
LEGACY_STORAGE="$(line_bool "$LEGACY_STORAGE_LINE" "未声明（默认 false）")"

# usesCleartextTraffic 的默认值与 targetSdk 有关：
# targetSdk >= 28 默认禁止明文；< 28 默认允许。
CLEARTEXT_DEFAULT="true（targetSdk < 28 时默认允许）"
if [[ "$TARGET_SDK" =~ ^[0-9]+$ && "$TARGET_SDK" -ge 28 ]]; then
  CLEARTEXT_DEFAULT="false（targetSdk >= 28 时默认禁止）"
fi
CLEARTEXT="$(line_bool "$CLEARTEXT_LINE" "$CLEARTEXT_DEFAULT")"

# ---------- 8. 输出 ----------
echo "============================================================"
echo "静态分析 06：Manifest / 组件 / 深链审计"
echo "目标：$TARGET"
echo "解析工具：${AAPT:-$AAPT2}"
echo "============================================================"
echo "包名              : ${PACKAGE_NAME:-?}"
echo "versionCode       : ${VERSION_CODE:-?}"
echo "versionName       : ${VERSION_NAME:-?}"
echo "minSdk            : ${MIN_SDK:-?}"
echo "targetSdk         : ${TARGET_SDK:-?}"
echo "启动 Activity     : ${LAUNCHABLE:-?}"
echo "组件总数          : $TOTAL_COMPONENTS"
echo "exported=true     : $EXPORTED_COMPONENTS"
echo "未声明 exported   : $UNSPECIFIED_COMPONENTS"
echo "深链数量          : $DEEPLINK_COUNT"

echo "------------------------------------------------------------"
echo "权限（$PERMISSION_COUNT 个）："
if [[ "$PERMISSION_COUNT" -eq 0 ]]; then
  echo "  (无)"
else
  printf '%s\n' "$PERMISSIONS" | awk 'NR <= 40' | sed 's/^/  - /'
  if [[ "$PERMISSION_COUNT" -gt 40 ]]; then
    echo "  ...（其余 $((PERMISSION_COUNT - 40)) 个已省略）"
  fi
fi

echo "------------------------------------------------------------"
echo "安全开关："
echo "  debuggable                  : $DEBUGGABLE"
if [[ -n "$BACKUP_LINE" ]]; then
  echo "  allowBackup                 : $BACKUP"
else
  echo "  allowBackup                 : $BACKUP"
fi
echo "  usesCleartextTraffic        : $CLEARTEXT"
echo "  networkSecurityConfig       : $([[ -n "$NSC_LINE" ]] && echo "已配置（资源引用，需解析 XML 内容）" || echo "未配置")"
echo "  fullBackupContent           : $([[ -n "$FULL_BACKUP_LINE" ]] && echo "已配置（资源引用，需解析 XML 内容）" || echo "未配置")"
echo "  dataExtractionRules         : $([[ -n "$DATA_EXTRACTION_LINE" ]] && echo "已配置（资源引用，需解析 XML 内容）" || echo "未配置")"
echo "  extractNativeLibs           : $EXTRACT_NATIVE"
echo "  requestLegacyExternalStorage: $LEGACY_STORAGE"

echo "------------------------------------------------------------"
echo "已导出组件（exported=true）："
EXPORTED_PRINTED=false
while IFS='|' read -r kind tag name exported permission authorities grant actions categories; do
  [[ "$kind" == "COMP" ]] || continue
  [[ "$exported" == "true" ]] || continue
  EXPORTED_PRINTED=true

  echo "  [$tag] $name"
  if [[ -n "$permission" ]]; then
    echo "      permission: $permission"
  else
    echo "      permission: (无)"
  fi
  if [[ -n "$authorities" ]]; then
    echo "      authorities: $authorities"
  fi
  if [[ -n "$grant" && "$grant" != "未声明" ]]; then
    echo "      grantUriPermissions: $grant"
  fi
  if [[ -n "$actions" ]]; then
    echo "      actions: $actions"
  fi
  if [[ -n "$categories" ]]; then
    echo "      categories: $categories"
  fi

  if [[ "$actions" == *'android.intent.action.MAIN'* && "$categories" == *'android.intent.category.LAUNCHER'* ]]; then
    echo "      说明: 启动入口（MAIN/LAUNCHER），通常需要导出。"
  elif [[ -z "$permission" ]]; then
    echo "      ⚠ 导出且无 permission 保护，需确认是否必要。"
  fi
done < "$COMP_FILE"
if [[ "$EXPORTED_PRINTED" != true ]]; then
  echo "  (无)"
fi

echo "------------------------------------------------------------"
echo "未显式声明 exported 的组件："
UNSPEC_PRINTED=false
while IFS='|' read -r kind tag name exported permission authorities grant actions categories; do
  [[ "$kind" == "COMP" ]] || continue
  [[ "$exported" == "未声明" ]] || continue
  UNSPEC_PRINTED=true

  echo "  [$tag] $name"
  if [[ -n "$actions" || -n "$categories" ]]; then
    echo "      含 intent-filter；Android 11 及以下可能默认导出。"
    if [[ "$TARGET_SDK" =~ ^[0-9]+$ && "$TARGET_SDK" -ge 31 ]]; then
      echo "      ⚠ targetSdk=$TARGET_SDK：Android 12+ 要求带 intent-filter 的组件显式声明 exported。"
    fi
  else
    echo "      无 intent-filter；默认通常不导出，但仍建议显式声明。"
  fi
  if [[ -n "$permission" ]]; then
    echo "      permission: $permission"
  fi
done < "$COMP_FILE"
if [[ "$UNSPEC_PRINTED" != true ]]; then
  echo "  (无)"
fi

if [[ "$SHOW_ALL" == true ]]; then
  echo "------------------------------------------------------------"
  echo "全部组件："
  grep '^COMP|' "$COMP_FILE" | while IFS='|' read -r kind tag name exported permission authorities grant actions categories; do
    printf '  [%s] %s  exported=%s' "$tag" "$name" "$exported"
    [[ -n "$permission" ]] && printf '  permission=%s' "$permission"
    printf '\n'
  done
fi

echo "------------------------------------------------------------"
echo "深链（scheme / host / path）："
DEEPLINK_PRINTED=false
while IFS='|' read -r kind name uri auto; do
  [[ "$kind" == "DEEPLINK" ]] || continue
  DEEPLINK_PRINTED=true
  echo "  - $uri"
  echo "      组件: $name"
  if [[ -n "$auto" ]]; then
    echo "      autoVerify: $auto"
  fi
done < "$COMP_FILE"
if [[ "$DEEPLINK_PRINTED" != true ]]; then
  echo "  (未解析到完整 scheme://host/path；原始 data 属性如下)"
  grep -E 'A: android:(scheme|host|pathPrefix|pathPattern)\(' "$TREE" \
    | sed -E 's/^[[:space:]]*//' | awk 'NR <= 20' | sed 's/^/  /' || true
fi

# ---------- 9. 结论 ----------
echo "------------------------------------------------------------"
echo "【结论】"

RISK=false

if [[ "$DEBUGGABLE" == "true" ]]; then
  echo "  ⚠ 应用声明了 debuggable=true：发布包不应开启调试。"
  RISK=true
fi

if [[ "$CLEARTEXT" == "true" ]]; then
  echo "  ⚠ 允许明文 HTTP（usesCleartextTraffic=true）：需确认是否有意，并检查网络安全配置。"
  RISK=true
fi

if [[ "$BACKUP" == "未声明（默认 true）" || "$BACKUP" == "true" ]]; then
  echo "  - 备份可能开启（allowBackup=$BACKUP）：需确认备份规则，避免敏感数据进入备份。"
fi

if [[ -n "$NSC_LINE" ]]; then
  echo "  - 存在 networkSecurityConfig：需进一步检查 cleartextTrafficPermitted 和 trust-anchors。"
fi

EXPORTED_NO_PERM=0
while IFS='|' read -r kind tag name exported permission authorities grant actions categories; do
  [[ "$kind" == "COMP" ]] || continue
  [[ "$exported" == "true" ]] || continue
  [[ -n "$permission" ]] && continue
  if [[ "$actions" == *'android.intent.action.MAIN'* && "$categories" == *'android.intent.category.LAUNCHER'* ]]; then
    continue
  fi
  EXPORTED_NO_PERM=$((EXPORTED_NO_PERM + 1))
done < "$COMP_FILE"

if [[ "$EXPORTED_NO_PERM" -gt 0 ]]; then
  echo "  ⚠ 有 $EXPORTED_NO_PERM 个非启动入口的导出组件没有 permission 保护：需逐个确认是否必要。"
  RISK=true
fi

if [[ "$DEEPLINK_COUNT" -gt 0 ]]; then
  echo "  - 存在 $DEEPLINK_COUNT 个深链：需确认参数校验、鉴权和敏感操作是否可被外部触发。"
fi

if [[ "$RISK" != true ]]; then
  echo "  未发现需要优先关注的 Manifest 风险信号。"
  echo "  注意：这不等于安全；还需检查代码、资源、native 和业务鉴权。"
  exit 0
fi

echo "  以上为静态结构信号，需结合业务逻辑和运行环境确认。"
exit 1
