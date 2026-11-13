#!/usr/bin/env bash
# scripts/build_release.sh
#
# release 构建入口。所有 release 包必须走这个脚本，
# 不允许开发者直接敲 flutter build。
set -euo pipefail

ENV="${1:-}"
case "$ENV" in
  prod|uat|test|dev) ;;
  *) echo "用法: $0 <prod|uat|test|dev>"; exit 2 ;;
esac

# 生产包必须显式传 prod。写错一个字母就构建失败，
# 而不是"默默用了 dev 的地址"。
BUILD_MODE="release"
if [ "$ENV" != "prod" ]; then
  if [ "${ALLOW_NON_PROD_RELEASE:-}" != "1" ]; then
    echo "拒绝：非生产环境不允许出 release 包。"
    exit 3
  fi
  # 非生产内测包走 profile：ApiConfig 的 kReleaseMode 守卫会拒绝
  # APP_ENV != prod 的 release 包；profile 既保留接近 release 的性能，
  # 又不会让这个逃生口产出"启动即炸"的包。
  BUILD_MODE="profile"
fi

# 先把环境配置文件生成出来，再传给 flutter。
# 用 --dart-define-from-file 而不是一长串 --dart-define：
# 配置文件可以被 CI 校验，命令行参数不行。
CFG="$(mktemp)"
trap 'rm -f "$CFG"' EXIT
python3 - "$ENV" > "$CFG" <<'PYEOF'
import json, sys
print(json.dumps({"APP_ENV": sys.argv[1]}))
PYEOF

# release 必须显式指定入口：程序从 main_prod.dart 出发，
# 不 import 任何 mock 文件；否则默认入口可能把 Mock 带进产物。
flutter build apk --$BUILD_MODE \
  -t lib/main_prod.dart \
  --dart-define-from-file="$CFG" \
  --obfuscate \
  --split-debug-info=build/symbols

# 构建完立刻过门槛，不通过就整条流水线失败。
#
# ⚠️ --baseline 必须带上。脚本现在把它当硬前置条件：不带会直接 FAIL，
# 不再打印 SKIP 后以 0 退出。"门槛静默降级成不检查"是最危险的一种失效。
python3 scripts/release_gate_scan.py \
  build/app/outputs/flutter-apk/app-$BUILD_MODE.apk \
  --baseline scripts/known-bad-keys.txt
