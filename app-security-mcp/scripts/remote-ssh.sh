#!/bin/sh
set -eu
# 凭证由本机钥匙串提供；服务器地址和用户名取自 ~/.ssh/config。
SSH_ASKPASS="$HOME/.ssh/app-security-askpass"
export SSH_ASKPASS
export SSH_ASKPASS_REQUIRE=force
export DISPLAY="${DISPLAY:-:0}"
if [ ! -x "$SSH_ASKPASS" ]; then
  echo 'Missing ~/.ssh/app-security-askpass; see deploy/SERVER.md' >&2
  exit 1
fi
exec ssh -o StrictHostKeyChecking=yes -o NumberOfPasswordPrompts=1 app-security-prod "$@"
