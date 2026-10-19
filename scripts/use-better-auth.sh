#!/usr/bin/env bash
# Install one Better Auth version, with the @better-auth/* plugins this package builds on, for the
# tests (CI's matrix). Usage: scripts/use-better-auth.sh <version|latest-1.7|latest-1.8|latest|next>
# latest-1.8 is the newest 1.8, pre-releases included (npm's `next` tag is an old 0.8 beta, and `beta` stops
# moving at 1.8.0).
set -euo pipefail
want="${1:?version}"
case "$want" in
  latest-1.7) v="$(npm view 'better-auth@>=1.7.0 <1.8.0' version --json | node -e 'const v=JSON.parse(require("fs").readFileSync(0,"utf8"));console.log(Array.isArray(v)?v.at(-1):v)')" ;;
  latest-1.8) v="$(npm view 'better-auth@>=1.8.0-0 <1.9.0' version --json | node -e 'const v=JSON.parse(require("fs").readFileSync(0,"utf8"));console.log(Array.isArray(v)?v.at(-1):v)')" ;;
  latest|next) v="$(npm view "better-auth@$want" version)" ;;
  *) v="$want" ;;
esac
echo "better-auth $want -> $v"
# Every @better-auth/* package the dev dependencies pin, so none keeps an older @better-auth/utils peer in the tree
# (1.7.8 moved to utils 0.5.0; drizzle-adapter 1.7.6 pins 0.4.2, which made two copies of @better-auth/core).
pnpm add -D -E "better-auth@$v" "@better-auth/core@$v" "@better-auth/oauth-provider@$v" "@better-auth/mcp@$v" "@better-auth/cimd@$v" "@better-auth/sso@$v" "@better-auth/scim@$v" "@better-auth/drizzle-adapter@$v"
