#!/usr/bin/env bash
# interop.sh: a Web Bot Auth verifier against the LATEST upstream: the WG
# draft's test vectors (editor's copy on main), Cloudflare's npm package
# web-bot-auth (the reference signer, installed fresh) and Stytch's example
# recipe. The operator runs it, on the operator's schedule, against the
# operator's own WAF; the output names every upstream version it used.
#
# Against a deployed WAF (yours):
#   lua/tests/interop/interop.sh init /etc/wba-interop      # once: your interop key
#   # serve /etc/wba-interop/interop.jwks.json from an https URL you control,
#   # add that URL to agents.txt with type=jwks_uri, grant it nothing
#   TARGET=https://www.example.com \
#   INTEROP_KEY=/etc/wba-interop/interop-key.json \
#   INTEROP_AGENT=https://www.example.com/.well-known/wba-interop.jwks.json \
#   LOGS='docker logs --since 2m waf' \
#   lua/tests/interop/interop.sh
#   LOGS is any command that prints the WAF's log covering this run, e.g.
#   'kubectl logs deploy/waf --since=2m', 'journalctl -u nginx --since -2min -o cat'
#   or 'tail -n 5000 /var/log/nginx/wba.log'. Exit 0: every case as expected.
#
# Against a throwaway test container (development; Finch by default):
#   lua/tests/interop/interop.sh                (DOCKER=docker for Docker)
#
# Also: VERSION=0.2.0 (a given web-bot-auth release instead of latest),
# IMAGE=crs-wba:live (reuse a built image), LOG_WAIT=5 (seconds before LOGS).
# Needs: bun, curl; lua 5.3+ and openssl for the draft vectors (skipped if
# absent); for the test container, Finch or Docker.
set -euo pipefail

# A GitHub token (CI sets one, only to read GitHub without the anonymous rate
# limit) stays in an unexported variable: only the two GitHub reads below see
# it, never the npm package this script installs and runs.
GH_READ_TOKEN=${GITHUB_TOKEN:-}
unset GITHUB_TOKEN

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)

if [ "${1:-}" = init ]; then
  KEY_DIR=${2:?usage: interop.sh init <directory>} bun "$HERE/interop.ts" init
  exit 0
fi

DOCKER=${DOCKER:-finch}
VERSION=${VERSION:-latest}
export TLS_PORT=${TLS_PORT:-18996}
NAME=wba-interop-$$
export OUT; OUT=$(mktemp -d)
export NPM_DIR="$OUT/npm"
BUILT=0
COMPLETED=0
cleanup() {
  [ -n "${TARGET:-}" ] || $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  [ "$BUILT" = 1 ] && [ "${KEEP_IMAGES:-0}" != 1 ] && $DOCKER rmi crs-wba:interop >/dev/null 2>&1 || true
  rm -rf "$OUT"
  [ "$COMPLETED" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT

if [ -n "${TARGET:-}" ]; then
  : "${INTEROP_KEY:?set INTEROP_KEY (from interop.sh init)}" "${INTEROP_AGENT:?set INTEROP_AGENT (the URL you listed in agents.txt)}"
  : "${LOGS:?set LOGS to a command that prints your WAF log}"
  export TARGET INTEROP_KEY INTEROP_AGENT
fi

echo "== upstream: the WG draft's latest test vectors (editor's copy, main)"
if command -v "${LUA:-lua}" >/dev/null && command -v openssl >/dev/null; then
  GITHUB_TOKEN="$GH_READ_TOKEN" bun "$HERE/vectors.ts" > "$OUT/vectors.json"
  "${LUA:-lua}" "$HERE/vectors.lua" "$OUT/vectors.json"
else
  echo "SKIP  draft vectors: needs ${LUA:-lua} and openssl (the vectors run through this checkout's verify.lua: run interop.sh from the release you deploy)"
fi

echo "== upstream: web-bot-auth@$VERSION from npm"
mkdir -p "$NPM_DIR"
(cd "$NPM_DIR" && echo '{"private":true}' > package.json && bun add --silent "web-bot-auth@$VERSION" >/dev/null)

# Stytch's example cannot be imported (interop.ts says why), so its recipe is
# reproduced in interop.ts as of this blob of sign-and-fetch.js. A change
# upstream is reported for review; it does not fail the run.
STYTCH_REVIEWED=d86d0c206d056f2e48b13f80ede708d76aefedd7
stytch_now=$(curl -sf --max-time 10 ${GH_READ_TOKEN:+-H "Authorization: Bearer $GH_READ_TOKEN"} \
  "https://api.github.com/repos/stytchauth/web-bot-auth-example/contents/sign-and-fetch.js?ref=main" \
  | grep -o '"sha": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{40\}' || true)
if [ -z "$stytch_now" ]; then echo "NOTE  could not read Stytch's example (network or rate limit); its recipe is tested as reviewed"
elif [ "$stytch_now" != "$STYTCH_REVIEWED" ]; then echo "NOTE  Stytch's sign-and-fetch.js changed upstream ($stytch_now): review the recipe in interop.ts"
else echo "== upstream: Stytch example unchanged since review"; fi

if [ -z "${TARGET:-}" ]; then
  if [ -z "${IMAGE:-}" ]; then
    echo "== build the test image"
    $DOCKER build -q -f "$REPO/lua/wba/Dockerfile" -t crs-wba:interop "$REPO" >/dev/null
    IMAGE=crs-wba:interop BUILT=1
  fi
  echo "== sign (key store written by wba-keysync's own code)"
  bun "$HERE/interop.ts" prepare
  $DOCKER run -d --name "$NAME" -p "$TLS_PORT:8443" -e BACKEND=http://127.0.0.1:9 \
    -v "$OUT/keys:/etc/modsecurity.d/wba/keys:ro" "$IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 "https://127.0.0.1:$TLS_PORT/" || true)" != "000" ] && break
    sleep 1
  done
  LOGS="$DOCKER logs $NAME"
else
  echo "== sign with your interop key ($INTEROP_AGENT)"
  bun "$HERE/interop.ts" prepare
fi

echo "== send to ${TARGET:-the test container}"
bun "$HERE/interop.ts" send
sleep "${LOG_WAIT:-5}"
sh -c "$LOGS" > "$OUT/log.txt" 2>&1 || true

bun "$HERE/interop.ts" check
COMPLETED=1
