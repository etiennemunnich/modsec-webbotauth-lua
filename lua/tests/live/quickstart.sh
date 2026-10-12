#!/usr/bin/env bash
# quickstart.sh: runs README.md's Quick start as written (only "finch "
# becomes "$DOCKER "), then checks what it printed: 403 for the unsigned
# request, 502 for the signed one, and a verified log line for the test bot.
# The commands are read from the README itself, so the page cannot drift
# from what works. Uses port 8443 and the container name waf, as the page does.
#   lua/tests/live/quickstart.sh                (Finch)
#   DOCKER=docker lua/tests/live/quickstart.sh  (Docker)
set -euo pipefail
export DOCKER=${DOCKER:-finch}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
cd "$REPO"
[ -e wba-demo ] && { echo "wba-demo/ already exists: move it away first"; exit 1; }
HAD_IMAGE=$($DOCKER image inspect crs-wba >/dev/null 2>&1 && echo 1 || true)
WORK=$(mktemp -d)
DONE=0
cleanup() {
  $DOCKER rm -f waf >/dev/null 2>&1 || true
  [ -n "$HAD_IMAGE" ] || $DOCKER rmi -f crs-wba >/dev/null 2>&1 || true
  rm -rf wba-demo "$WORK"
  [ "$DONE" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT

# The Quick start's bash blocks, in order: block1 sets up, block2 sees it work.
awk -v dir="$WORK" '
  /^## Quick start/ { q = 1; next }
  /^## / { q = 0 }
  q && /^```bash/ { n++; on = 1; next }
  q && /^```/ { on = 0; next }
  on { gsub(/finch /, "$DOCKER "); print > (dir "/block" n ".sh") }
' lua/wba/README.md
[ -s "$WORK/block1.sh" ] && [ -s "$WORK/block2.sh" ] || { echo "FAIL  no Quick start blocks in README.md"; exit 1; }

echo "== Quick start, set up ($DOCKER)"
bash -e "$WORK/block1.sh" >/dev/null
for _ in $(seq 1 30); do
  [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 https://localhost:8443/ || true)" != "000" ] && break
  sleep 1
done

echo "== Quick start, see it work"
out=$(bash -e "$WORK/block2.sh" 2>&1)
FAIL=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 -> $2"; else echo "FAIL  $1 -> ${2:-<nothing>} (want $3)"; FAIL=1; fi; }
check "unsigned on /agents/" "$(printf '%s\n' "$out" | sed -n 1p)" 403
check "signed by the test bot" "$(printf '%s\n' "$out" | sed -n 2p)" 502
want='"status":"verified","reason":"","agent":"https://test-agent.example/.well-known/http-message-signatures-directory"'
if printf '%s' "$out" | grep -qF "$want"; then echo "PASS  log: verified for the test bot"
else echo "FAIL  log has no verified line for the test bot:"; printf '%s\n' "$out" | sed 's/^/      /'; FAIL=1; fi
[ -e wba-demo ] && { echo "FAIL  the last step left wba-demo/"; FAIL=1; }

DONE=1
[ "$FAIL" = 0 ] && echo "== QUICK START WORKS AS WRITTEN" || { echo "== QUICK START FAILED"; exit 1; }
