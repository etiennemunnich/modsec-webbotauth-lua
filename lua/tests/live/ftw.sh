#!/usr/bin/env bash
# ftw.sh: runs the go-ftw tests in tests/regression/web-bot-auth-plugin, the
# CRS way of testing a plugin, against our image with CRS at paranoia level 4,
# blocking. go-ftw cannot make a signature itself (it copies header values as
# written), so its requests go through lua/tests/live/ftw-agent.ts, a test bot
# that signs any request carrying X-WBA-Sign and passes the rest through.
#
#   lua/tests/live/ftw.sh                (Finch)
#   DOCKER=docker lua/tests/live/ftw.sh  (Docker)
#
# Needs: the container CLI, go-ftw 2.x (brew install coreruleset/tap/go-ftw;
# FTW=/path/to/go-ftw to choose one), bun, curl.
set -euo pipefail
DOCKER=${DOCKER:-finch}
PORT=${PORT:-18905}
TLS_PORT=${TLS_PORT:-18906}
AGENT_PORT=${AGENT_PORT:-18907}
NAME=wba-ftw-$$
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
TESTS=$REPO/tests/regression
FTW=${FTW:-$(command -v go-ftw || command -v ftw || true)}
[ -n "$FTW" ] || { echo "FAIL  go-ftw not found: brew install coreruleset/tap/go-ftw, or set FTW"; exit 1; }
WORK=$(mktemp -d)
PIDS=()
COMPLETED=0
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "${KEEP_IMAGES:-0}" = 1 ] || $DOCKER rmi crs-wba:ftw >/dev/null 2>&1 || true
  [ "$COMPLETED" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT

echo "== go-ftw: $("$FTW" -v | head -1)"
"$FTW" check -d "$TESTS"

echo "== build"
$DOCKER build -q ${CRS_IMAGE:+--build-arg CRS_IMAGE="$CRS_IMAGE"} -f "$REPO/lua/wba/Dockerfile" -t crs-wba:ftw "$REPO" >/dev/null

echo "== test bot"
bun "$REPO/wba-keysync/sign.ts" init "$WORK/bot" >/dev/null

# CRS_ENABLE_TEST_MARKER: the image logs go-ftw's marker requests, which is
# how go-ftw finds each test's lines in the log. ERRORLOG and LOGLEVEL: nginx
# writes its error log to a mounted file that go-ftw reads as it grows, at
# info, the level of ModSecurity's rule messages (the image's warn leaves them
# out). ANOMALY_OUTBOUND: the dead backend's 502 page is not what is tested.
mkdir -m 777 "$WORK/log"
$DOCKER run -d --name "$NAME" -p "$PORT:8080" -p "$TLS_PORT:8443" -e BACKEND=http://127.0.0.1:9 \
  -e BLOCKING_PARANOIA=4 -e DETECTION_PARANOIA=4 -e ANOMALY_OUTBOUND=10000 \
  -e CRS_ENABLE_TEST_MARKER=1 -e ERRORLOG=/var/log/ftw/error.log -e LOGLEVEL=info \
  -v "$WORK/log:/var/log/ftw" \
  -v "$WORK/bot/keys:/etc/modsecurity.d/wba/keys:ro" \
  -v "$HERE/wba-test-site-config.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-test-site-config.conf:ro" \
  -v "$HERE/wba-ftw-after.conf:/etc/modsecurity.d/owasp-crs/plugins/zz-wba-ftw-after.conf:ro" \
  -v "$REPO/lua/wba/recipes.conf:/etc/modsecurity.d/owasp-crs/plugins/zz-wba-recipes-after.conf:ro" \
  crs-wba:ftw >/dev/null
up=0
for _ in $(seq 1 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$PORT/" || true)" != "000" ] && { up=1; break; }
  sleep 1
done
[ "$up" = 1 ] || { echo "FAIL  container did not come up"; $DOCKER logs "$NAME" 2>&1 | tail -20; exit 1; }

bun "$HERE/ftw-agent.ts" "$AGENT_PORT" "$TLS_PORT" "$WORK/bot" > "$WORK/agent.log" 2>&1 &
PIDS+=($!); disown
for _ in $(seq 1 50); do grep -q '^ready$' "$WORK/agent.log" 2>/dev/null && break; sleep 0.2; done
grep -q '^ready$' "$WORK/agent.log" || { echo "FAIL  ftw-agent did not start:"; cat "$WORK/agent.log"; exit 1; }

# Every test goes to the agent, whatever its YAML says.
cat > "$WORK/ftw.yaml" <<EOF
logfile: $WORK/log/error.log
testoverride:
  input:
    dest_addr: 127.0.0.1
    port: $AGENT_PORT
    protocol: http
EOF

echo "== go-ftw run (CRS paranoia level 4, blocking)"
want=$(cat "$TESTS"/*/*.yaml | grep -c '^  - test_id:')
FAIL=0
"$FTW" run --config "$WORK/ftw.yaml" -d "$TESTS" -o plain > "$WORK/ftw.out" 2>&1 || FAIL=1
cat "$WORK/ftw.out"
# Every test must have run and passed: a file go-ftw skipped or could not read
# must not pass by being absent.
passed=$(grep -cE "running [0-9]+-[0-9]+: \+ passed" "$WORK/ftw.out" || true)
[ "$passed" = "$want" ] || FAIL=1
if [ -s "$WORK/agent.log" ] && grep -qv '^ready$' "$WORK/agent.log"; then
  echo "FAIL  ftw-agent reported:"; grep -v '^ready$' "$WORK/agent.log" | sed 's/^/      /'; FAIL=1
fi
echo "== $passed of $want go-ftw tests passed"
COMPLETED=1
if [ "$FAIL" = 0 ]; then echo "== GO-FTW TESTS PASSED"; else echo "== GO-FTW TESTS FAILED"; exit 1; fi
