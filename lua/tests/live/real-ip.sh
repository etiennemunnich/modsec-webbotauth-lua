#!/usr/bin/env bash
# real-ip.sh: which client address ModSecurity sees behind a trusted proxy, in
# the CRS image the Dockerfile pins (README, step 5). A rule answers 418 when
# REMOTE_ADDR is the address sent in the proxy header, so 418 means
# ModSecurity saw the visitor and 502 (the dead test backend) means it saw the
# proxy.
#   - The image's own SET_REAL_IP_FROM/REAL_IP_HEADER settings, which sit
#     inside `location /`: nginx swaps the address after ModSecurity-nginx 1.0.4
#     has read it, so ModSecurity keeps the proxy's. If this starts answering
#     418, the image or the connector changed: update README step 5.
#   - The README's http-level file: ModSecurity sees the visitor, through
#     X-Real-IP and through X-Forwarded-For with real_ip_recursive.
#   bash lua/tests/live/real-ip.sh                (Finch)
#   DOCKER=docker bash lua/tests/live/real-ip.sh  (Docker)
set -euo pipefail
export DOCKER=${DOCKER:-finch}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
IMAGE=$(sed -n 's/^ARG CRS_IMAGE=//p' "$REPO/lua/wba/Dockerfile" | head -1)
HAD_IMAGE=$($DOCKER image inspect "$IMAGE" >/dev/null 2>&1 && echo 1 || true)
PORT=18093 NAME=wba-real-ip-$$
WORK=$(mktemp -d)
FAIL=0 DONE=0
cleanup() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  [ -n "$HAD_IMAGE" ] || $DOCKER rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "$DONE" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 -> $2"; else echo "FAIL  $1 -> ${2:-<nothing>} (want $3)"; FAIL=1; fi; }

printf '%s\n' "SecRule REMOTE_ADDR \"@ipMatch 203.0.113.7\" \"id:9534995,phase:1,deny,status:418,nolog,t:none\"" > "$WORK/see.conf"
printf 'set_real_ip_from 0.0.0.0/0;\nset_real_ip_from ::/0;\nreal_ip_header X-Real-IP;\n' > "$WORK/x-real-ip.conf"
printf 'set_real_ip_from 0.0.0.0/0;\nset_real_ip_from ::/0;\nreal_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n' > "$WORK/xff.conf"

# start [extra run options]: the image with the probe rule, trusting every
# proxy through the image's own settings (test only: never trust everyone).
start() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  $DOCKER run -d --name "$NAME" -p "$PORT:8080" -e BACKEND=http://127.0.0.1:9 \
    -e SET_REAL_IP_FROM=0.0.0.0/0 -e REAL_IP_HEADER=X-Real-IP \
    -v "$WORK/see.conf:/etc/modsecurity.d/owasp-crs/plugins/zz-real-ip-probe-before.conf:ro" \
    "$@" "$IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://localhost:$PORT/" || true)" != "000" ] && return
    sleep 1
  done
}
probe() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 -H "$1" "http://localhost:$PORT/" || true; }

echo "== the image's own real-IP settings (inside location /) ($DOCKER)"
start
check "X-Real-IP: 203.0.113.7, image settings only: ModSecurity sees the proxy" "$(probe 'X-Real-IP: 203.0.113.7')" 502

echo "== the README's http-level file"
start -v "$WORK/x-real-ip.conf:/etc/nginx/conf.d/00-real-ip.conf:ro"
check "X-Real-IP: 203.0.113.7: ModSecurity sees the visitor" "$(probe 'X-Real-IP: 203.0.113.7')" 418
check "no header: ModSecurity sees the connection's address" "$(probe 'X-Unrelated: 1')" 502
start -v "$WORK/xff.conf:/etc/nginx/conf.d/00-real-ip.conf:ro"
check "X-Forwarded-For: 203.0.113.7: ModSecurity sees the visitor" "$(probe 'X-Forwarded-For: 203.0.113.7')" 418

DONE=1
[ "$FAIL" = 0 ] && echo "== REAL-IP CHECKS PASSED" || { echo "== REAL-IP CHECKS FAILED"; exit 1; }
