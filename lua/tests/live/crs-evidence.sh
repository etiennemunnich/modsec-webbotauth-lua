#!/usr/bin/env bash
# crs-evidence.sh: proof, as request and response, of how CRS's own rules treat
# signed requests at a paranoia level. For each "PL protocol case" given, it
# sends the request, then writes the headers sent, the status received and the
# CRS rules ModSecurity's audit log recorded for that request, plus the nginx,
# libmodsecurity, connector and CRS versions of the image. Markdown on stdout.
#   lua/tests/live/crs-evidence.sh "4 h2 verified" "1 h1 pl-nonce-b64-32"   (Finch)
#   DOCKER=docker lua/tests/live/crs-evidence.sh ...                       (Docker)
# Protocols: h1 (HTTP/1.1, header names as gen.lua writes them) and h2 (HTTP/2,
# where every header name is lower case). Cases are gen.lua's.
set -euo pipefail
DOCKER=${DOCKER:-finch}
LUA=${LUA:-lua}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
WORK=$(mktemp -d)
NAME=wba-evidence-$$
IMAGE=crs-wba:evidence
PORT=${PORT:-18992}
export TLS_PORT=${TLS_PORT:-18993}
if command -v node >/dev/null; then H2=node; else H2=bun; fi
cleanup() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  $DOCKER rmi -f "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
[ $# -gt 0 ] || { echo "usage: $0 \"<PL> <h1|h2> <case>\" ..." >&2; exit 2; }

$DOCKER build -q -f "$REPO/lua/wba/Dockerfile" -t "$IMAGE" "$REPO" >/dev/null
OUT=$WORK MODE=keys "$LUA" "$HERE/gen.lua"

start() { # paranoia level
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  $DOCKER run -d --name "$NAME" -p "$PORT:8080" -p "$TLS_PORT:8443" -e BACKEND=http://127.0.0.1:9 \
    -e BLOCKING_PARANOIA="$1" -e DETECTION_PARANOIA="$1" -e ANOMALY_OUTBOUND=10000 \
    -v "$WORK/keys:/etc/modsecurity.d/wba/keys:ro" \
    -v "$HERE/wba-test-site-config.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-test-site-config.conf:ro" \
    "$IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$PORT/" || true)" != "000" ] && break
    sleep 1
  done
}

start 1
versions=$($DOCKER exec "$NAME" sh -c '
  nginx -v 2>&1
  echo "libmodsecurity $(ls /usr/local/modsecurity/lib/ | sed -n "s/^libmodsecurity\.so\.\(3\.[0-9.]*\)$/\1/p" | sort -V | tail -1)"
  echo "connector $(grep -a -m1 -oE "ModSecurity-nginx v[0-9.]+" /etc/nginx/modules/ngx_http_modsecurity_module.so || echo unknown)"
  echo "CRS $(grep -rhoE -m1 "ver:.OWASP_CRS/[0-9.]+" /opt/owasp-crs/rules | head -1 | sed "s/.*OWASP_CRS\///")"')
echo "# CRS and signed requests: evidence"
echo
echo "Captured $(date -u +%Y-%m-%dT%H:%MZ) by \`lua/tests/live/crs-evidence.sh\` against the image built from \`lua/wba/Dockerfile\`:"
echo
printf '%s\n' "$versions" | sed 's/^/- /'
echo "- base image: \`$(sed -n 's/^ARG CRS_IMAGE=//p' "$REPO/lua/wba/Dockerfile")\`"
echo
echo "The backend is a dead port: 502 means the request passed every rule. CRS's outbound threshold is raised so the 502 itself cannot be refused."

current=1
for spec in "$@"; do
  read -r pl proto case <<<"$spec"
  [ "$pl" = "$current" ] || { start "$pl"; current=$pl; }
  if [ "$proto" = h2 ]; then
    tag="$case-h2"
    status=$(OUT=$WORK MODE=send PRINT=1 CASE=$case "$LUA" "$HERE/gen.lua" | grep -v "^gen: " | $H2 "$HERE/h2.ts" "$tag" example.com | awk '{ print $2 }')
  else
    tag=$case
    status=$(OUT=$WORK MODE=send PORT=$PORT CASE=$case "$LUA" "$HERE/gen.lua" | awk -v c="$case" '$1 == c { print $2 }')
  fi
  sleep 1
  echo
  echo "## PL$pl, $( [ "$proto" = h2 ] && echo HTTP/2 || echo HTTP/1.1 ), case \`$case\`"
  echo
  echo "Response: **$status**"
  echo
  # The request as ModSecurity saw it, and the CRS rules it matched, from the audit log.
  $DOCKER logs "$NAME" 2>&1 | TAG=$tag $H2 "$HERE/audit-entry.ts"
done
