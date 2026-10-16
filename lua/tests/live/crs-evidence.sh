#!/usr/bin/env bash
# crs-evidence.sh: proof, as request and response, of how CRS's own rules treat
# signed requests at a paranoia level. For each "PL protocol case" given, it
# sends the request, then writes the headers sent, the status received and the
# CRS rules ModSecurity's audit log recorded for that request, plus the nginx,
# libmodsecurity, connector and CRS versions of the image. Markdown on stdout.
# With no arguments it sends the five cases of
# lua/wba/evidence/crs-paranoia-levels.md and writes that page, intro included:
#   bash lua/tests/live/crs-evidence.sh > lua/wba/evidence/crs-paranoia-levels.md
#   bash lua/tests/live/crs-evidence.sh "4 h2 verified" "1 h1 pl-nonce-b64-32"
# Finch by default; DOCKER=docker for Docker.
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
PAGE=0
if [ $# -eq 0 ]; then
  PAGE=1
  set -- "1 h1 pl-nonce-b64-32" "1 h1 pl-digest-b64-32" "4 h1 verified" "4 h2 verified" "4 h2 agent-jwks"
fi

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
# shellcheck disable=SC2016 # the $(...) run in the container's shell, not here
versions=$($DOCKER exec "$NAME" sh -c '
  nginx -v 2>&1
  echo "libmodsecurity $(ls /usr/local/modsecurity/lib/ | sed -n "s/^libmodsecurity\.so\.\(3\.[0-9.]*\)$/\1/p" | sort -V | tail -1)"
  echo "connector $(grep -a -m1 -oE "ModSecurity-nginx v[0-9.]+" /etc/nginx/modules/ngx_http_modsecurity_module.so || echo unknown)"
  echo "CRS $(grep -rhoE -m1 "ver:.OWASP_CRS/[0-9.]+" /opt/owasp-crs/rules | head -1 | sed "s/.*OWASP_CRS\///")"')
echo "# CRS paranoia levels and signed requests: evidence"
echo
if [ "$PAGE" = 1 ]; then
  cat <<'EOF'
CRS's paranoia level (PL) sets how strict its rules are, from 1, the default, to 4. Each case below is one signed request: the response, the request as ModSecurity recorded it, and the CRS rules it matched. The first two show a false positive at PL 1, and so at every level: rule 941120, an XSS rule, reads a digit, `/` or `+` followed by `on`, letters and `=` as an HTML event handler such as `onload=`. About 1 in 2,000 random 32-byte values in padded base64, such as a 32-byte nonce or a sha-256 `Content-Digest`, match it. The exclusion for it is in the [README](../README.md#crs-paranoia-levels). The last three pass at PL 4 over HTTP/1.1 and HTTP/2, because `wba.conf` exempts `Signature-Input`, `Signature` and `Signature-Agent` from rule 920274, and from that rule only, whatever the case of the header names.

EOF
fi
echo "Captured $(date -u +%Y-%m-%dT%H:%MZ) by \`lua/tests/live/crs-evidence.sh\` against the image built from \`lua/wba/Dockerfile\`:"
echo
printf '%s\n' "$versions" | sed 's/^/- /'
echo "- base image: \`$(sed -n 's/^ARG CRS_IMAGE=//p' "$REPO/lua/wba/Dockerfile")\`"
echo
echo "The backend is a dead port: 502 means the request passed every rule. CRS's outbound threshold is raised so the 502 itself cannot be refused."
if [ "$PAGE" = 1 ]; then
  echo
  echo "Rerun (Finch; \`DOCKER=docker\` for Docker): \`bash lua/tests/live/crs-evidence.sh > lua/wba/evidence/crs-paranoia-levels.md\`. Timestamps and signatures differ on every run."
fi

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
