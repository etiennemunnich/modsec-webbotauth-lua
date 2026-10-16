#!/usr/bin/env bash
# paranoia.sh: do CRS's own rules, at paranoia levels 1 to 4, refuse signed
# requests the verifier accepts? Builds the image, sends every signer shape the
# live suite knows (each algorithm, jwks_uri and cimd agents, a proof, URL-less,
# an ActivityPub draft-cavage header) at each level over HTTP/1.1 and over
# HTTP/2 (where every header name is lower case), and fails if any is refused
# or not verified. At level 4 it also checks that the exemption from rule
# 920274 (wba.conf 1b) ignores letter case and covers nothing else. At level 1
# it pins a CRS false positive the README documents: rule 941120 refuses a
# random base64 value that happens to read as an "on...=" event handler. At
# every level it sends Signature-Agent URLs with percent-encoded characters,
# and pins which ones CRS rule 920272 refuses at levels 3 and 4. Last, at level
# 3, the exclusion the README gives for those: it lets them through and covers
# no other header.
# The backend is a dead port, so 502 means the request passed every rule;
# CRS's outbound threshold is raised so that 502 itself (rule 950100) cannot
# turn into a refusal.
#   lua/tests/live/paranoia.sh                 (Finch)
#   DOCKER=docker lua/tests/live/paranoia.sh   (Docker)
set -euo pipefail
DOCKER=${DOCKER:-finch}
LUA=${LUA:-lua}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
WORK=$(mktemp -d)
NAME=wba-paranoia-$$
IMAGE=crs-wba:paranoia
PORT=${PORT:-18990}
export TLS_PORT=${TLS_PORT:-18991}
FAIL=0
DONE=0
if command -v node >/dev/null; then H2=node; else H2=bun; fi
cleanup() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  $DOCKER rmi -f "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "$DONE" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT
h2() { # case, X-WBA-Test value: the case over HTTP/2, its header names in lower case
  OUT=$WORK MODE=send PRINT=1 CASE=$1 "$LUA" "$HERE/gen.lua" | grep -v '^gen: ' | $H2 "$HERE/h2.ts" "$2" example.com | awk '{ print $2 }'
}
rule_matched() { # X-WBA-Test value, CRS rule id: did the audit log record that rule for it?
  sleep 1
  $DOCKER logs "$NAME" 2>&1 | TAG=$1 $H2 "$HERE/audit-entry.ts" | grep -q "^$2 "
}

echo "== build"
$DOCKER build -q -f "$REPO/lua/wba/Dockerfile" -t "$IMAGE" "$REPO" >/dev/null
OUT=$WORK MODE=keys "$LUA" "$HERE/gen.lua"

CASES="verified verified-raw-path header-order url-less signed-googlebot-ua alg-ecdsa-p256 alg-ecdsa-p384 alg-rsa-pss alg-rsa-v15 agent-jwks agent-cimd agent-proof activitypub-cavage"
PCT_CASES="agent-pct-tilde agent-pct-space agent-pct-utf8 agent-pct-percent"
for pl in 1 2 3 4; do
  echo "== paranoia level $pl"
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  $DOCKER run -d --name "$NAME" -p "$PORT:8080" -p "$TLS_PORT:8443" -e BACKEND=http://127.0.0.1:9 \
    -e BLOCKING_PARANOIA="$pl" -e DETECTION_PARANOIA="$pl" -e ANOMALY_OUTBOUND=10000 \
    -v "$WORK/keys:/etc/modsecurity.d/wba/keys:ro" \
    -v "$HERE/wba-test-site-config.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-test-site-config.conf:ro" \
    "$IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$PORT/" || true)" != "000" ] && break
    sleep 1
  done
  for c in $CASES; do
    got=$(OUT=$WORK MODE=send PORT=$PORT CASE=$c "$LUA" "$HERE/gen.lua" | awk -v c="$c" '$1 == c { print $2 }')
    if [ "$got" = 502 ]; then echo "PASS  PL$pl $c (HTTP/1.1) -> passed every rule"
    else echo "FAIL  PL$pl $c (HTTP/1.1) -> HTTP $got (want 502)"; FAIL=1; fi
    got=$(h2 "$c" "$c-h2")
    if [ "$got" = 502 ]; then echo "PASS  PL$pl $c (HTTP/2) -> passed every rule"
    else echo "FAIL  PL$pl $c (HTTP/2) -> HTTP $got (want 502)"; FAIL=1; fi
  done
  # Signature-Agent URLs with percent-encoded characters. CRS rule 920272
  # (PL3 and up) decodes %XX first (t:urlDecodeUni), then allows only
  # printable ASCII other than "%" in any header: "~" (%7E) and a space (%20)
  # pass, but "é" in UTF-8 (%C3%A9) and a literal "%" (%25) are refused.
  # wba.conf exempts these headers from rule 920274 (PL4) only, not from
  # 920272. Pinned as found: if it changes, update the README's CRS section.
  for c in $PCT_CASES; do
    want=502 rule=""
    case "$pl:$c" in [34]:agent-pct-utf8|[34]:agent-pct-percent) want=403 rule=920272 ;; esac
    for v in 1.1 2; do
      if [ "$v" = 2 ]; then tag=$c-h2 got=$(h2 "$c" "$c-h2")
      else tag=$c got=$(OUT=$WORK MODE=send PORT=$PORT CASE=$c "$LUA" "$HERE/gen.lua" | awk -v c="$c" '$1 == c { print $2 }'); fi
      if [ "$got" = "$want" ] && { [ -z "$rule" ] || rule_matched "$tag" "$rule"; }; then
        echo "PASS  PL$pl $c (HTTP/$v) -> $([ -z "$rule" ] && echo "passed every rule" || echo "refused by CRS $rule")"
      else echo "FAIL  PL$pl $c (HTTP/$v) -> HTTP $got (want $want${rule:+ from $rule})"; FAIL=1; fi
    done
  done
  sleep 2
  want=32 # every case but the draft-cavage one verifies, over each protocol, refused by CRS or not
  got=$($DOCKER logs "$NAME" 2>&1 | grep -F '{"event":"web-bot-auth"' | grep -c '"status":"verified"' || true)
  if [ "$got" = "$want" ]; then echo "PASS  PL$pl verifier: $got verified"
  else echo "FAIL  PL$pl verifier: $got verified (want $want)"; FAIL=1; fi
  echo "      CRS rules matched: $($DOCKER logs "$NAME" 2>&1 | grep -oE '"ruleId":"9[0-9]{5}"' | sort | uniq -c | tr -s ' \n' ' ' || true)"

  if [ "$pl" = 4 ]; then
    # The exemption ignores letter case: the same request, its names in capitals
    # (over TLS, like every signed request here).
    signed=$(OUT=$WORK MODE=send PRINT=1 CASE=verified "$LUA" "$HERE/gen.lua" | grep -iE '^signature(-input|-agent)?: ')
    upper=()
    while IFS= read -r h; do upper+=(-H "$(printf '%s' "${h%%:*}" | tr 'a-z' 'A-Z'):${h#*:}"); done <<<"$signed"
    got=$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' -H 'Host: example.com' -H 'X-WBA-Test: upper-case-names' "${upper[@]}" --http1.1 -k "https://127.0.0.1:$TLS_PORT/" || true)
    if [ "$got" = 502 ]; then echo "PASS  PL4 header names in capitals (SIGNATURE-INPUT) -> passed every rule"
    else echo "FAIL  PL4 header names in capitals -> HTTP $got (want 502)"; FAIL=1; fi
    # ... and covers nothing else: the same Signature-Input value under another name.
    value=$(printf '%s
' "$signed" | grep -i '^signature-input: ' | cut -d' ' -f2-)
    got=$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' -H 'Host: example.com' -H 'X-WBA-Test: not-exempt' -H "X-Signature-Input: $value" --http1.1 -k "https://127.0.0.1:$TLS_PORT/" || true)
    if [ "$got" = 403 ] && rule_matched not-exempt 920274; then echo "PASS  PL4 the same value in X-Signature-Input -> refused by 920274"
    else echo "FAIL  PL4 the same value in X-Signature-Input -> HTTP $got (want 403 from 920274)"; FAIL=1; fi
  fi
  if [ "$pl" = 1 ]; then
    # CRS 4.30.0 rule 941120 (PL1) refuses these: a nonce, and a sha-256
    # Content-Digest, each 32 random-looking bytes in padded base64 (gen.lua).
    # If this starts passing, CRS fixed it: update the README's CRS section.
    for c in pl-nonce-b64-32 pl-digest-b64-32; do
      got=$(OUT=$WORK MODE=send PORT=$PORT CASE=$c "$LUA" "$HERE/gen.lua" | awk -v c="$c" '$1 == c { print $2 }')
      if [ "$got" = 403 ] && rule_matched "$c" 941120; then echo "PASS  PL1 $c -> refused by CRS 941120, as the README says"
      else echo "FAIL  PL1 $c -> HTTP $got (the README says CRS 941120 refuses it)"; FAIL=1; fi
    done
  fi
done

echo "== paranoia level 3, with the README's exclusion from rule 920272"
# The exclusion the README gives operators who need such Signature-Agent URLs
# at PL3 and PL4: it lets them through, and covers no other header.
printf '%s\n' 'SecRuleUpdateTargetById 920272 "!REQUEST_HEADERS:/^signature-agent$/"' > "$WORK/exclude-920272.conf"
$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
$DOCKER run -d --name "$NAME" -p "$PORT:8080" -p "$TLS_PORT:8443" -e BACKEND=http://127.0.0.1:9 \
  -e BLOCKING_PARANOIA=3 -e DETECTION_PARANOIA=3 -e ANOMALY_OUTBOUND=10000 \
  -v "$WORK/keys:/etc/modsecurity.d/wba/keys:ro" \
  -v "$HERE/wba-test-site-config.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-test-site-config.conf:ro" \
  -v "$WORK/exclude-920272.conf:/etc/modsecurity.d/owasp-crs/plugins/zz-exclude-920272-after.conf:ro" \
  "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$PORT/" || true)" != "000" ] && break
  sleep 1
done
for c in agent-pct-utf8 agent-pct-percent; do
  got=$(OUT=$WORK MODE=send PORT=$PORT CASE=$c "$LUA" "$HERE/gen.lua" | awk -v c="$c" '$1 == c { print $2 }')
  if [ "$got" = 502 ]; then echo "PASS  PL3 + exclusion: $c (HTTP/1.1) -> passed every rule"
  else echo "FAIL  PL3 + exclusion: $c (HTTP/1.1) -> HTTP $got (want 502)"; FAIL=1; fi
  got=$(h2 "$c" "$c-h2")
  if [ "$got" = 502 ]; then echo "PASS  PL3 + exclusion: $c (HTTP/2) -> passed every rule"
  else echo "FAIL  PL3 + exclusion: $c (HTTP/2) -> HTTP $got (want 502)"; FAIL=1; fi
done
got=$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' -H 'Host: example.com' -H 'X-WBA-Test: pct-not-excluded' \
  -H 'X-Signature-Agent: agent1="https://jwks.example/caf%C3%A9/keys.json";type=jwks_uri' --http1.1 -k "https://127.0.0.1:$TLS_PORT/" || true)
if [ "$got" = 403 ] && rule_matched pct-not-excluded 920272; then echo "PASS  PL3 + exclusion: the same value in X-Signature-Agent -> refused by 920272"
else echo "FAIL  PL3 + exclusion: the same value in X-Signature-Agent -> HTTP $got (want 403 from 920272)"; FAIL=1; fi

DONE=1
[ "$FAIL" = 0 ] && echo "== ALL PARANOIA CHECKS PASSED" || { echo "== PARANOIA CHECKS FAILED"; exit 1; }
