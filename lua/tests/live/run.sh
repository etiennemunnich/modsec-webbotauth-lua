#!/usr/bin/env bash
# run.sh: end-to-end proof against a real owasp/modsecurity-crs:nginx container.
# Builds lua/wba/Dockerfile, mounts a fresh key store, sends signed requests,
# and asserts every outcome ModSecurity logs. Exits non-zero on any mismatch.
#
#   lua/tests/live/run.sh               (Finch, the default)
#   DOCKER=docker lua/tests/live/run.sh (Docker; both are tested in CI, or any compatible CLI)
#   CRS_IMAGE=owasp/modsecurity-crs:<tag> lua/tests/live/run.sh  (another base image)
#
# Needs: the container CLI, lua 5.3+, openssl, curl, bun or node.
set -euo pipefail

LUA=${LUA:-lua}
DOCKER=${DOCKER:-finch}
PORT=${PORT:-18895}
export TLS_PORT=${TLS_PORT:-18896}
NAME=wba-live-$$
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
WORK=$(mktemp -d)
FAIL=0
COMPLETED=0
# Every check below prints one PASS line through pass(). A run that skips a
# check, or loses one to a broken helper, ends with fewer and fails: change
# this number only together with the checks.
EXPECTED_PASSES=231
PASSES=0
pass() { echo "PASS  $*"; PASSES=$((PASSES + 1)); }
# Images this script builds are removed on exit (KEEP_IMAGES=1 keeps them):
# every rebuild otherwise leaves the previous one behind, untagged, and a
# 21-image matrix filled Finch's 50 GiB disk that way (2026-10-01).
cleanup() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "${KEEP_IMAGES:-0}" = 1 ] || $DOCKER rmi crs-wba:live crs-wba:test >/dev/null 2>&1 || true
  # bash 3.2 (macOS) exits 0 when set -u aborts a script that has an EXIT
  # trap, and $? reads 0 inside the trap: only reaching the end is success.
  [ "$COMPLETED" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT

echo "== test stage: Lua suites on the image's Lua 5.3, Wycheproof and crypto.lua's planted bugs against the built lua-openssl"
$DOCKER build --progress=plain --no-cache --target test ${CRS_IMAGE:+--build-arg CRS_IMAGE="$CRS_IMAGE"} -t crs-wba:test -f "$REPO/lua/wba/Dockerfile" "$REPO" 2>&1 \
  | grep -E "checks passed|wycheproof |planted bug caught|ERROR|FAIL" || { echo "FAIL  test stage"; exit 1; }

echo "== build"
$DOCKER build -q ${CRS_IMAGE:+--build-arg CRS_IMAGE="$CRS_IMAGE"} -f "$REPO/lua/wba/Dockerfile" -t crs-wba:live "$REPO" >/dev/null

echo "== key store"
OUT=$WORK MODE=keys "$LUA" "$HERE/gen.lua"

start() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  $DOCKER run -d --name "$NAME" -p "$PORT:8080" -p "$TLS_PORT:8443" -e BACKEND=http://127.0.0.1:9 \
    -v "${KEYS:-$WORK/keys}:/etc/modsecurity.d/wba/keys:ro" \
    -v "${SITE_CONF:-$HERE/wba-test-site-config.conf}:/etc/modsecurity.d/owasp-crs/plugins/wba-test-site-config.conf:ro" \
    -v "$HERE/wba-test-after.conf:/etc/modsecurity.d/owasp-crs/plugins/zz-wba-test-after.conf:ro" \
    -v "$REPO/lua/wba/recipes.conf:/etc/modsecurity.d/owasp-crs/plugins/zz-wba-recipes-after.conf:ro" \
    "$@" crs-wba:live >/dev/null
  for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$PORT/" || true)" != "000" ] && return 0
    sleep 1
  done
  echo "container did not come up"; exit 1
}
# gen.lua prints "<case> <HTTP status> <HTTP version>" for each request it
# sends; send keeps those lines in $WORK/sent.log.
send() { OUT=$WORK MODE=send PORT=$PORT CASE=${1:-} "$LUA" "$HERE/gen.lua" >> "$WORK/sent.log"; sleep 1; }
expect_h2() { # case: its last send went over HTTP/2 (curl --http2 falls back to HTTP/1.1 without a word)
  local got; got=$({ awk -v c="$1" '$1 == c { v = $3 } END { print v }' "$WORK/sent.log"; } 2>/dev/null || true)
  if [ "$got" = 2 ]; then pass "$1 -> sent over HTTP/2"
  else echo "FAIL  $1 -> sent over HTTP/${got:-?} (want 2): the TLS port must negotiate HTTP/2"; FAIL=1; fi
}
result() { # latest logged outcome for a case: "status/reason"
  { $DOCKER logs "$NAME" 2>&1 | grep -o "WBA-RESULT case=$1 status=[a-z-]* reason=[a-z-]*" | tail -1 \
    | sed -E 's/.*status=([a-z-]*) reason=([a-z-]*)/\1\/\2/'; } || true
}
phase1() { # the interim outcome a body case had at the end of phase 1
  { $DOCKER logs "$NAME" 2>&1 | grep -o "WBA-PHASE1 case=$1 status=[a-z-]* reason=[a-z-]*" | tail -1 \
    | sed -E 's/.*status=([a-z-]*) reason=([a-z-]*)/\1\/\2/'; } || true
}
# lua/tests/reasons.sh counts an outcome as tested live only on a line that
# starts with expect or expect1: keep each on its own line.
expect1() {
  local got; got=$(phase1 "$1")
  if [ "$got" = "$2" ]; then pass "$1 (phase 1) -> $got"; else echo "FAIL  $1 (phase 1) -> ${got:-<no result>} (want $2)"; FAIL=1; fi
}
expect() {
  local got; got=$(result "$1")
  if [ "$got" = "$2" ]; then pass "$1 -> $got"; else echo "FAIL  $1 -> ${got:-<no result>} (want $2)"; FAIL=1; fi
}
expect_http() { # case, status: sends the case again on its own and checks the HTTP status it gets
  local got; got=$(OUT=$WORK MODE=send PORT=$PORT CASE=$1 "$LUA" "$HERE/gen.lua" | awk -v c="$1" '$1 == c { print $2 }')
  if [ "$got" = "$2" ]; then pass "$1 -> HTTP $got"; else echo "FAIL  $1 -> HTTP ${got:-?} (want $2)"; FAIL=1; fi
}
lua_runs() { # Lua executions for one request, from the debug log
  $DOCKER exec "$NAME" sh -c ': > /tmp/modsec-debug.log'
  send "$1"
  $DOCKER exec "$NAME" sh -c 'grep -c "Returning from lua script" /tmp/modsec-debug.log || true'
}

echo "== live cases"
start
send
expect verified            verified/
expect verified-raw-path   verified/
expect alias-decoded-path  invalid/bad-signature
expect tampered-host       invalid/foreign-authority  # a Host that is not one of the site's names
expect unknown-key         unverified/unknown-key
expect dotted-component    invalid/missing-component
expect expired             invalid/expired
expect host-default-port   verified/
expect eight-sig-headers   invalid/orphan-label    # 7 Signature members without labels (RFC 9421 4); still 1 Lua run (below)
expect unsigned            not-signed/no-signature
expect header-order        verified/                 # repeated lines reach Lua in arrival order
expect header-order-swapped invalid/bad-signature    # and order is signed
expect malformed-input     not-signed/unparsable-field  # RFC 9651 4.2: an unparsable field is ignored (the default)
expect_http malformed-input 403         # not 400: the harness answers 403 to every plain case (rule 9534900)
expect malformed-reject    invalid/malformed-headers    # tx.wba_malformed=reject: the message is malformed
expect_http malformed-reject 400
expect activitypub-cavage  not-signed/unparsable-field  # a draft-cavage Signature header (ActivityPub) is not refused
expect_http activitypub-cavage 403      # not 400 (rule 9534900, as above)
expect url-less            verified/url-less          # draft 4.3: key held, no directory named
url_less_agent=$($DOCKER logs "$NAME" 2>&1 | grep -o "WBA-RESULT case=url-less [^']*" | tail -1)
case "$url_less_agent" in *"agent=n/a keyid="?*) pass "url-less names no agent, only the keyid";;
  *) echo "FAIL  url-less tx vars: $url_less_agent"; FAIL=1;; esac
expect orphan-label        invalid/orphan-label       # RFC 9421 4
expect cleartext-unsigned  not-signed/no-signature    # plain HTTP without a signature
expect cleartext-signed    verified/                  # plain HTTP: ModSecurity cannot see TLS (draft 6.1 not met, CONFORMANCE.md)
expect cleartext-scheme    invalid/bad-signature      # @scheme signed as http: the verifier uses https
expect signed-googlebot-ua verified/
# A full URL in the request line: nginx hands ModSecurity only what follows the
# host, and serves the request-line host. @path and @query exist only for a
# target that starts with "/".
expect absform-query-attack     invalid/missing-component  # "?evil=1": the signed @query is unavailable
expect absform-host-attack      verified/  # known limit: signed for example.com, served as other.example (README)
expect absform-host-2sp         verified/  # "GET  http://..." (nginx accepts extra SP)
expect absform-host-msearch     verified/  # method with "-"
expect absform-host-underscore  verified/  # method with "_"
expect absform-matching         verified/  # RFC 9112 3.2.2: absolute-form accepted
expect absform-request-target   invalid/bad-signature      # @request-target signed as the full URL; built here as "/x"
expect absform-query-legit      invalid/missing-component  # no path, so @query is unavailable here too
# Each spelling above, unsigned: nginx accepts it and hands it to ModSecurity,
# which the harness answers with 403 (rule 9534900).
for c in absform-unsigned absform-query-unsigned absform-host-unsigned absform-2sp-unsigned \
         absform-msearch-unsigned absform-underscore-unsigned; do
  expect_http "$c" 403; sleep 1
  expect "$c" not-signed/no-signature
done

echo "== every documented reason reaches ModSecurity (lua/tests/reasons.sh): the rest"
expect missing-param          invalid/missing-param          # no keyid
expect bad-param              invalid/bad-param              # created is a string
expect bad-keyid              invalid/bad-keyid              # not a 43-character thumbprint
expect not-yet-valid          invalid/not-yet-valid          # created 300 s ahead (60 s allowed)
expect too-old                invalid/too-old                # created 4000 s ago (tx.wba_max_age 3600)
expect no-wba-signature       not-signed/no-wba-signature    # tag="other"
expect duplicate-component    invalid/duplicate-component
expect authority-not-covered  invalid/authority-not-covered
expect unsupported-component  invalid/unsupported-component  # @status is for responses
expect bad-component-value    invalid/bad-component-value    # a covered header that is not ASCII
expect agent-not-covered      invalid/agent-not-covered      # Signature-Agent sent but not signed
expect ambiguous-agent        invalid/ambiguous-agent        # two members covered, neither the label's
expect agent-not-https        invalid/agent-not-https
expect unsupported-agent-type unverified/unsupported-agent-type
expect unparsable-agent       invalid/unparsable-agent       # covered whole, not a dictionary: never a 400 by default
expect test-key               invalid/test-key               # RFC 9421's published Ed25519 key
expect agent-absent           unverified/agent-absent        # URL-less, a key the store does not hold
expect key-not-current        unverified/key-not-current     # the store dates the key out
expect digest-malformed       invalid/malformed-digest
expect_http digest-malformed  400                            # rule 9534107, whatever tx.wba_malformed says
expect digest-md5-only        unverified/digest-algorithm-unsupported

echo "== every algorithm (RFC 9421 3.3, chosen per 3.2 step 6) through lua-openssl"
expect alg-ecdsa-p256        verified/
expect alg-ecdsa-p256-noalg  verified/                  # the key type allows one algorithm
expect alg-ecdsa-p384        verified/
expect alg-rsa-pss           verified/
expect alg-rsa-v15           verified/
expect alg-rsa-noalg         invalid/alg-undetermined   # an RSA key with no JWK alg and no parameter
expect alg-rsa-declared      verified/                  # the same key, alg named by the signer
expect alg-mismatch          invalid/alg-mismatch       # the JWK pins rsa-pss-sha512
expect alg-ecdsa-der         invalid/bad-signature      # r || s only (3.3.4)
expect alg-hmac              invalid/unsupported-alg    # draft 6.4

echo "== agent types (draft 5.5) and possession proofs (Appendix B)"
expect agent-jwks            verified/
agent_of() { $DOCKER logs "$NAME" 2>&1 | grep -o "WBA-RESULT case=$1 [^']*" | tail -1 | grep -o 'agent=[^ ]*' || true; }
[ "$(agent_of agent-jwks)" = "agent=https://jwks.example/keys.json" ] && pass "agent-jwks names the jwks_uri, query dropped" \
  || { echo "FAIL  agent-jwks agent: $(agent_of agent-jwks)"; FAIL=1; }
expect agent-cimd            verified/
expect agent-jwks-wrong-type unverified/bad-agent-url  # untyped means directory: an origin, never a path (5.5)
expect agent-proof           verified/

echo "== logs (wba.conf rule 7, wba_log.lua): one JSON line per signed request, none for unsigned, never the signature"
audit_entry() { # case $1's transaction in the audit log (one JSON object per line)
  { $DOCKER logs "$NAME" 2>&1 | grep -F "WBA-RESULT case=$1 " | tail -1; } || true
}
wba_line() { # the plugin's own JSON line for case $1's transaction
  local u; u=$(audit_entry "$1" | grep -o '"unique_id":"[^"]*"' | head -1)
  [ -n "$u" ] || { echo "NO-TRANSACTION-FOUND"; return; }
  { $DOCKER logs "$NAME" 2>&1 | grep -F '{"event":"web-bot-auth"' | grep -F "$u" | tail -1; } || true
}
expect_wba() { # case, ERE its line must match ("" = there must be no line)
  local line; line=$(wba_line "$1")
  if [ -z "$2" ]; then
    [ -z "$line" ] && pass "$1: no log line" || { echo "FAIL  $1: unexpected log line: $line"; FAIL=1; }
  elif printf '%s' "$line" | grep -Eq -- "$2"; then pass "$1: log line as expected"
  else echo "FAIL  $1: log line '${line:-<none>}' does not match $2"; FAIL=1; fi
}
expect_rule() { # case, rule id: that rule matched in the case's transaction
  if audit_entry "$1" | grep -qF "\"ruleId\":\"$2\""; then pass "$1 -> rule $2"
  else echo "FAIL  $1: rule $2 not in its audit entry"; FAIL=1; fi
}
expect_no_rule() { # case, rule id: the case's transaction was logged, and that rule did not match in it
  local e; e=$(audit_entry "$1")
  if [ -n "$e" ] && ! printf '%s' "$e" | grep -qF "\"ruleId\":\"$2\""; then pass "$1 -> not rule $2"
  else echo "FAIL  $1: ${e:+rule $2 in its audit entry}${e:-no audit entry}"; FAIL=1; fi
}
DIR='https://agent\.example/\.well-known/http-message-signatures-directory'
WIN='"created":[0-9]+,"expires":[0-9]+'
# agent_proof: gen.lua's store records proof "none" for key 1 and "valid" for proof.example's key.
expect_wba agent-proof '"status":"verified","reason":"","agent":"https://proof\.example/\.well-known/http-message-signatures-directory","agent_proof":"valid",'
expect_wba verified "\"status\":\"verified\",\"reason\":\"\",\"agent\":\"$DIR\",\"agent_proof\":\"none\",\"keyid\":\"[A-Za-z0-9_-]{43}\",\"label\":\"sig1\",$WIN,\"granted\":false,\"sighash\":\"[0-9a-f]{64}\",\"uses\":null,\"nonce_uses\":null,\"covered\":\"@authority signature-agent\"\}$"
expect_wba url-less "\"status\":\"verified\",\"reason\":\"url-less\",\"agent\":null,\"agent_proof\":null,\"keyid\":\"[A-Za-z0-9_-]{43}\",\"label\":\"sig1\",$WIN,\"granted\":false,\"sighash\":\"[0-9a-f]{64}\",\"uses\":null,\"nonce_uses\":null,\"covered\":\"@authority\"\}$"
expect_wba tampered-host '"host":"evil\.example","status":"invalid","reason":"foreign-authority","agent":null,"agent_proof":null,"keyid":null,"label":null,"created":null,"expires":null,"granted":false,"sighash":null,"uses":null,"nonce_uses":null,"covered":null\}$'
expect_wba verified '^\{"event":"web-bot-auth","time":[0-9]+,"unique_id":"[^"]+","client_ip":"[^"]+","method":"GET","uri":"/","host":"example\.com","status":'
expect_wba unsigned ""
lines=$($DOCKER logs "$NAME" 2>&1 | grep -cF '{"event":"web-bot-auth"' || true)
long=$($DOCKER logs "$NAME" 2>&1 | grep -F '{"event":"web-bot-auth"' | grep -cE '[A-Za-z0-9+/]{80,}' || true)
[ "$lines" -gt 0 ] && [ "$long" = 0 ] && pass "$lines log lines, none carries signature bytes" \
  || { echo "FAIL  log lines: $lines, with an 80+ char base64 run: $long"; FAIL=1; }
audit=$($DOCKER logs "$NAME" 2>&1 | grep -vF '{"event":"web-bot-auth"' | grep -cE 'sig1=:[A-Za-z0-9+/]{80,}' || true)
[ "$audit" -gt 0 ] && pass "the audit log's part B does hold raw signatures ($audit entries), as the README warns" \
  || { echo "FAIL  no raw signature in the audit log: the README's part B warning needs revisiting"; FAIL=1; }

echo "== recipes.conf as shipped: A requires a signature under /agents/; B ties a claimed User-Agent to its directory"
for c in recipe-agents-unsigned recipe-agents-dot recipe-agents-slashes recipe-agents-case recipe-agents-encoded \
         recipe-agents-bare recipe-agents-matrix; do
  expect_http "$c" 403; sleep 1; expect_rule "$c" 9534130
done
expect_http recipe-agents-dotdot 403; sleep 1 # "..": CRS path-traversal rules refuse it before the recipe runs
if audit_entry recipe-agents-dotdot | grep -qE '"ruleId":"930[0-9]{3}"'; then pass "recipe-agents-dotdot -> refused by CRS 930xxx first"
else echo "FAIL  recipe-agents-dotdot: no CRS 930xxx rule in its audit entry"; FAIL=1; fi
for c in recipe-ua-unsigned recipe-ua-urlless; do # urlless: verified, but for no directory
  expect_http "$c" 403; sleep 1; expect_rule "$c" 9534131
done
for c in recipe-agents-verified recipe-ua-verified recipe-no-claim; do
  expect_http "$c" 502 # passed every rule; the test backend is a dead port
done
expect_http recipe-agents-prefix 502; sleep 1 # /agentsx is another path: A must not match it
expect_no_rule recipe-agents-prefix 9534130
expect_http recipe-forged 403; sleep 1; expect_rule recipe-forged 9534135   # F: a held key's check failed
expect recipe-forged invalid/bad-signature
expect_http recipe-foreign 403; sleep 1; expect_rule recipe-foreign 9534135 # F: a signature made for another site
expect recipe-foreign invalid/foreign-authority
expect_http recipe-test-key 403; sleep 1; expect_rule recipe-test-key 9534135 # F: a published key, which anyone can sign with
expect recipe-test-key invalid/test-key
expect_http recipe-expired 502                                             # F: an expired signature is not refused
expect recipe-expired invalid/expired

echo "== switching the plugin off: tx.web-bot-auth-plugin_enabled=0, the web-bot-auth tag, and the CRS id form"
expect_http recipe-switch-off 403; sleep 1        # a valid signature on /agents: off means nothing verifies, so recipe A refuses
expect_rule recipe-switch-off 9534130
expect recipe-switch-off not-signed/no-signature  # every variable still exists: the switch comes after rule 9534100
expect_wba recipe-switch-off ""
runs=$(lua_runs recipe-switch-off)
[ "$runs" = "0" ] && pass "recipe-switch-off -> 0 Lua runs: the switch skips the scripts in phases 1, 2 and 5" \
  || { echo "FAIL  recipe-switch-off -> $runs Lua runs (want 0)"; FAIL=1; }
expect_http recipe-tag-off 502; sleep 1           # every rule tagged web-bot-auth is gone for this request, recipe A included
got=$(result recipe-tag-off)
[ "$got" = "/" ] && pass "recipe-tag-off -> no tx.wba_* variable at all: rule 9534100 (a SecAction) removed too" \
  || { echo "FAIL  recipe-tag-off -> $got (want no status and no reason)"; FAIL=1; }
expect_wba recipe-tag-off ""
runs=$(lua_runs recipe-tag-off)
[ "$runs" = "0" ] && pass "recipe-tag-off -> 0 Lua runs: ctl:ruleRemoveByTag reaches SecRuleScript" \
  || { echo "FAIL  recipe-tag-off -> $runs Lua runs (want 0)"; FAIL=1; }
expect recipe-ids-off verified/                    # ctl:ruleRemoveById leaves the scripts running; phase 2 keeps phase 1's outcome
expect_wba recipe-ids-off '"status":"verified","reason":"",'
runs=$(lua_runs recipe-ids-off)
[ "$runs" = "3" ] && pass "recipe-ids-off -> 3 Lua runs (phases 1, 2, 5): ctl:ruleRemoveById does not reach SecRuleScript" \
  || { echo "FAIL  recipe-ids-off -> $runs Lua runs (want 3)"; FAIL=1; }
expect recipe-ids-off-unsigned not-signed/no-signature  # not unverified/internal-error from phase 2
expect_wba recipe-ids-off-unsigned ""

echo "== draft 5.3: recipe A asks for a signature (460 becomes 403 with Accept-Signature), and the answer verifies"
hdr() { # case, header name: that header of the case's last response
  { tr -d '\r' < "$WORK/$1.hdr" | grep -i "^$2:" | head -1 | sed -E 's/^[^:]*: //'; } || true
}
ACCEPT_RE='^sig1=\("@authority" "@method" "@path" "signature-agent";key="sig1"\);created;expires;nonce="[0-9a-f]{32}";tag="web-bot-auth"$'
expect_accept() { # case, status: the response asks for a signature
  local st acc; st=$(tr -d '\r' < "$WORK/$1.hdr" | head -1 | awk '{ print $2 }'); acc=$(hdr "$1" Accept-Signature)
  if [ "$st" = "$2" ] && printf '%s' "$acc" | grep -Eq "$ACCEPT_RE" && [ "$(hdr "$1" Cache-Control)" = no-store ]; then
    pass "$1 -> $st, Accept-Signature $acc, Cache-Control no-store"
  else echo "FAIL  $1 -> $st, Accept-Signature '${acc}', Cache-Control '$(hdr "$1" Cache-Control)'"; FAIL=1; fi
}
expect_accept recipe-agents-unsigned 403
expect_accept recipe-agents-case 403
expect_accept recipe-agents-matrix 403
n1=$(hdr recipe-agents-unsigned Accept-Signature | sed -E 's/.*nonce="([0-9a-f]*)".*/\1/')
n2=$(hdr recipe-agents-case Accept-Signature | sed -E 's/.*nonce="([0-9a-f]*)".*/\1/')
[ -n "$n1" ] && [ "$n1" != "$n2" ] && pass "each request gets its own nonce" || { echo "FAIL  nonces '$n1' '$n2'"; FAIL=1; }
[ -z "$(hdr recipe-agents-dotdot Accept-Signature)" ] && pass "CRS's own 403 asks for nothing" \
  || { echo "FAIL  a CRS 403 carries Accept-Signature"; FAIL=1; }
got=$(OUT=$WORK MODE=send PORT=$PORT NONCE=$n1 CASE=recipe-accept-answer "$LUA" "$HERE/gen.lua" | awk '$1 == "recipe-accept-answer" { print $2 }')
sleep 1
[ "$got $(result recipe-accept-answer)" = "502 verified/" ] && pass "signed as asked (label sig1, member sig1, the nonce): verified, passes recipe A" \
  || { echo "FAIL  the answer: HTTP $got, $(result recipe-accept-answer)"; FAIL=1; }

echo "== HTTP/2 on the TLS port: nginx turns :authority into the Host header ModSecurity reads"
# Never skipped: the image negotiates HTTP/2 on its TLS port, and the run
# proves it. Each curl case shows the version it went over (expect_h2);
# h2.ts speaks HTTP/2 only, so it cannot fall back.
expect_h2 verified-h2
expect verified-h2 verified/
expect_h2 tampered-h2
expect tampered-h2 invalid/foreign-authority
if command -v node >/dev/null; then H2=node; else H2=bun; fi
h2() { OUT=$WORK MODE=send PRINT=1 CASE=verified "$LUA" "$HERE/gen.lua" | $H2 "$HERE/h2.ts" "$@"; }
h2 h2-authority-only example.com >/dev/null; sleep 1
expect h2-authority-only verified/
h2_refused() { # case, :authority, host: nginx must answer 400 before ModSecurity sees it
  local got r; got=$(h2 "$1" "$2" "$3" | awk '{ print $2 }'); sleep 1; r=$(result "$1")
  if [ "$got" = 400 ] && [ -z "$r" ]; then pass "$1 (:authority $2, host $3) -> HTTP 400, never reached ModSecurity"
  else echo "FAIL  $1 -> HTTP ${got:-?} ${r}"; FAIL=1; fi
}
h2_refused h2-authority-mismatch other.example example.com
h2_refused h2-host-mismatch      example.com   other.example

echo "== RFC 9530 body digests: pending in phase 1, decided in phase 2 with REQUEST_BODY"
for c in body-match body-match-512 body-tampered body-removed body-chunked body-h2 body-nobody-access body-too-large body-large-512; do
  expect1 "$c" unverified/digest-pending
done
expect body-match          verified/
expect body-match-512      verified/   # lua-openssl's sha512 (crypto.lua)
expect body-tampered       invalid/digest-mismatch
expect_http body-tampered 403; sleep 1; expect_rule body-tampered 9534135 # recipe F: the body is not the one signed
expect body-removed        invalid/digest-mismatch
expect body-chunked        verified/   # nginx removes the chunked framing before ModSecurity
expect_h2 body-h2
expect body-h2             verified/
expect body-nobody-access  unverified/digest-pending  # phase 2 never runs: never verified without the body
expect body-too-large      unverified/body-too-large  # SHA-256 runs in Lua: capped (policy.max_sha256_body)
expect body-large-512      verified/                  # SHA-512 runs in C: 1 MiB is cheap

echo "== content codings (unencoded-digest draft 5, coding.lua) and partial PUT (RFC 9110 14.4, 14.5)"
for c in body-coded-gzip body-coded-xgzip-512 body-coded-mismatch body-coded-corrupt body-coded-bomb body-coded-repr \
         body-range-post body-range-put-whole; do
  expect1 "$c" unverified/digest-pending
done
expect1 body-coded-br          unverified/digest-coding-unsupported # decided from the headers, in phase 1
expect1 body-range-put-partial unverified/digest-partial
expect body-coded-gzip         verified/                   # decoded, then hashed
expect body-coded-xgzip-512    verified/
expect body-coded-mismatch     invalid/digest-mismatch
expect body-coded-corrupt      invalid/bad-content-coding  # gzip without its trailer
expect body-coded-bomb         unverified/body-too-large   # 10 MiB of zeros, ~10 KB sent: stops at the decode budget
expect body-coded-br           unverified/digest-coding-unsupported
expect body-coded-repr         verified/                   # Repr-Digest covers the coded bytes, never decoded
expect body-range-post         verified/                   # Content-Range ignored off PUT (14.4: MUST ignore)
expect body-range-put-partial  unverified/digest-partial   # the rest of the representation is not here
expect body-range-put-whole    verified/                   # bytes 0-17/18 is the whole representation

crashes=$($DOCKER logs "$NAME" 2>&1 | grep -c "exited on signal" || true)
[ "$crashes" = "0" ] && pass "0 worker crashes" || { echo "FAIL  $crashes worker crashes"; FAIL=1; }

runs=$(lua_runs eight-sig-headers) # verification once, plus the phase-5 log line
[ "$runs" = "2" ] && pass "8 Signature headers -> 1 verification + 1 log Lua run" || { echo "FAIL  8 Signature headers -> $runs Lua runs (want 2)"; FAIL=1; }
runs=$(lua_runs unsigned)
[ "$runs" = "0" ] && pass "unsigned -> 0 Lua runs" || { echo "FAIL  unsigned -> $runs Lua runs"; FAIL=1; }

echo "== body cut at SecRequestBodyLimit (ProcessPartial): INBOUND_DATA_ERROR=1"
start -e MODSEC_REQ_BODY_LIMIT=64 -e MODSEC_REQ_BODY_LIMIT_ACTION=ProcessPartial
send body-cut-at-limit
expect1 body-cut-at-limit unverified/digest-pending
expect  body-cut-at-limit unverified/body-incomplete

echo "== operator settings (wba-test-config.conf over web-bot-auth-config.conf)"
start -v "$HERE/wba-test-config.conf:/etc/modsecurity.d/owasp-crs/plugins/web-bot-auth-config.conf:ro"
for c in grant grant-authority-only needs-path needs-path-covered short-window bad-config needs-nonce needs-nonce-given; do send "$c"; done
expect grant              verified/
expect_wba grant '"granted":true,'
expect grant-authority-only verified/
expect_wba grant-authority-only '"granted":false,'   # a grant needs @method and @path covered
expect needs-path         unverified/insufficient-coverage
expect needs-path-covered verified/
expect short-window       invalid/window-too-long
expect needs-nonce        unverified/missing-nonce   # tx.wba_require_nonce=1
expect needs-nonce-given  verified/
expect bad-config         unverified/bad-config
expect_wba bad-config '"status":"unverified","reason":"bad-config"'
named=$($DOCKER exec "$NAME" sh -c 'grep -c "bad configuration: tx.wba_max_window" /tmp/modsec-debug.log || true')
[ "${named:-0}" -gt 0 ] && pass "the debug log names the malformed setting" || { echo "FAIL  malformed setting not named in the debug log"; FAIL=1; }
# Recipe C marks a granted bot with tx.bot_management_exempt=1. It logs
# nothing (nolog), so rule 9534917 in wba-test-config.conf logs when the
# variable is set, in phase 5, after every phase-2 rule. recipe- cases pass
# rule 9534900 and reach phase 2.
expect_http recipe-grant 502; sleep 1                  # passed every rule; the test backend is a dead port
expect_rule recipe-grant 9534917
expect_http recipe-grant-authority-only 502; sleep 1   # verified, not granted (@method and @path not covered)
expect_no_rule recipe-grant-authority-only 9534917

echo "== replay accounting (wba-test-replay-config.conf): recipes D and E answer 429 with Accept-Signature"
start -v "$HERE/wba-test-replay-config.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-test-replay-config.conf:ro"
print_case() { # case [fixed time]: save the signed headers gen.lua prints
  NOW=${2:-} OUT=$WORK MODE=send PRINT=1 CASE=$1 "$LUA" "$HERE/gen.lua" | grep -E '^[A-Za-z-]+: ' > "$WORK/$1.sig"
}
signed_curl() { # case, path, header dump [, headers file]: send saved bytes, print the status
  local args=() h
  while IFS= read -r h; do args+=(-H "$h"); done < "${4:-$WORK/$1.sig}"
  curl -sk --http1.1 -o /dev/null -D "$3" -w '%{http_code}\n' --max-time 10 --path-as-is "${args[@]}" \
    -H "X-WBA-Test: $1" "https://127.0.0.1:$TLS_PORT$2"
}
print_case recipe-replay
c1=$(signed_curl recipe-replay /agents/r /dev/null); sleep 1; r1=$(result recipe-replay)
signed_curl recipe-replay /agents/r "$WORK/recipe-replay.hdr" >/dev/null; sleep 1
[ "$c1 $r1" = "502 verified/" ] && pass "first use of a signature: verified, passes" || { echo "FAIL  first use: $c1 $r1"; FAIL=1; }
expect_accept recipe-replay 429
expect_rule recipe-replay 9534133
expect_wba recipe-replay '"status":"verified",.*"uses":2,"nonce_uses":null,'
$DOCKER exec "$NAME" sh -c ': > /tmp/modsec-debug.log'
c3=$(signed_curl recipe-replay /agents/r /dev/null); sleep 1
runs=$($DOCKER exec "$NAME" sh -c 'grep -c "Returning from lua script" /tmp/modsec-debug.log || true')
u=$(audit_entry recipe-replay | grep -o '"unique_id":"[^"]*"' | head -1)
lines=$({ $DOCKER logs "$NAME" 2>&1 | grep -F '{"event":"web-bot-auth"' | grep -cF "$u"; } || true)
[ "$c3 $runs $lines" = "429 2 1" ] && pass "a 429 answer runs the Lua twice (verify, log) and logs one line: error_page re-runs nothing" \
  || { echo "FAIL  429 path: HTTP $c3, $runs Lua runs, $lines log lines (want 429 2 1)"; FAIL=1; }
ecnow=$(date +%s)
print_case recipe-replay-ecdsa "$ecnow"; mv "$WORK/recipe-replay-ecdsa.sig" "$WORK/ec1.sig"
print_case recipe-replay-ecdsa "$ecnow"; mv "$WORK/recipe-replay-ecdsa.sig" "$WORK/ec2.sig"
e1=$(signed_curl recipe-replay-ecdsa /agents/ec /dev/null "$WORK/ec1.sig")
e2=$(signed_curl recipe-replay-ecdsa /agents/ec /dev/null "$WORK/ec2.sig")
if ! cmp -s <(grep '^Signature:' "$WORK/ec1.sig") <(grep '^Signature:' "$WORK/ec2.sig") && [ "$e1 $e2" = "502 429" ]; then
  pass "two ECDSA signatures over one base: the second is a reuse (counted by the signed statement, not its bytes)"
else echo "FAIL  ECDSA same base: HTTP $e1 then $e2 (want 502 429, with different signature bytes)"; FAIL=1; fi
print_case recipe-replay-burst
codes=$(for _ in $(seq 1 20); do signed_curl recipe-replay-burst /agents/burst /dev/null & done; wait)
ok=$(printf '%s\n' "$codes" | grep -c '^502$' || true); limited=$(printf '%s\n' "$codes" | grep -c '^429$' || true)
[ "$ok $limited" = "1 19" ] && pass "20 concurrent uses of one signature: 1 passes, 19 get 429" \
  || { echo "FAIL  20 concurrent uses: $ok passed, $limited limited ($(printf '%s ' $codes))"; FAIL=1; }
print_case recipe-nonce-1; print_case recipe-nonce-2
c1=$(signed_curl recipe-nonce-1 / /dev/null); signed_curl recipe-nonce-2 / "$WORK/recipe-nonce-2.hdr" >/dev/null; sleep 1
[ "$c1" = 502 ] && pass "a nonce's first use passes" || { echo "FAIL  nonce first use: HTTP $c1"; FAIL=1; }
expect_accept recipe-nonce-2 429
expect_rule recipe-nonce-2 9534134
send replay-unavailable
expect replay-unavailable unverified/replay-unavailable # a directory the workers cannot write fails closed

echo "== key rotation without restart"
OUT=$WORK MODE=rotate "$LUA" "$HERE/gen.lua" > "$WORK/rotated.tsv"
if command -v bun >/dev/null; then RUNTIME=bun; else RUNTIME=node; fi
(cd "$REPO" && SRC="$WORK/rotated.tsv" DST="$WORK/keys/wba-keys.tsv" $RUNTIME -e \
  'import("./wba-keysync/keysync.ts").then(async (m) => { const fs = await import("node:fs"); m.writeAtomic(process.env.DST, fs.readFileSync(process.env.SRC, "utf8")); })')
send verified
expect verified    unverified/unknown-key
send unknown-key
expect unknown-key verified/

echo "== no site names set: nothing verifies"
: > "$WORK/no-site-names.conf"
SITE_CONF=$WORK/no-site-names.conf start
send no-site-names
expect no-site-names unverified/no-site-names

echo "== no key store mounted"
mkdir -p "$WORK/no-keys"
KEYS=$WORK/no-keys start
send keystore-unavailable
expect keystore-unavailable unverified/keystore-unavailable

echo "== crypto module missing (an empty directory hides lua-openssl's openssl.so)"
mkdir -p "$WORK/empty"
start -v "$WORK/empty:/usr/local/lib/lua/5.3:ro"
send unknown-key
expect unknown-key unverified/engine-error

echo "== a Lua script that does not compile stops startup (SecRuleScript; @inspectFile would run it as a program)"
printf 'function main(\n' > "$WORK/broken.lua"
if $DOCKER run --rm -v "$WORK/broken.lua:/etc/modsecurity.d/wba/lua/modsecurity_entry.lua:ro" crs-wba:live nginx -t > "$WORK/broken.out" 2>&1; then
  echo "FAIL  nginx -t accepted a script that does not compile"; FAIL=1
elif grep -q 'Rules error' "$WORK/broken.out"; then pass "a script that does not compile: nginx -t refuses the rules"
else echo "FAIL  nginx -t failed for another reason: $(tail -1 "$WORK/broken.out")"; FAIL=1; fi

COMPLETED=1
# The count, not only the absence of FAIL lines: a check that quietly did not
# run must fail the run.
[ "$PASSES" = "$EXPECTED_PASSES" ] && echo "== $PASSES checks passed, as EXPECTED_PASSES says" \
  || { echo "FAIL  $PASSES checks passed, EXPECTED_PASSES is $EXPECTED_PASSES: a check was skipped, lost or added"; FAIL=1; }
[ "$FAIL" = 0 ] && echo "== ALL LIVE CHECKS PASSED" || { echo "== LIVE CHECKS FAILED"; exit 1; }
