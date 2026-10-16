#!/usr/bin/env bash
# registry.sh: the operator's path end to end, with real servers and a real
# client. Two test bots each publish their key directory from their own HTTPS
# server on this machine (bot-server.ts; certificates from a CA made here).
# A bots file lists both, and one that only claims a User-Agent;
# wba-keysync/agents.ts writes agents.txt from it; the key sync CLI fetches
# the directories over the network (TLS checked against that CA, and
# --allow-private-origin for exactly these two origins: without it key sync
# refuses them, which is checked first); the WAF mounts the store, and a bot
# client (sign.ts and curl) sends signed requests. Each is checked against the
# HTTP status and the JSON log line:
#   - each bot verifies as itself, with the example rules loaded;
#   - one bot's key cannot sign for the other;
#   - an unsigned request on the bot-only path is refused;
#   - the shipped rules act on each failure: a request changed after signing
#     is refused on the bot-only path (recipe A) and elsewhere (recipe F); a
#     User-Agent claiming ExampleBot is refused from a bot verified as
#     itself and from an unknown key (recipe B); an unknown key with no
#     claim, off the bot-only path, is logged and let through;
#   - a bot that rotates its key: after the next sync the old key is unknown
#     and the new one verifies, without restarting the WAF;
#   - a bot removed from the bots file stops verifying after the next sync,
#     and the other still verifies;
#   - a key server that breaks (404, wrong media type, a redirect, down, a
#     certificate key sync does not trust): key sync fails and says so (exit
#     2), keeps the last good key (draft 6.10), and that key still verifies;
#     the retry right after a failure is held back (draft C.5);
#   - a key the directory dates in the future (nbf) is held but not current;
#     one already expired is dropped, so the bot is no longer in the store.
#   bash lua/tests/live/registry.sh                (Finch)
#   DOCKER=docker bash lua/tests/live/registry.sh  (Docker)
# Needs: the container CLI, bun, openssl, curl. Ports 18444 (WAF), 19443 and
# 19444 (the bots, on 127.0.0.1); container wba-registry-$$.
set -euo pipefail
export DOCKER=${DOCKER:-finch}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
cd "$REPO"
PORT=18444 NAME=wba-registry-$$ IMAGE=crs-wba:registry
A=https://localhost:19443 B=https://localhost:19444
W=$(mktemp -d)
PIDS=() DONE=0 PID_a=''
cleanup() {
  for p in "${PIDS[@]}"; do { kill "$p"; wait "$p"; } 2>/dev/null || true; done
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  [ "${KEEP_IMAGES:-0}" = 1 ] || $DOCKER rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$W"
  [ "$DONE" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT

FAIL=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 -> $2"; else echo "FAIL  $1 -> ${2:-<nothing>} (want $3)"; FAIL=1; fi; }
count() { grep -vc '^#' "$1" || true; }

echo "== two bots, each serving its key directory over HTTPS"
mkdir -p "$W/tls" "$W/keys" "$W/scratch"
( cd "$W/tls"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 1 -subj "/CN=wba test CA"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost"
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 1 -extfile ext.cnf
) >/dev/null 2>&1
serve() { # serve <bot> <port>: start that bot's key server and wait until it answers
  bun "$HERE/bot-server.ts" "$2" "$W/$1.served.json" "$W/tls/srv.pem" "$W/tls/srv.key" >> "$W/$1.log" 2>&1 &
  PIDS+=($!); [ "$1" = a ] && PID_a=$!   # bot a's server is stopped later, to test a key server that is down
  for _ in $(seq 1 20); do
    curl -s --cacert "$W/tls/ca.pem" -o /dev/null "https://localhost:$2/" && return 0
    sleep 0.5
  done
  echo "bot-$1's key server did not start"; return 1
}
for bot in a b; do
  port=$([ "$bot" = a ] && echo 19443 || echo 19444)
  bun wba-keysync/sign.ts init "$W/$bot" --agent "https://localhost:$port" >/dev/null
  cp "$W/$bot/test-agent.jwks.json" "$W/$bot.served.json"
  serve "$bot" "$port"
done

bots() { # the bots file: the named bots, and one that only claims a User-Agent
  echo "bots:"
  for b in "$@"; do printf '  - name: bot-%s\n    wba: %s\n' "$b" "$([ "$b" = a ] && echo "$A" || echo "$B")"; done
  printf '  - name: claim-only\n    user_agent: ClaimBot\n'
}
keysync() { # the key sync CLI as an operator runs it, trusting the test CA (unless NO_CA=1)
  if [ "${NO_CA:-0}" = 1 ]; then bun wba-keysync/cli.ts --origins "$W/agents.txt" --out "$1" "${@:2}"
  else NODE_EXTRA_CA_CERTS="$W/tls/ca.pem" bun wba-keysync/cli.ts --origins "$W/agents.txt" --out "$1" "${@:2}"; fi
}
sync_registry() { # bots file -> agents.txt -> key store
  bun wba-keysync/agents.ts "$W/bots.yaml" --out "$W/agents.txt" 2>/dev/null
  local rc=0; keysync "$W/keys/wba-keys.tsv" --allow-private-origin "$A" --allow-private-origin "$B" > "$W/sync.log" 2>&1 || rc=$?
  chmod 755 "$W/keys"; chmod 644 "$W/keys/wba-keys.tsv"
  echo "$rc"
}

echo "== bots file -> agents.ts -> key sync over the network"
bots a b > "$W/bots.yaml"
bun wba-keysync/agents.ts "$W/bots.yaml" --out "$W/agents.txt" 2>/dev/null
check "agents.txt lines (claim-only bot left out)" "$(count "$W/agents.txt")" 2
rc=0; out=$(keysync "$W/scratch/wba-keys.tsv" 2>&1) || rc=$?
check "key sync without --allow-private-origin refuses both (draft 6.7)" "$rc/$(printf '%s\n' "$out" | grep -c 'loopback.*draft 6.7')" "2/2"
check "key sync with it" "$(sync_registry)" 0
check "keys in the store" "$(count "$W/keys/wba-keys.tsv")" 2
check "each bot's server was fetched" "$(grep -c 'GET /.well-known/http-message-signatures-directory' "$W/a.log")/$(grep -c 'GET /.well-known/http-message-signatures-directory' "$W/b.log")" "1/1"

echo "== the WAF with that store ($DOCKER)"
$DOCKER build -q -f lua/wba/Dockerfile -t "$IMAGE" . >/dev/null
printf '%s\n' "SecAction \"id:9534017,phase:1,pass,nolog,t:none,setvar:'tx.wba_site_names=example.com'\"" > "$W/site.conf"
$DOCKER run -d --name "$NAME" -p "$PORT:8443" -e BACKEND=http://127.0.0.1:9 \
  -v "$W/keys:/etc/modsecurity.d/wba/keys:ro" \
  -v "$W/site.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-site-config.conf:ro" \
  -v "$REPO/lua/wba/recipes.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-recipes-after.conf:ro" \
  "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 "https://localhost:$PORT/" || true)" != "000" ] && break
  sleep 1
done

# cmd <path> <key dir> [sign.ts options]: the bot client's curl command for
# that path, not yet sent, so a case can change it on the way (a proxy that
# rewrites the path, a User-Agent). Piped to sh it prints the HTTP status.
cmd() { bun wba-keysync/sign.ts curl "https://localhost:$PORT$1" --dir "$2" --host example.com --insecure "${@:3}"; }
# signed <name> <key dir> [sign.ts options]: send a signed request for /agents/<name>.
signed() { cmd "/agents/$1" "$2" "${@:3}" | sh; }
# verdict <name or path>: "status/reason agent" from that request's JSON log
# line (a bare name is under /agents/).
verdict() {
  local uri=$1; case $uri in /*) ;; *) uri=/agents/$uri ;; esac
  sleep 1
  $DOCKER logs "$NAME" 2>&1 | grep -F '{"event":"web-bot-auth"' | grep -F "\"uri\":\"$uri\"" | tail -1 \
    | sed -E 's/.*"status":"([^"]*)","reason":"([^"]*)","agent":("([^"]*)"|null).*/\1\/\2 \4/'
}
# refused_by <path> <rule id>: yes if that rule matched in the request's audit log entry.
refused_by() { $DOCKER logs "$NAME" 2>&1 | grep -F "\"uri\":\"$1\"" | grep -qF "\"ruleId\":\"$2\"" && echo yes || echo no; }
ua() { sed "s#^curl #curl '-A' 'ExampleBot/1.0' #"; }
ID_A=$A/.well-known/http-message-signatures-directory ID_B=$B/.well-known/http-message-signatures-directory

echo "== signed requests"
check "bot-a signs for itself" "$(signed a1 "$W/a")" 502
check "  log" "$(verdict a1)" "verified/ $ID_A"
check "bot-b signs for itself" "$(signed b1 "$W/b")" 502
check "  log" "$(verdict b1)" "verified/ $ID_B"
check "bot-a's key, claiming bot-b" "$(signed forged "$W/a" --agent "$B")" 403
check "  log" "$(verdict forged)" "unverified/unknown-key "
check "unsigned on /agents/" "$(curl -sk -o /dev/null -w '%{http_code}' -H 'Host: example.com' "https://localhost:$PORT/agents/unsigned")" 403

echo "== what the shipped rules (recipes.conf) do with each failure"
# A part bot-a signed (the path) changed on the way, as a forger or a
# rewriting proxy would: invalid/bad-signature. Recipe A refuses it on the
# bot-only path, and recipe F everywhere else.
check "bot-a's request, path changed after signing, on /agents/" \
  "$(cmd /agents/tampered "$W/a" | sed "s#/agents/tampered'\$#/agents/tampered-x'#" | sh)" 403
check "  log" "$(verdict tampered-x)" "invalid/bad-signature " # never attributed: README, agent
check "  refused by recipe A (9534130)" "$(refused_by /agents/tampered-x 9534130)" yes
check "the same on an ordinary path" "$(cmd /page/tampered "$W/a" | sed "s#/page/tampered'\$#/page/tampered-x'#" | sh)" 403
check "  log" "$(verdict /page/tampered-x)" "invalid/bad-signature "
check "  refused by recipe F (9534135)" "$(refused_by /page/tampered-x 9534135)" yes
# A User-Agent claiming ExampleBot needs ExampleBot's own signature (recipe
# B): a bot verified as itself is not enough, nor a key no one here holds.
check "bot-a, verified as itself, claiming ExampleBot's User-Agent" "$(cmd /page/ua-verified "$W/a" | ua | sh)" 403
check "  log" "$(verdict /page/ua-verified)" "verified/ $ID_A"
check "  refused by recipe B (9534131)" "$(refused_by /page/ua-verified 9534131)" yes
check "bot-a's key claiming bot-b, and ExampleBot's User-Agent" "$(cmd /page/ua-unknown "$W/a" --agent "$B" | ua | sh)" 403
check "  log" "$(verdict /page/ua-unknown)" "unverified/unknown-key "
check "  refused by recipe B (9534131)" "$(refused_by /page/ua-unknown 9534131)" yes
# With no claim and off the bot-only path, a signature that cannot be
# checked is logged, not refused: the shipped rules leave that to the site.
check "bot-a's key claiming bot-b, ordinary path, no claim" "$(cmd /page/unknown "$W/a" --agent "$B" | sh)" 502
check "  log" "$(verdict /page/unknown)" "unverified/unknown-key "

echo "== bot-a rotates its key; key sync runs; no restart"
bun wba-keysync/sign.ts init "$W/a2" --agent "$A" >/dev/null
cp "$W/a2/test-agent.jwks.json" "$W/a.served.json"
check "key sync" "$(sync_registry)" 0
check "keys in the store" "$(count "$W/keys/wba-keys.tsv")" 2
check "bot-a's old key" "$(signed a-old "$W/a")" 403
check "  log" "$(verdict a-old)" "unverified/unknown-key "
check "bot-a's new key" "$(signed a-new "$W/a2")" 502
check "  log" "$(verdict a-new)" "verified/ $ID_A"

echo "== bot-b removed from the bots file; key sync runs; no restart"
bots a > "$W/bots.yaml"
check "key sync" "$(sync_registry)" 0
check "keys in the store" "$(count "$W/keys/wba-keys.tsv")" 1
check "bot-b signs for itself" "$(signed b2 "$W/b")" 403
check "  log" "$(verdict b2)" "unverified/unknown-agent "
check "bot-a still verifies" "$(signed a3 "$W/a2")" 502
check "  log" "$(verdict a3)" "verified/ $ID_A"

echo "== bot-a's key server breaks; key sync keeps the last good key (draft 6.10)"
fetches() { grep -c 'GET /.well-known/http-message-signatures-directory' "$W/a.log" || true; }
# broken <case> <text key sync's error must contain>: run key sync on a fresh
# cache (no backoff from the case before), then sign with bot-a's current key.
broken() {
  rm -f "$W/keys/wba-keys.tsv.cache.json"
  local rc; rc=$(sync_registry)
  check "$1: key sync fails (exit 2)" "$rc" 2
  check "  and says why" "$(grep -F "failed: $A: " "$W/sync.log" | grep -cF -- "$2")" 1
  check "  last good key kept" "$(count "$W/keys/wba-keys.tsv")" 1
  check "  and still verifies" "$(signed "kept-$1" "$W/a2")" 502
  check "  log" "$(verdict "kept-$1")" "verified/ $ID_A"
}
ctl() { printf '%s\n' "$1" > "$W/a.served.json.ctl"; }
ctl '{"status":404}';                       broken 404 "HTTP 404"
before=$(fetches); rc=$(sync_registry)
check "retry straight after a failure: held back (draft C.5)" "$rc/$(grep -cF 'next try after' "$W/sync.log")/$(( $(fetches) - before ))" "2/1/0"
ctl '{"contentType":"application/json"}';   broken wrong-type 'content-type "application/json"'
ctl "{\"status\":302,\"location\":\"$B/.well-known/http-message-signatures-directory\"}"
broken redirect "HTTP 302"
rm -f "$W/a.served.json.ctl"
kill "$PID_a"; wait "$PID_a" 2>/dev/null || true
broken down "localhost:19443"
serve a 19443
before=$(fetches); NO_CA=1 broken untrusted-tls "certificate"
check "  no request reached bot-a's server (refused at TLS)" "$(( $(fetches) - before ))" 0
rm -f "$W/keys/wba-keys.tsv.cache.json"
check "repaired: key sync" "$(sync_registry)" 0

echo "== bot-a's directory dates its key (nbf, exp)"
bun wba-keysync/sign.ts init "$W/a-dated" --agent "$A" >/dev/null
# dated <member> <seconds from now>: bot-a serves its new key with that member set.
dated() { M=$1 D=$2 bun -e 'const f = process.argv[1], j = JSON.parse(await Bun.file(f).text());
  j.keys[0][process.env.M] = Math.floor(Date.now() / 1000) + Number(process.env.D); console.log(JSON.stringify(j));' \
  "$W/a-dated/test-agent.jwks.json" > "$W/a.served.json"; }
dated nbf 3600
check "key sync (nbf an hour ahead)" "$(sync_registry)" 0
check "keys in the store (held for later)" "$(count "$W/keys/wba-keys.tsv")" 1
check "the key before its nbf" "$(signed early "$W/a-dated")" 403
check "  log" "$(verdict early)" "unverified/key-not-current "
dated exp -60
check "key sync (exp passed): no usable key, exit 2" "$(sync_registry)/$(grep -cF "warning: $A: no usable key" "$W/sync.log")" "2/1"
check "keys in the store (bot-a has none now)" "$(count "$W/keys/wba-keys.tsv")" 0
check "the expired key" "$(signed late "$W/a-dated")" 403
check "  log" "$(verdict late)" "unverified/unknown-agent "
cp "$W/a2/test-agent.jwks.json" "$W/a.served.json"
check "bot-a back on its good key: key sync" "$(sync_registry)" 0
check "  verifies" "$(signed a4 "$W/a2")" 502
check "  log" "$(verdict a4)" "verified/ $ID_A"

DONE=1
[ "$FAIL" = 0 ] && echo "== REGISTRY PATH WORKS END TO END" || { echo "== REGISTRY PATH FAILED"; exit 1; }
