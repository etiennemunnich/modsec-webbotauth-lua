#!/usr/bin/env bash
# bot-lists.sh: the bot lists path end to end. Three test operators publish
# IP lists from their own HTTPS servers on this machine (bot-server.ts;
# certificates from a CA made here) and a fourth publishes a key directory.
# wba-keysync/lists.ts turns the bots file into rules and data files; the WAF
# loads them; requests arrive "from" chosen addresses through the README's
# http-level real-IP file (X-Real-IP, every proxy trusted: a test only). A
# probe rule logs tx.bot_* for each request that passes. Checked:
#   - a claim from an address on the bot's list is verified (ip-list), with
#     the list's version; from elsewhere it is claimed (not-in-list) and the
#     allow policy refuses it as an impostor (enforce mode);
#   - no claim, no evidence; IPv6; upper case; a token with a space and a dot;
#   - deny refuses the bot from its list and anyone claiming it; log logs a
#     bot with no list (no-list); a claim-only token from outside its list
#     passes; a bot verified by its Web Bot Auth signature (signature);
#   - the operator changes a list: lists.ts --check/--reload (nginx -t and a
#     reload in the container) gives a new version, which the next request
#     carries; a list server that breaks keeps the previous version (exit 2);
#   - log mode: the impostor passes, and the policy rule logs it;
#   - load order: an operator's own site-wba-rules-after.conf (it sorts before
#     the bot list rules' name) reads a bot that signed, with its User-Agent
#     token, as verified by signature, and the same token unsigned as claimed;
#   - a list with ranges inside others (and ranges side by side): only the
#     outer ones are written, and an address in an inner range still matches.
#   bash lua/tests/live/bot-lists.sh                (Finch)
#   DOCKER=docker bash lua/tests/live/bot-lists.sh  (Docker)
# Needs: the container CLI, bun, openssl, curl. Ports 18445 (WAF), 19445 to
# 19449 (the operators, on 127.0.0.1); container wba-bot-lists-$$.
set -euo pipefail
export DOCKER=${DOCKER:-finch}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
cd "$REPO"
PORT=18445 NAME=wba-bot-lists-$$ IMAGE=crs-wba:bot-lists
W=$(mktemp -d)
PIDS=() DONE=0
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do { kill "$p"; wait "$p"; } 2>/dev/null || true; done
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  [ "${KEEP_IMAGES:-0}" = 1 ] || $DOCKER rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$W"
  [ "$DONE" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT

FAIL=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 -> $2"; else echo "FAIL  $1 -> ${2:-<nothing>} (want $3)"; FAIL=1; fi; }

echo "== three operators publishing IP lists, one publishing keys, over HTTPS"
mkdir -p "$W/tls" "$W/out" "$W/keys"
( cd "$W/tls"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 1 -subj "/CN=wba test CA"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost"
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 1 -extfile ext.cnf
) >/dev/null 2>&1
list() { # list <file> <creationTime> <range>...: an operator's list in the common JSON shape
  local f=$1 t=$2 items="" r; shift 2
  for r in "$@"; do
    case $r in *:*) items="$items{\"ipv6Prefix\":\"$r\"}," ;; *) items="$items{\"ipv4Prefix\":\"$r\"}," ;; esac
  done
  printf '{"creationTime":"%s","prefixes":[%s]}\n' "$t" "${items%,}" > "$f"
}
serve() { # serve <port> <file> [path]: start an operator's server and wait until it answers
  bun "$HERE/bot-server.ts" "$1" "$2" "$W/tls/srv.pem" "$W/tls/srv.key" ${3:+"$3"} >> "$W/servers.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 20); do
    curl -s --cacert "$W/tls/ca.pem" -o /dev/null "https://localhost:$1/" && return 0
    sleep 0.5
  done
  echo "the server on $1 did not start"; return 1
}
list "$W/listbot.json" 2026-10-01T00:00:00Z 192.0.2.0/24 2001:db8:1::/48
list "$W/denybot.json" 2026-10-01T00:00:00Z 198.51.100.0/24
list "$W/sharedbot.json" 2026-10-01T00:00:00Z 203.0.113.0/25
# Ranges inside others (a /29 and an address inside the /26; a /64 inside the
# first /48), and ranges side by side that are never merged.
list "$W/nestbot.json" 2026-10-01T00:00:00Z 203.0.113.136/29 203.0.113.128/26 203.0.113.140 203.0.113.192/27 \
  2001:db8:5:1::/64 2001:db8:5::/48 2001:db8:6::/48
serve 19445 "$W/listbot.json" /listbot.json
serve 19446 "$W/denybot.json" /denybot.json
serve 19447 "$W/sharedbot.json" /sharedbot.json
serve 19449 "$W/nestbot.json" /nestbot.json
bun wba-keysync/sign.ts init "$W/signer" --agent https://localhost:19448 >/dev/null
cp "$W/signer/test-agent.jwks.json" "$W/signer.served.json"
serve 19448 "$W/signer.served.json"
printf 'https://localhost:19448\n' > "$W/agents.txt"
NODE_EXTRA_CA_CERTS="$W/tls/ca.pem" bun wba-keysync/cli.ts --origins "$W/agents.txt" --out "$W/keys/wba-keys.tsv" \
  --allow-private-origin https://localhost:19448 > "$W/sync.log" 2>&1
chmod 755 "$W/keys"; chmod 644 "$W/keys/wba-keys.tsv"

bots() { # bots <policy mode>: the bots file
  cat <<EOF
policy_mode: $1
bots:
  - name: listbot
    user_agent: [ListBot, Mon.itor Bot/]
    ips: https://localhost:19445/listbot.json
    policy: allow
  - name: denybot
    user_agent: DenyBot
    ips: https://localhost:19446/denybot.json
    policy: deny
  - name: logbot
    user_agent: LogBot
    policy: log
  - name: sharedbot
    user_agent: Shared-User
    ips: https://localhost:19447/sharedbot.json
    policy: allow
    claim_only: true
  - name: signbot
    user_agent: SignBot
    wba: https://localhost:19448
  - name: nestbot
    user_agent: NestBot
    ips: https://localhost:19449/nestbot.json
EOF
}
ORIGINS=(--allow-private-origin https://localhost:19445 --allow-private-origin https://localhost:19446 --allow-private-origin https://localhost:19447
  --allow-private-origin https://localhost:19449)
lists() { # lists [lists.ts options]: as an operator's cron runs it; prints the exit code
  local rc=0
  NODE_EXTRA_CA_CERTS="$W/tls/ca.pem" bun wba-keysync/lists.ts "$W/bots.yaml" --out "$W/out" "${ORIGINS[@]}" "$@" > "$W/lists.log" 2>&1 || rc=$?
  chmod -R a+rX "$W/out"
  echo "$rc"
}
js() { bun -e "const v = JSON.parse(require('fs').readFileSync('$W/out/$1', 'utf8')); console.log($2)"; }
policy_rule() { js ids.json "9534200 + 4 * v.$1 + 3"; }

echo "== bots file -> lists.ts"
bots enforce > "$W/bots.yaml"
check "lists.ts fetches all four lists" "$(lists)" 0
check "  data files" "$(cd "$W/out/web-bot-auth-bots" && printf '%s ' *)" "denybot.data listbot.data nestbot.data sharedbot.data tokens.data "
check "  nestbot.data: the ranges inside others left out" "$(tr '\n' ' ' < "$W/out/web-bot-auth-bots/nestbot.data")" \
  "203.0.113.128/26 203.0.113.192/27 2001:db8:5::/48 2001:db8:6::/48 "
V1=$(js versions.json v.listbot.version)

echo "== the WAF with those rules ($DOCKER)"
$DOCKER build -q -f lua/wba/Dockerfile -t "$IMAGE" . >/dev/null
printf '%s\n' "SecAction \"id:9534017,phase:1,pass,nolog,t:none,setvar:'tx.wba_site_names=example.com'\"" > "$W/site.conf"
printf '%s\n' "Include /etc/modsecurity.d/bots/web-bot-auth-bots-before.conf" > "$W/include.conf"
printf '%s\n' "SecAction \"id:9534996,phase:2,pass,log,t:none,msg:'bot-probe',logdata:'name=%{tx.bot_name} status=%{tx.bot_status} reason=%{tx.bot_reason} version=%{tx.bot_list_version}'\"" > "$W/probe.conf"
# An operator's own rules, named like the README's example: the name sorts
# before web-bot-auth-bots-*, so this file shows what such rules read in phase 2.
printf '%s\n' "SecAction \"id:9534995,phase:2,pass,log,t:none,msg:'site-rule',logdata:'site saw name=%{tx.bot_name} status=%{tx.bot_status} reason=%{tx.bot_reason}'\"" > "$W/site-rules.conf"
printf 'set_real_ip_from 0.0.0.0/0;\nset_real_ip_from ::/0;\nreal_ip_header X-Real-IP;\n' > "$W/real-ip.conf"
$DOCKER run -d --name "$NAME" -p "$PORT:8443" -e BACKEND=http://127.0.0.1:9 \
  -v "$W/keys:/etc/modsecurity.d/wba/keys:ro" \
  -v "$W/out:/etc/modsecurity.d/bots:ro" \
  -v "$W/site.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-site-config.conf:ro" \
  -v "$W/include.conf:/etc/modsecurity.d/owasp-crs/plugins/web-bot-auth-bots-before.conf:ro" \
  -v "$W/probe.conf:/etc/modsecurity.d/owasp-crs/plugins/zz-bot-probe-after.conf:ro" \
  -v "$W/site-rules.conf:/etc/modsecurity.d/owasp-crs/plugins/site-wba-rules-after.conf:ro" \
  -v "$W/real-ip.conf:/etc/nginx/conf.d/00-real-ip.conf:ro" \
  "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 "https://localhost:$PORT/" || true)" != "000" ] && break
  sleep 1
done

N=0
# next: a fresh path for the next request, in $P (set here, not in the
# subshell $(req ...) runs in). req <from> <User-Agent> -> its status.
next() { N=$((N + 1)); P=/c$N; }
req() { curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H "X-Real-IP: $1" -A "$2" "https://localhost:$PORT$P" || true; }
# evidence: the probe's tx.bot_* line for the last request.
evidence() {
  sleep 1
  $DOCKER logs "$NAME" 2>&1 | grep -F "\"uri\":\"$P\"" | grep -o '"data":"name=[^"]*"' | tail -1 | sed 's/^"data":"//; s/"$//'
}
# site_saw: what site-wba-rules-after.conf read for the last request.
site_saw() {
  sleep 1
  $DOCKER logs "$NAME" 2>&1 | grep -F "\"uri\":\"$P\"" | grep -o '"data":"site saw [^"]*"' | tail -1 | sed 's/^"data":"//; s/"$//'
}
# refused_by <rule id>: yes if that rule matched in the last request's audit log entry.
refused_by() { sleep 1; $DOCKER logs "$NAME" 2>&1 | grep -F "\"uri\":\"$P\"" | grep -qF "\"ruleId\":\"$1\"" && echo yes || echo no; }

echo "== enforce mode"
next; check "listbot from its list" "$(req 192.0.2.10 'Mozilla/5.0 (compatible; ListBot/1.0)')" 502
check "  evidence" "$(evidence)" "name=listbot status=verified reason=ip-list version=$V1"
next; check "listbot from elsewhere: refused as an impostor" "$(req 203.0.113.200 'ListBot/1.0')" 403
check "  by listbot's policy rule" "$(refused_by "$(policy_rule listbot)")" yes
next; check "no claim, from listbot's list" "$(req 192.0.2.10 'curl/8.0')" 502
check "  evidence" "$(evidence)" "name= status= reason= version="
next; check "listbot over IPv6, from its list" "$(req 2001:db8:1::10 'ListBot/1.0')" 502
check "  evidence" "$(evidence)" "name=listbot status=verified reason=ip-list version=$V1"
next; check "LISTBOT in upper case" "$(req 192.0.2.10 'LISTBOT/2')" 502
check "  evidence" "$(evidence)" "name=listbot status=verified reason=ip-list version=$V1"
next; check "a token with a space and a dot" "$(req 192.0.2.10 'x Mon.itor Bot/1')" 502
check "  evidence" "$(evidence)" "name=listbot status=verified reason=ip-list version=$V1"
next; check "the dot is not a wildcard" "$(req 192.0.2.10 'x MonXitor Bot/1')" 502
check "  evidence" "$(evidence)" "name= status= reason= version="
next; check "denybot from its list: refused" "$(req 198.51.100.5 'DenyBot/1')" 403
check "  by denybot's policy rule" "$(refused_by "$(policy_rule denybot)")" yes
next; check "DenyBot claimed from elsewhere: refused" "$(req 203.0.113.200 'DenyBot/1')" 403
next; check "logbot (no list): passes" "$(req 203.0.113.200 'LogBot/1')" 502
check "  evidence" "$(evidence)" "name=logbot status=claimed reason=no-list version=none"
check "  logged by its policy rule" "$(refused_by "$(policy_rule logbot)")" yes
next; check "Shared-User from outside its list (claim only): passes" "$(req 203.0.113.200 'Shared-User/1')" 502
check "  evidence" "$(evidence)" "name=sharedbot status=claimed reason=not-in-list version=$(js versions.json v.sharedbot.version)"
next; check "Shared-User from its list" "$(req 203.0.113.10 'Shared-User/1')" 502
check "  evidence" "$(evidence)" "name=sharedbot status=verified reason=ip-list version=$(js versions.json v.sharedbot.version)"
next
check "signbot, signed" "$(bun wba-keysync/sign.ts curl "https://localhost:$PORT$P" --dir "$W/signer" --host example.com --insecure | sh)" 502
check "  evidence" "$(evidence)" "name=signbot status=verified reason=signature version=none"

echo "== load order: the operator's site-wba-rules-after.conf sees the bot list rules' final word"
next
check "signbot, signed, with its User-Agent token" \
  "$(sh -c "$(bun wba-keysync/sign.ts curl "https://localhost:$PORT$P" --dir "$W/signer" --host example.com --insecure) -A 'SignBot/1.0'")" 502
check "  site-wba-rules-after.conf reads it as verified" "$(site_saw)" "site saw name=signbot status=verified reason=signature"
next; check "SignBot claimed, unsigned" "$(req 203.0.113.9 'SignBot/1.0')" 502
check "  site-wba-rules-after.conf reads it as claimed" "$(site_saw)" "site saw name=signbot status=claimed reason=no-list"

echo "== a list with ranges inside others: the outer ranges still match"
NV=$(js versions.json v.nestbot.version)
next; check "nestbot from inside the /29 that was left out" "$(req 203.0.113.140 'NestBot/1')" 502
check "  evidence" "$(evidence)" "name=nestbot status=verified reason=ip-list version=$NV"
next; check "nestbot from the /27 beside the /26" "$(req 203.0.113.210 'NestBot/1')" 502
check "  evidence" "$(evidence)" "name=nestbot status=verified reason=ip-list version=$NV"
next; check "nestbot over IPv6, inside the /64 that was left out" "$(req 2001:db8:5:1::9 'NestBot/1')" 502
check "  evidence" "$(evidence)" "name=nestbot status=verified reason=ip-list version=$NV"
next; check "nestbot from just past its ranges" "$(req 203.0.113.230 'NestBot/1')" 502
check "  evidence" "$(evidence)" "name=nestbot status=claimed reason=not-in-list version=$NV"

echo "== the operator adds an address; lists.ts checks the files with nginx -t and reloads"
list "$W/listbot.json" 2026-10-02T00:00:00Z 192.0.2.0/24 2001:db8:1::/48 203.0.113.200
check "lists.ts with --check and --reload" "$(lists --check "$DOCKER exec $NAME nginx -t" --reload "$DOCKER exec $NAME nginx -s reload")" 0
V2=$(js versions.json v.listbot.version)
check "  a new version" "$([ "$V2" != "$V1" ] && echo "${V2%%#*}" || echo same)" 2026-10-02T00:00:00Z
sleep 2
next; check "listbot from the new address" "$(req 203.0.113.200 'ListBot/1.0')" 502
check "  evidence carries the new version" "$(evidence)" "name=listbot status=verified reason=ip-list version=$V2"

echo "== listbot's server breaks: the previous version stays"
printf '{"status":404}\n' > "$W/listbot.json.ctl"
check "lists.ts says so (exit 2)" "$(lists --check "$DOCKER exec $NAME nginx -t" --reload "$DOCKER exec $NAME nginx -s reload")" 2
check "  kept" "$(grep -c "kept  listbot: HTTP 404; keeping version $V2" "$W/lists.log")" 1
sleep 2
next; check "listbot from the new address still verified" "$(req 203.0.113.200 'ListBot/1.0')" 502
check "  evidence" "$(evidence)" "name=listbot status=verified reason=ip-list version=$V2"
rm "$W/listbot.json.ctl"

echo "== log mode"
bots log > "$W/bots.yaml"
check "lists.ts, policy_mode log" "$(lists --check "$DOCKER exec $NAME nginx -t" --reload "$DOCKER exec $NAME nginx -s reload")" 0
sleep 2
next; check "listbot from elsewhere: passes" "$(req 2001:db8:2::1 'ListBot/1.0')" 502
check "  logged by listbot's policy rule" "$(refused_by "$(policy_rule listbot)")" yes
check "  evidence" "$(evidence)" "name=listbot status=claimed reason=not-in-list version=$V2"
next; check "denybot from its list: passes" "$(req 198.51.100.5 'DenyBot/1')" 502

DONE=1
if [ "$FAIL" = 0 ]; then echo "== BOT LISTS WORK END TO END"; else echo "== BOT LISTS FAILED"; exit 1; fi
