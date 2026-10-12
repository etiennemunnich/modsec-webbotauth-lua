#!/usr/bin/env bash
# getting-started.sh: runs lua/wba/GETTING-STARTED.md as written on a clean
# Debian 13 container, then checks what it printed and what the server
# logged. The commands are read from the page itself, so the page cannot
# drift from what works. debian-page.sh runs the page and says which block
# runs where, and what the test stands in for.
#
# After the page: a signed POST whose signature covers its body's digest, and
# the same request with one byte of the body changed; the signed requests
# again at paranoia level 4 (the page's optional block); log rotation (wba.log
# needs no signal; the audit log needs copytruncate); and last, the page's
# "behind a load balancer" blocks, with a fifth stand-in, your load balancer:
# an nginx server in the same container on port 8443 that ends TLS with the
# page's test certificate and connects to nginx's port 80 from 192.0.2.10,
# the address the page trusts. (That address is added to the container's
# loopback interface, so the container gets NET_ADMIN.)
#
#   bash lua/tests/live/getting-started.sh                (Finch)
#   DOCKER=docker bash lua/tests/live/getting-started.sh  (Docker)
# Needs: the container CLI, bun, Lua and openssl (gen.lua signs the body
# requests), curl with HTTP/2, and network access from the container (Debian
# mirrors, GitHub, coreruleset.org). Ports 18996 (HTTP), 18997 (HTTPS) and
# 18998 (the load balancer).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LUA=${LUA:-lua}
NAME=wba-getting-started-$$
LB_PORT=18998
# shellcheck disable=SC2034 # read by debian-page.sh, which this script sources
RUN_OPTS=(-p "$LB_PORT:8443" --cap-add NET_ADMIN)
# shellcheck source=debian-page.sh
. "$HERE/debian-page.sh"

run_page

echo "== what the page printed"
o=$(out_of "-D - https://example.com/agents/hello")
check "unsigned request to /agents/hello" "$(grep -m1 '^HTTP/' "$o" | tr -d '\r' | sed 's/ *$//')" "HTTP/2 403"
has "  ... asking for a signature (Accept-Signature)" "$o" "accept-signature: sig1=("
o=$(out_of "/etc/passwd&bar=/bin/sh")
check "CRS refuses ?foo=/etc/passwd&bar=/bin/sh" "$(tr -d '\r\n' < "$o")" 403
o=$(out_of "sign.ts curl https://example.com/agents/hello")
check "signed by the test bot, HTTP/1.1" "$(sed -n 1p "$o")" 200
check "signed by the test bot, HTTP/2" "$(sed -n 2p "$o")" 200
o=$(out_of "sign.ts curl http://example.com/agents/hello")
check "signed, over plain HTTP (the guard)" "$(tr -d '\r\n' < "$o")" 400
o=$(out_of "Host: other.example")
check "a name this server does not serve (the catch-all)" "$(tr -d '\r\n' < "$o")" 421
o=$(out_of "runuser -u www-data")
check "www-data reads the key store" "$(head -n 1 "$o")" "# wba-keys v2"
o=$(out_of "tail -n 2 /var/log/nginx/wba.log")
VERIFIED='"status":"verified","reason":"","agent":"https://test-agent.example/.well-known/http-message-signatures-directory"'
check "wba.log: verified lines for the test bot" "$(grep -cF "$VERIFIED" "$o" || true)" 2
has "access log: the HTTP/1.1 request reached the application (200)" "$o" '"GET /agents/hello HTTP/1.1" 200'
has "access log: the HTTP/2 request reached the application (200)" "$o" '"GET /agents/hello HTTP/2.0" 200'
has "error log: recipe A refused with 460" "$o" 'Access denied with code 460'
has "  ... and names rule 9534130" "$o" '[id "9534130"]'
has "error log: CRS refused (949110)" "$o" '[id "949110"]'

echo "== the server"
if server 'nginx -t' >"$WORK/nginx-t.txt" 2>&1; then pass "nginx -t"; else fail "nginx -t:"; sed 's/^/      /' "$WORK/nginx-t.txt"; fi
has "nginx -t names ModSecurity-nginx 1.0.3" "$WORK/nginx-t.txt" "ModSecurity-nginx v1.0.3"
# audit_ids: "<lines> <rule ids> <uri=status[ids] per entry>" for the audit log;
# fails unless every line is JSON.
audit_ids() {
  server 'cat /var/log/nginx/modsec_audit.json' > "$WORK/audit.json"
  AUDIT="$WORK/audit.json" bun -e '
    const lines = (await Bun.file(process.env.AUDIT).text()).split("\n").filter(Boolean);
    const ids = new Set(), each = [];
    for (const l of lines) {
      const t = JSON.parse(l).transaction, own = (t.messages ?? []).map((m) => m.details.ruleId);
      own.forEach((id) => ids.add(id));
      each.push(`${t.request?.uri}=${t.response?.http_code}[${own.join(",")}]`);
    }
    console.log(lines.length, [...ids].sort().join(",") || "-", each.join(" "));
  '
}
if a=$(audit_ids 2>&1); then
  pass "audit log: ${a%% *} lines, each one JSON"
  ids=$(echo "$a" | awk '{print $2}')
  # Pinned, as the page says: through the Accept-Signature error_page, Debian's
  # 3.0.14 + 1.0.3 log the refusal with status 403 and no rules (the image lists them).
  case " $a " in *" /agents/hello=403[] "*) pass "audit log: recipe A's refusal, 403, no rules listed (as the page says)";;
    *) fail "audit log: want /agents/hello=403[] (403, no rules): $a";; esac
  case ",$ids," in *,949110,*) pass "audit log: CRS's refusal (949110)";; *) fail "audit log has no 949110: $a";; esac
else
  fail "audit log is not one JSON object per line: $a"
fi
check "TLS by address, so no name: the catch-all refuses the handshake" \
  "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:$HTTPS_PORT/" || true)" 000

# wba_last: "<method> <status>/<reason> <client_ip>" from the last line in wba.log.
wba_last() {
  sleep 1
  server 'tail -n 1 /var/log/nginx/wba.log' \
    | sed -n 's/.*"client_ip":"\([^"]*\)","method":"\([A-Z]*\)".*"status":"\([a-z-]*\)","reason":"\([a-z-]*\)".*/\2 \3\/\4 \1/p'
}
wba_lines() { server 'wc -l < /var/log/nginx/wba.log' | tr -d ' '; }

echo "== a signed request with a body (POST, Content-Digest)"
# gen.lua signs with openssl, independently of the plugin and of sign.ts: its
# signature covers @authority, Content-Digest (the body's sha-256, RFC 9530)
# and Signature-Agent. Its keys join the test bot's in the key store.
mkdir -p "$WORK/gen"
OUT="$WORK/gen" MODE=keys "$LUA" "$HERE/gen.lua"
grep -v '^#' "$WORK/gen/keys/wba-keys.tsv" | $DOCKER exec -i "$NAME" sh -c 'cat >> /etc/modsecurity.d/wba/keys/wba-keys.tsv'
# gen CASE: one gen.lua case, sent to example.com (the curlrc maps it); prints its HTTP status.
gen() {
  OUT="$WORK/gen" MODE=send CASE=$1 BASE_URL=https://example.com CURL_HOME="$WORK/home" "$LUA" "$HERE/gen.lua" \
    | awk -v c="$1" '$1 == c { print $2 }'
}
for v in 1.1 2; do
  [ "$v" = 2 ] && sfx=-h2 || sfx=""
  c=body-match; [ "$v" = 2 ] && c=body-h2
  check "POST, its body signed (HTTP/$v): reaches the application" "$(gen "$c")" 200
  r=$(wba_last)
  check "  ... wba.log" "${r% *}" "POST verified/"
  check "the same POST, one byte of its body changed (HTTP/$v): refused" "$(gen "body-one-byte$sfx")" 403
  r=$(wba_last)
  check "  ... wba.log" "${r% *}" "POST invalid/digest-mismatch"
  check "  ... error log: the rule that refused it" \
    "$(server 'grep -F "Access denied" /var/log/nginx/error.log | tail -n 1' | grep -oE '\[id "[0-9]+"\] \[rev "[^"]*"\] \[msg "[^"]*"\]' | sed -E 's/ \[rev "[^"]*"\]//')" \
    '[id "9534135"] [msg "Web Bot Auth: a signature that cannot be genuine (digest-mismatch)"]'
done

echo "== paranoia level 4 (the page's optional block)"
run_blocks optional
check "PL 4 is on: CRS 920274 refuses '(\"@...\")' in another header" \
  "$(machine "curl -sk -o /dev/null -w '%{http_code}' -H 'X-Probe: (\"@authority\")' https://example.com/")" 403
sleep 1
server 'tail -n 1 /var/log/nginx/modsec_audit.json' > "$WORK/last.json"
has "  ... audit log names rule 920274" "$WORK/last.json" '"ruleId":"920274"'
for v in 1.1 2; do
  check "PL 4: signed by the test bot, HTTP/$v" "$(machine "bun wba-keysync/sign.ts curl https://example.com/agents/hello --dir ~/wba-test --insecure | sed 's/^curl /curl --http$v /' | sh")" 200
done
sleep 1
server 'tail -n 2 /var/log/nginx/wba.log' > "$WORK/wba-pl4.txt"
check "PL 4: wba.log verified lines" "$(grep -cF "$VERIFIED" "$WORK/wba-pl4.txt" || true)" 2

echo "== log rotation"
# Renaming the audit log does not move ModSecurity to the new file, even with
# a reload: why the page rotates it with copytruncate.
server 'cd /var/log/nginx && mv modsec_audit.json modsec_audit.moved && install -o root -g adm -m 640 /dev/null modsec_audit.json && nginx -s reload 2>/dev/null && sleep 2'
machine "curl -sk -o /dev/null https://example.com/agents/hello"
sleep 1
check "renamed audit log, then nginx -s reload: the new file stays empty" "$(server 'wc -c < /var/log/nginx/modsec_audit.json' | tr -d ' ')" 0
server 'mv /var/log/nginx/modsec_audit.moved /var/log/nginx/modsec_audit.json'
# Rotate with the page's configuration and Debian's own (postrotate cannot
# signal nginx here: the image's policy-rc.d refuses it, so no signal at all).
server 'logrotate -f /etc/logrotate.d/nginx /etc/logrotate.d/modsecurity-audit'
machine "bun wba-keysync/sign.ts curl https://example.com/agents/hello --dir ~/wba-test --insecure | sh" >/dev/null
machine "curl -sk -o /dev/null https://example.com/agents/hello"
sleep 1
server 'ls /var/log/nginx' > "$WORK/logs.txt"
has "wba.log was rotated (wba.log.1)" "$WORK/logs.txt" "wba.log.1"
check "rotated wba.log: the next line is in the new file, no signal" \
  "$(server 'grep -cF "\"status\":\"verified\"" /var/log/nginx/wba.log' || true)" 1
has "audit log was rotated (modsec_audit.json.1)" "$WORK/logs.txt" "modsec_audit.json.1"
if a=$(audit_ids 2>&1) && [ "${a%% *}" -ge 1 ]; then
  pass "copytruncate: the next audit entry is in the emptied file, as JSON (${a%% *} lines)"
else
  fail "copytruncate: no JSON entry in the emptied audit log: ${a:-<nothing>}"
fi

echo "== behind a load balancer (the page's last blocks)"
# Your load balancer (a test stand-in, not part of the page): TLS on port 8443
# with the page's test certificate; connects to nginx's port 80 from
# 192.0.2.10, the address the page's real-IP file trusts; adds the client's
# address to X-Forwarded-For and sets X-Forwarded-Proto, replacing any the
# client sent. Its log records the address each client connected from.
server 'apt-get install -y --no-install-recommends iproute2 >/dev/null 2>&1 && ip address add 192.0.2.10/32 dev lo'
$DOCKER exec -i "$NAME" sh -c 'cat > /etc/nginx/conf.d/zz-test-load-balancer.conf' <<'EOF'
log_format test_load_balancer '$remote_addr';
server {
    listen 8443 ssl;
    server_name example.com;
    ssl_certificate     /etc/nginx/tls/example.com.crt;
    ssl_certificate_key /etc/nginx/tls/example.com.key;
    access_log /var/log/nginx/test-load-balancer.log test_load_balancer;
    location / {
        proxy_pass http://192.0.2.10:80;
        proxy_bind 192.0.2.10;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
run_blocks lb
mkdir -p "$WORK/lb"
printf 'connect-to = example.com:443:127.0.0.1:%s\n' "$LB_PORT" > "$WORK/lb/.curlrc"
# lb COMMAND: a machine command whose https://example.com goes through the load balancer.
lb() { (cd "$REPO" && HOME="$WORK/home" CURL_HOME="$WORK/lb" bash -euo pipefail -c "$1"); }
SIGN='bun wba-keysync/sign.ts curl https://example.com/agents/hello --dir ~/wba-test --insecure'
client() { sleep 1; server 'tail -n 1 /var/log/nginx/test-load-balancer.log'; }

check "unsigned request to /agents/hello, through the load balancer" \
  "$(lb "curl -sk -o /dev/null -w '%{http_code}' https://example.com/agents/hello")" 403
check "signed by the test bot, through the load balancer" "$(lb "$SIGN | sh")" 200
r=$(wba_last) ip=$(client)
check "  ... wba.log" "${r% *}" "GET verified/"
check "  ... wba.log client_ip is the client's address, as the load balancer saw it" "${r##* }" "$ip"
if [ -n "$ip" ] && [ "$ip" != 192.0.2.10 ]; then pass "  ... which is not the load balancer's (192.0.2.10): $ip"
else fail "  ... client address '$ip' is empty or the load balancer's"; fi
check "signed, the client sending its own X-Forwarded-For: 203.0.113.66" \
  "$(lb "$SIGN | sed \"s/^curl /curl -H 'X-Forwarded-For: 203.0.113.66' /\" | sh")" 200
r=$(wba_last)
check "  ... wba.log client_ip is still the client's real address (real_ip_recursive)" "${r##* }" "$ip"
# A signature made for other.example, replayed to example.com: Host is
# example.com again (sign.ts --host signs and sends other.example).
check "signed for other.example, sent to example.com, through the load balancer" \
  "$(lb "bun wba-keysync/sign.ts curl https://example.com/ --dir ~/wba-test --insecure --host other.example | sed \"s/'Host: other.example'/'Host: example.com'/\" | sh")" 403
r=$(wba_last)
check "  ... wba.log: not verified" "${r% *}" "GET invalid/bad-signature"
n=$(wba_lines)
check "signed for other.example and sent as other.example: the catch-all" \
  "$(lb "bun wba-keysync/sign.ts curl https://example.com/ --dir ~/wba-test --insecure --host other.example | sh")" 421
check "  ... never reached ModSecurity (no new wba.log line)" "$(wba_lines)" "$n"
check "signed, straight to nginx's port 80 (no load balancer, so no X-Forwarded-Proto): the guard" \
  "$(machine "bun wba-keysync/sign.ts curl http://example.com/agents/hello --dir ~/wba-test | sh")" 400

finish "GETTING STARTED WORKS AS WRITTEN" "GETTING STARTED FAILED"
