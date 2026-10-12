#!/usr/bin/env bash
# pcre-limit.sh: does ModSecurity's regular expression work limit refuse real
# signed requests at 1,000, the value in ModSecurity's sample configuration?
# GETTING-STARTED.md uses 100000, the CRS image's value. This builds the
# page's Debian 13 server (debian-page.sh runs the page as written), then
# sends the same requests with both limits at 100000 and at 1000, at CRS
# paranoia levels 1 and 4:
#   - signed by gen.lua (openssl): Ed25519, RSA-PSS with a 2048-bit key and
#     with a 4096-bit key (the longest Signature header), each on a GET and on
#     a POST whose JSON body's Content-Digest is signed;
#   - signed by the page's test bot (wba-keysync/sign.ts);
#   - unsigned: a browser's page request, a search with a query string, a
#     login form, a JSON API call, and /agents/hello (recipe A refuses it).
# For each it records the HTTP status, the rule that refused it, and every
# regular expression that hit the limit (debug log level 4 names the rule and
# what it read; rule 9534990 flags the request in the audit log). Checked:
# no request hits the limit at either value, and each gets the same status at
# both. Then, recorded only: how low the limit can go at PL4 before the first
# hit. Last, where rule 200005 looks: a test rule that hits the limit in
# phase 2 is not refused (200005 runs at the start of phase 2, before it), the
# same rule in phase 1 is refused by 200005, and a copy of 200005 placed after
# CRS refuses the phase 2 hit.
#
#   bash lua/tests/live/pcre-limit.sh                         (Finch)
#   DOCKER=docker bash lua/tests/live/pcre-limit.sh           (Docker)
#   REPORT=path bash lua/tests/live/pcre-limit.sh             also write the tables there
# Needs what getting-started.sh needs. Ports 18986 (HTTP) and 18987 (HTTPS).
# Not part of run_all.sh. Results: lua/wba/evidence/pcre-match-limit.md.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LUA=${LUA:-lua}
if command -v node >/dev/null; then JS=node; else JS=bun; fi
NAME=wba-pcre-limit-$$
HTTP_PORT=${HTTP_PORT:-18986} HTTPS_PORT=${HTTPS_PORT:-18987}
# shellcheck source=debian-page.sh
. "$HERE/debian-page.sh"

run_page
echo "== the probe (test only: rule 9534990, the debug log, gen.lua's keys)"
mkdir -p "$WORK/gen" "$WORK/r"
OUT="$WORK/gen" MODE=keys RSA4096=1 "$LUA" "$HERE/gen.lua"
grep -v '^#' "$WORK/gen/keys/wba-keys.tsv" | $DOCKER exec -i "$NAME" sh -c 'cat >> /etc/modsecurity.d/wba/keys/wba-keys.tsv'
server 'install -o www-data -g adm -m 640 /dev/null /var/log/nginx/modsec_debug.log'
$DOCKER exec -i "$NAME" sh -c 'cat > /etc/modsecurity.d/owasp-crs/plugins/zz-pcre-probe-after.conf' <<'EOF'
# pcre-limit.sh: name every regular expression that hits the match limit
# (debug level 4: "(Rule: N) Executing operator ... against VAR", then level
# 1: "rx: regex error 'MATCH_LIMIT'"), and flag the request in the audit log.
SecDebugLog /var/log/nginx/modsec_debug.log
SecDebugLogLevel 4
SecRule TX:MSC_PCRE_LIMITS_EXCEEDED "@streq 1" \
    "id:9534990,phase:5,pass,log,auditlog,t:none,msg:'probe: a regular expression hit the match limit'"
EOF

# limit N: both PCRE limits in the page's modsecurity.conf, then a reload.
limit() {
  server "sed -i -E 's/^(SecPcreMatchLimit(Recursion)?) [0-9]+\$/\\1 $1/' /etc/modsecurity.d/modsecurity.conf &&
    [ \$(grep -cE '^SecPcreMatchLimit(Recursion)? $1\$' /etc/modsecurity.d/modsecurity.conf) = 2 ] &&
    nginx -t >/dev/null 2>&1 && nginx -s reload 2>/dev/null && sleep 2" || { echo "FAIL  could not set both limits to $1"; exit 1; }
}
BROWSER=(-H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
  -H 'Accept-Language: en-AU,en;q=0.9' -H 'Accept-Encoding: gzip, deflate, br, zstd'
  -H 'Cookie: session=3f9a2c7e1b4d; theme=dark' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate'
  -H 'Sec-Fetch-Site: none' -H 'Upgrade-Insecure-Requests: 1')
API='{"query": "weather in Sydney tomorrow", "page": 2, "filters": {"lang": "en-AU", "safe": true}}'
# send TAG: one request; prints its HTTP status. Every request carries
# X-WBA-Test: TAG, so its audit log entry can be found.
send() {
  local u=(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H "X-WBA-Test: $1")
  case "$1" in
    pcre-*) OUT="$WORK/gen" MODE=send CASE=$1 BASE_URL=https://example.com CURL_HOME="$WORK/home" "$LUA" "$HERE/gen.lua" \
              | awk -v c="$1" '$1 == c { print $2 }' ;;
    sign-ts) machine "bun wba-keysync/sign.ts curl https://example.com/agents/hello --dir ~/wba-test --insecure | sed \"s/^curl /curl -H 'X-WBA-Test: sign-ts' /\" | sh" ;;
    page-home) CURL_HOME="$WORK/home" "${u[@]}" "${BROWSER[@]}" https://example.com/ ;;
    page-search) CURL_HOME="$WORK/home" "${u[@]}" "${BROWSER[@]}" 'https://example.com/search?q=red+running+shoes&size=10&sort=price_asc&page=2' ;;
    page-form) CURL_HOME="$WORK/home" "${u[@]}" "${BROWSER[@]}" https://example.com/login \
                 --data 'username=alice%40example.com&password=correct+horse+battery+staple&remember=on' ;;
    page-json) CURL_HOME="$WORK/home" "${u[@]}" -H 'Content-Type: application/json' --data "$API" https://example.com/api/search ;;
    page-agents) CURL_HOME="$WORK/home" "${u[@]}" https://example.com/agents/hello ;;
  esac
}
REQUESTS="pcre-ed25519 pcre-ed25519-body pcre-rsa-pss pcre-rsa-pss-body pcre-rsa4096 pcre-rsa4096-body sign-ts page-home page-search page-form page-json page-agents"
describe() {
  case "$1" in
    pcre-ed25519) echo "signed, Ed25519, GET /agents/hello" ;;
    pcre-ed25519-body) echo "signed, Ed25519, POST /api/search with a signed JSON body" ;;
    pcre-rsa-pss) echo "signed, RSA-PSS 2048-bit key, GET /agents/hello" ;;
    pcre-rsa-pss-body) echo "signed, RSA-PSS 2048-bit key, POST with a signed JSON body" ;;
    pcre-rsa4096) echo "signed, RSA-PSS 4096-bit key, GET /agents/hello" ;;
    pcre-rsa4096-body) echo "signed, RSA-PSS 4096-bit key, POST with a signed JSON body" ;;
    sign-ts) echo "signed by the page's test bot (sign.ts, Ed25519, with a nonce), GET /agents/hello" ;;
    page-home) echo "unsigned, a browser's request for /" ;;
    page-search) echo "unsigned, a browser's search, GET /search?q=red+running+shoes&size=10&sort=price_asc&page=2" ;;
    page-form) echo "unsigned, a browser's login form, POST /login" ;;
    page-json) echo "unsigned, a JSON API call, POST /api/search" ;;
    page-agents) echo "unsigned, GET /agents/hello (recipe A asks for a signature)" ;;
  esac
}

# probe LIMIT PL TAG: send TAG, then append to $WORK/results.tsv:
#   limit pl tag status refused-by hits wba
# refused-by: the rule in nginx's error log "Access denied" line, and the CRS
# rules the audit log lists; hits: "rule:variable" for each regular
# expression that hit the limit; wba: the plugin's status/reason, if it wrote
# a line.
probe() {
  local n w st denied hits wba crs
  server ': > /var/log/nginx/modsec_debug.log'
  n=$(server 'wc -l < /var/log/nginx/error.log' | tr -d ' ')
  w=$(server 'wc -l < /var/log/nginx/wba.log' | tr -d ' ')
  st=$(send "$3")
  sleep 1
  denied=$(server "tail -n +$((n + 1)) /var/log/nginx/error.log" | grep -F 'Access denied' | grep -oE '\[id "[0-9]+"\]' | grep -oE '[0-9]+' | paste -sd, - || true)
  hits=$(server 'cat /var/log/nginx/modsec_debug.log' | awk '
    /\(Rule: [0-9]+\) Executing operator/ { r = $0; sub(/.*\(Rule: /, "", r); sub(/\).*/, "", r); v = $0; sub(/.* against /, "", v); sub(/\.$/, "", v) }
    /regex error .MATCH_LIMIT./ { printf "%s%s:%s", sep, r, v; sep = "," }')
  wba=-
  if [ "$(server 'wc -l < /var/log/nginx/wba.log' | tr -d ' ')" != "$w" ]; then
    wba=$(server 'tail -n 1 /var/log/nginx/wba.log' | sed -n 's/.*"status":"\([a-z-]*\)","reason":"\([a-z-]*\)".*/\1\/\2/p')
  fi
  crs=$(server 'cat /var/log/nginx/modsec_audit.json' | TAG=$3 $JS "$HERE/audit-entry.ts" | grep -oE '^[0-9]{6} \(PL[0-9]\)' | cut -d' ' -f1 | paste -sd, - || true)
  [ -n "$crs" ] && denied="${denied:-}${denied:+ }(CRS: $crs)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${st:-000}" "${denied:--}" "${hits:--}" "$wba" >> "$WORK/results.tsv"
  echo "      limit $1, PL$2, $3: HTTP ${st:-000}; refused by ${denied:--}; limit hits ${hits:-none}; wba.log $wba"
}
round() { # LIMIT PL
  echo "== both limits $1, paranoia level $2"
  limit "$1"
  for r in $REQUESTS; do probe "$1" "$2" "$r"; done
}
row() { awk -F'\t' -v l="$1" -v p="$2" -v t="$3" '$1 == l && $2 == p && $3 == t' "$WORK/results.tsv"; }
compare() { # PL: each request at 1000 against 100000
  local r a b
  for r in $REQUESTS; do
    a=$(row 100000 "$1" "$r") b=$(row 1000 "$1" "$r")
    check "PL$1 $r: no regular expression hit the limit at 100000 or at 1000" "$(echo "$a" | cut -f6)/$(echo "$b" | cut -f6)" "-/-"
    check "PL$1 $r: the same status at 1000 as at 100000 ($(echo "$a" | cut -f4))" "$(echo "$b" | cut -f4)" "$(echo "$a" | cut -f4)"
    case "$r" in pcre-*|sign-ts) check "PL$1 $r: verified at 1000" "$(echo "$b" | cut -f7)" "verified/" ;; esac
  done
}

round 100000 1
round 1000 1
compare 1
echo "== paranoia level 4 (the page's optional block)"
run_blocks optional
round 1000 4
round 100000 4
compare 4

echo "== how low can the limit go at PL4? (recorded, not checked)"
for l in 500 250 120 60 40; do round "$l" 4; done

echo "== where rule 200005 looks (both limits 1000)"
# A test rule whose regular expression, ^(a+)+$, does about 2^n steps on n
# letters "a" followed by "b": with the limit at 1000 it gives up, and its
# answer is "no match". Rule 200005 checks the flag that sets once, at the
# start of phase 2, so it sees a hit from phase 1 and never one from phase 2.
limit 1000
order() { # PHASE [extra rule] [probe value]: install the test rule, send the probe, print "<status> <refusing rule or ->"
  printf '%s\n%s\n' "SecRule ARGS_GET:probe \"@rx ^(a+)+\$\" \"id:9534991,phase:$1,deny,status:418,log,t:none,msg:'probe: the test regex matched'\"" "${2:-}" \
    | $DOCKER exec -i "$NAME" sh -c 'cat > /etc/modsecurity.d/owasp-crs/plugins/zz-order-probe-after.conf'
  server 'nginx -t >/dev/null 2>&1 && nginx -s reload 2>/dev/null && sleep 2'
  local n st by
  n=$(server 'wc -l < /var/log/nginx/error.log' | tr -d ' ')
  st=$(CURL_HOME="$WORK/home" curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://example.com/?probe=${3:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab}")
  sleep 1
  by=$(server "tail -n +$((n + 1)) /var/log/nginx/error.log" | grep -F 'Access denied' | grep -oE '\[id "[0-9]+"\]' | grep -oE '[0-9]+' | paste -sd, - || true)
  echo "$st ${by:--}"
}
check "the test rule matches 'aaaa' (no limit hit): 418 from it" "$(order 2 '' aaaa)" "418 9534991"
check "phase 2: the test regex hits the limit; nothing refuses the request" "$(order 2)" "200 -"
check "phase 1: the same hit; rule 200005 refuses" "$(order 1)" "403 200005"
check "phase 2, with a copy of 200005 after CRS: that copy refuses" \
  "$(order 2 "SecRule TX:/^MSC_/ \"!@streq 0\" \"id:9534992,phase:2,deny,log,t:none,msg:'probe: ModSecurity internal error flagged after CRS: %{MATCHED_VAR_NAME}'\"")" "403 9534992"
server 'rm -f /etc/modsecurity.d/owasp-crs/plugins/zz-order-probe-after.conf'

echo "== versions"
server 'nginx -v 2>&1; dpkg-query -W libmodsecurity3t64 libnginx-mod-http-modsecurity libpcre2-8-0 liblua5.3-0
  sed -n "s/.*ver:.OWASP_CRS\/\([0-9.]*\).*/CRS \1/p" /etc/modsecurity.d/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf | head -n 1' | tee "$WORK/versions.txt"
report() {
  echo "Versions: $(paste -sd';' "$WORK/versions.txt" | sed 's/;/; /g')"
  echo
  echo "| Both limits | PL | Request | HTTP | Refused by | Regular expressions that hit the limit | wba.log |"
  echo "|---|---|---|---|---|---|---|"
  local l p t st by hits wba
  while IFS=$'\t' read -r l p t st by hits wba; do
    case "$l" in 100000|1000) ;; *) continue ;; esac
    [ "$hits" = - ] && hits=none
    echo "| $l | $p | $(describe "$t") | $st | $by | $hits | $wba |"
  done < "$WORK/results.tsv"
  echo
  echo "| Both limits, PL 4 | Requests refused by rule 200005 | Signed requests among them | Regular expressions that hit the limit (rule:what it read) |"
  echo "|---|---|---|---|"
  for l in 500 250 120 60 40; do
    awk -F'\t' -v l="$l" '$1 == l {
        n++; if ($5 ~ /(^|[ ,])200005([ ,]|$)/) { bad++; if ($3 ~ /^(pcre-|sign-ts)/) sig++ }
        split($6, h, ","); for (i in h) if (h[i] != "-") seen[h[i]] = 1 }
      END { s = ""; for (k in seen) s = s (s == "" ? "" : ", ") k
            printf "| %s | %d of %d | %d of 7 | %s |\n", l, bad, n, sig, (s == "" ? "none" : s) }' "$WORK/results.tsv"
  done
}
echo "== the results, as Markdown"
report | tee "${REPORT:-/dev/null}"
finish "PCRE LIMIT PROBE DONE: 1000 REFUSES NO REQUEST IT TRIED" "PCRE LIMIT PROBE FOUND A DIFFERENCE"
