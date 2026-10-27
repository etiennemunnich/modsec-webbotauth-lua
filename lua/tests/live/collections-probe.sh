#!/usr/bin/env bash
# collections-probe.sh: why replay.lua counts with O_APPEND instead of
# libmodsecurity's persistent collections. Three runs of a CRS nginx image,
# each counting requests in a rule or a Lua script:
#   1. as shipped: initcol/setvar on RESOURCE (LMDB)  -> the count never rises
#   2. nginx working directory writable (-w /tmp)     -> concurrent increments lost
#   3. Lua O_APPEND counter (replay.lua's method)     -> every request its own count
# Prints what it measured; exits 1 if run 3 loses or repeats a count.
#
#   lua/tests/live/collections-probe.sh   (Finch by default; DOCKER=docker for Docker)
#   CRS_IMAGE=owasp/modsecurity-crs:<tag> lua/tests/live/collections-probe.sh
set -euo pipefail
DOCKER=${DOCKER:-finch}
IMG=${CRS_IMAGE:-owasp/modsecurity-crs:4.30.0-nginx-202610180210}
PORT=${PORT:-18897}
N=${N:-200}
NAME=wba-collections-probe-$$
WORK=$(mktemp -d)
COMPLETED=0
cleanup() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  # bash 3.2 (macOS) exits 0 when set -u aborts a script that has an EXIT
  # trap, and $? reads 0 inside the trap: only reaching the end is success.
  [ "$COMPLETED" = 1 ] || { echo "== ABORTED"; exit 1; }
}
trap cleanup EXIT

cat > "$WORK/lmdb.conf" <<'EOF'
SecAction "id:9534980,phase:1,pass,nolog,t:none,initcol:resource=wba-probe"
SecAction "id:9534981,phase:1,pass,nolog,t:none,setvar:resource.n=+1,expirevar:resource.n=600"
SecRule REQUEST_HEADERS:X-Probe "@rx ^(.*)$" "id:9534982,phase:1,deny,status:403,log,t:none,capture,msg:'PROBE case=%{TX.1} n=%{resource.n}'"
EOF
cat > "$WORK/append.lua" <<'EOF'
function main()
    local f = io.open("/tmp/wba-append-probe", "ab")
    if not f then m.setvar("tx.n", "open-failed") return nil end
    f:setvbuf("no")
    f:write("x")
    m.setvar("tx.n", tostring(f:seek("cur")))
    f:close()
    return nil
end
EOF
cat > "$WORK/append.conf" <<'EOF'
SecRuleScript /etc/modsecurity.d/append.lua "id:9534990,phase:1,pass,nolog"
SecRule REQUEST_HEADERS:X-Probe "@rx ^(.*)$" "id:9534983,phase:1,deny,status:403,log,t:none,capture,msg:'PROBE case=%{TX.1} n=%{tx.n}'"
EOF

run() { # conf, extra run args...
  local conf=$1; shift
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  $DOCKER run -d --name "$NAME" -p "$PORT:8080" -e BACKEND=http://127.0.0.1:9 \
    -v "$WORK/$conf:/etc/modsecurity.d/owasp-crs/plugins/zz-probe-after.conf:ro" \
    -v "$WORK/append.lua:/etc/modsecurity.d/append.lua:ro" "$@" "$IMG" >/dev/null
  for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$PORT/" || true)" != "000" ] && break
    sleep 1
  done
  seq 1 "$N" | xargs -P 50 -I{} curl -s -o /dev/null -H "X-Probe: c{}" "http://127.0.0.1:$PORT/"
  sleep 2
  $DOCKER logs "$NAME" 2>&1 | grep -o "PROBE case=c[0-9]* n=[0-9a-z-]*" | sort -u | sed 's/.*n=//' > "$WORK/counts" || true
}
summary() { # label
  local total distinct max
  total=$(grep -c . "$WORK/counts" || true); distinct=$(sort -u "$WORK/counts" | grep -c . || true)
  max=$(grep -E '^[0-9]+$' "$WORK/counts" | sort -n | tail -1 || true)
  echo "$1: $N concurrent requests, $total counts logged, $distinct distinct, highest ${max:-none}"
}

echo "== $IMG"
run lmdb.conf
summary "1. LMDB collection, image as shipped (nginx cwd /)"
run lmdb.conf -w /tmp
summary "2. LMDB collection, nginx cwd /tmp (writable)"
run append.conf
summary "3. O_APPEND counter in Lua"
distinct=$(sort -u "$WORK/counts" | grep -cE '^[0-9]+$' || true)
COMPLETED=1
# Run 3 counted every request once: N distinct counts (one more request, the
# readiness probe, may come first, so the counts run 1..N or 2..N+1).
[ "$distinct" = "$N" ] && echo "== O_APPEND exact" || { echo "== O_APPEND lost or repeated a count"; exit 1; }
