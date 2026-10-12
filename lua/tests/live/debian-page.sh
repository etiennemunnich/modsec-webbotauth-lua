# shellcheck shell=bash
# debian-page.sh: sourced by getting-started.sh and pcre-limit.sh, never run
# alone. Starts a clean Debian 13 container and runs lua/wba/GETTING-STARTED.md
# in it as written; the scripts that source it then check what it did. The
# commands are read from the page itself, so the page cannot drift from what
# works.
#
# Which block runs where is set by its first line, as the page says:
#   "# On the server"                             as root in the container, in page order
#   "# On your machine"                           here, from the repository root, in page order
#   "# On the server (optional)"                  run_blocks optional (paranoia level 4)
#   "# On the server (behind a load balancer)"    run_blocks lb
# Any other block is not run. The test stands in for four things the page
# leaves to the reader, and changes nothing else:
#   - your application: an nginx server on 127.0.0.1:8080 that answers 200,
#     written before the page runs (conf.d/zz-test-application.conf);
#   - DNS: a curlrc sends example.com to the container's published ports;
#   - systemd: the container has none; a systemctl stand-in starts nginx or
#     reloads it;
#   - scp: a stand-in copies the file into the container.
# (getting-started.sh adds a fifth, your load balancer, for the "behind a load
# balancer" blocks.) Machine blocks run with HOME set to a scratch directory,
# so the test bot's private key (~/wba-test) never lands in your own home.
#
# Before sourcing, set NAME (the container's name); optionally HTTP_PORT and
# HTTPS_PORT, and RUN_OPTS (an array of extra options for "run").
# KEEP=1 leaves the container running at the end, to look around in it.
# Then: run_page (the server and machine blocks), run_blocks optional|lb,
# out_of TEXT, machine COMMAND, server COMMAND, check, has, pass, fail, and
# finish (prints the totals and exits). The EXIT trap removes the container
# and the scratch directory $WORK.
export DOCKER=${DOCKER:-finch}
export NAME
REPO=$(cd "$HERE/../../.." && pwd)
PAGE="$REPO/lua/wba/GETTING-STARTED.md"
# debian:trixie, the multi-arch index digest (Docker Hub, 2026-10-11).
IMAGE=debian:trixie@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5
HTTP_PORT=${HTTP_PORT:-18996} HTTPS_PORT=${HTTPS_PORT:-18997}
HAD_IMAGE=$($DOCKER image inspect "$IMAGE" >/dev/null 2>&1 && echo 1 || true)
WORK=$(mktemp -d)
PASSED=0 FAILED=0 DONE=0
START=$(date +%s)
cleanup() {
  if [ "${KEEP:-}" = 1 ]; then # KEEP=1: leave the container and $WORK for a look
    echo "== kept: container $NAME, work $WORK ($DOCKER rm -f $NAME when done)"; return
  fi
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
  [ -n "$HAD_IMAGE" ] || $DOCKER rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "$DONE" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT

pass() { echo "PASS  $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL  $1"; FAILED=$((FAILED + 1)); }
check() { if [ "$2" = "$3" ]; then pass "$1 -> $2"; else fail "$1 -> ${2:-<nothing>} (want $3)"; fi; }
# has NAME FILE TEXT: FILE holds TEXT (case-insensitive, fixed string).
has() {
  if grep -qiF -- "$3" "$2" 2>/dev/null; then pass "$1"; else fail "$1: no '$3' in:"; sed 's/^/      /' "$2" 2>/dev/null || true; fi
}

# --- The page's bash blocks, by their first line ------------------------------
mkdir -p "$WORK/blocks" "$WORK/out" "$WORK/bin" "$WORK/home"
awk -v dir="$WORK/blocks" '
  /^```bash[[:space:]]*$/ { n++; on = 1; first = 1; f = ""; next }
  on && /^```/ { on = 0; if (f != "") close(f); next }
  on {
    if (first) {
      first = 0; kind = ""
      if ($0 == "# On the server") kind = "server"
      else if ($0 == "# On your machine") kind = "machine"
      else if ($0 == "# On the server (optional)") kind = "optional"
      else if ($0 == "# On the server (behind a load balancer)") kind = "lb"
      if (kind != "") f = sprintf("%s/%02d-%s.sh", dir, n, kind)
    }
    if (f != "") print > f
  }
' "$PAGE"
for kind in server machine optional lb; do
  ls "$WORK/blocks/"*-"$kind".sh >/dev/null 2>&1 || { echo "FAIL  no '$kind' blocks in $PAGE"; exit 1; }
done

# --- Test stand-ins (not part of the page) -------------------------------------
# DNS: example.com is the container.
printf 'connect-to = example.com:443:127.0.0.1:%s\nconnect-to = example.com:80:127.0.0.1:%s\n' \
  "$HTTPS_PORT" "$HTTP_PORT" > "$WORK/home/.curlrc"
# scp: "scp FILE root@example.com:/path" copies FILE into the container.
cat > "$WORK/bin/scp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
$DOCKER cp "$1" "$NAME:${2#*:}"
EOF
chmod 755 "$WORK/bin/scp"
# machine COMMAND: run as the page's machine blocks run.
machine() { (cd "$REPO" && HOME="$WORK/home" CURL_HOME="$WORK/home" PATH="$WORK/bin:$PATH" bash -euo pipefail -c "$1"); }
server() { $DOCKER exec "$NAME" sh -c "$1"; }

echo "== start $IMAGE ($DOCKER)"
$DOCKER run -d --name "$NAME" -p "$HTTP_PORT:80" -p "$HTTPS_PORT:443" ${RUN_OPTS[@]+"${RUN_OPTS[@]}"} "$IMAGE" sleep infinity >/dev/null
# The repository copy the page expects at /opt/web-bot-auth (only lua/wba is used).
server 'mkdir -p /opt/web-bot-auth/lua /etc/nginx/conf.d'
$DOCKER cp "$REPO/lua/wba" "$NAME:/opt/web-bot-auth/lua/wba" >/dev/null
# Your application: answers 200, no WAF, not in the access log.
$DOCKER exec -i "$NAME" sh -c 'cat > /etc/nginx/conf.d/zz-test-application.conf' <<'EOF'
server {
    listen 127.0.0.1:8080;
    access_log off;
    location / { default_type text/plain; return 200 "test application\n"; }
}
EOF
# systemd: "systemctl start|restart|reload nginx".
$DOCKER exec -i "$NAME" sh -c 'cat > /usr/local/sbin/systemctl && chmod 755 /usr/local/sbin/systemctl' <<'EOF'
#!/bin/sh
# getting-started.sh's stand-in for systemd, which this container lacks.
[ "${2:-}" = nginx ] || { echo "systemctl stand-in: only nginx" >&2; exit 1; }
case "$1" in
  start|restart|reload)
    if [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then nginx -s reload; else nginx; fi
    sleep 2 ;;
  *) echo "systemctl stand-in: $1 is not supported" >&2; exit 1 ;;
esac
EOF

# --- Run the blocks ------------------------------------------------------------
wait_https() {
  for _ in $(seq 1 30); do
    [ "$(machine "curl -sk -o /dev/null -w '%{http_code}' --max-time 2 https://example.com/" 2>/dev/null || true)" != "000" ] && return
    sleep 1
  done
}
run_block() {
  local f=$1 base out
  base=$(basename "$f" .sh)
  out="$WORK/out/$base.txt"
  echo "== block $base: $(grep -v '^#' "$f" | grep -v '^[[:space:]]*$' | head -1 | cut -c1-90)"
  case "$f" in
    *-machine.sh)
      wait_https
      (cd "$REPO" && HOME="$WORK/home" CURL_HOME="$WORK/home" PATH="$WORK/bin:$PATH" \
        bash -euo pipefail "$f") >"$out" 2>&1 </dev/null ;;
    *)
      $DOCKER cp "$f" "$NAME:/tmp/getting-started-block.sh" >/dev/null </dev/null &&
        $DOCKER exec -e DEBIAN_FRONTEND=noninteractive "$NAME" \
          bash -euo pipefail /tmp/getting-started-block.sh >"$out" 2>&1 </dev/null ;;
  esac
}
# run_page: every server and machine block, in page order; stops at the first
# that fails.
run_page() {
  local f
  for f in "$WORK/blocks/"*-server.sh "$WORK/blocks/"*-machine.sh; do echo "$f"; done | sort > "$WORK/order"
  while read -r f <&3; do
    if ! run_block "$f"; then
      echo "FAIL  block $(basename "$f" .sh) failed; its output ends:"
      tail -n 40 "$WORK/out/$(basename "$f" .sh).txt" | sed 's/^/      /'
      exit 1
    fi
  done 3< "$WORK/order"
}
# run_blocks KIND: the blocks of that kind, in page order; a failing block is
# a failed check, with its output.
run_blocks() {
  local f
  for f in "$WORK/blocks/"*-"$1".sh; do
    if run_block "$f"; then pass "block $(basename "$f" .sh) ran"
    else fail "block $(basename "$f" .sh):"; sed 's/^/      /' "$WORK/out/$(basename "$f" .sh).txt"; fi
  done
}

# out_of TEXT: the output of the page block whose commands contain TEXT.
touch "$WORK/out/missing"
out_of() {
  local f
  f=$(grep -lF -- "$1" "$WORK/blocks/"*.sh | head -1 || true)
  if [ -z "$f" ]; then echo "$WORK/out/missing"; return; fi
  echo "$WORK/out/$(basename "$f" .sh).txt"
}

# finish SUCCESS-LINE FAILURE-LINE: the totals; exits non-zero if any check failed.
finish() {
  DONE=1
  echo "== $PASSED passed, $FAILED failed, in $(( $(date +%s) - START )) s"
  [ "$FAILED" = 0 ] && echo "== $1" || { echo "== $2"; exit 1; }
}
