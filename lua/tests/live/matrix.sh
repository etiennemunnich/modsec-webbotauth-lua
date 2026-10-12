#!/usr/bin/env bash
# matrix.sh: run.sh against every image in crs-images.txt, one row per image.
# Each row records what the image actually contains (ModSecurity, connector,
# CRS and the Lua the module links), not what its tag claims.
#
#   lua/tests/live/matrix.sh [results.tsv]
#   DOCKER=docker uses Docker instead of Finch (both are tested in CI).
#   IMAGES=<file> runs another list (one tag per line, as crs-images.txt).
#   LOGS=<dir> keeps each image's run.sh log there (default: a new temp dir).
#   KEEP_IMAGES=1 keeps each pulled and built image; by default they, and the
#   build cache, are removed after each run.
set -uo pipefail
DOCKER=${DOCKER:-finch}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-matrix-results.tsv}
IMAGES=${IMAGES:-$HERE/crs-images.txt}
LOGS=${LOGS:-$(mktemp -d)}
mkdir -p "$LOGS"
PROBE=wba-matrix-probe-$$
COMPLETED=0
cleanup() {
  $DOCKER rm -f "$PROBE" >/dev/null 2>&1 || true
  # bash 3.2 (macOS) exits 0 when set -u aborts a script that has an EXIT
  # trap, and $? reads 0 inside the trap: only reaching the end is success.
  [ "$COMPLETED" = 1 ] || { echo "== ABORTED before the last check"; exit 1; }
}
trap cleanup EXIT
printf 'image\tmodsecurity\tconnector\tcrs\tlua\tunit\twycheproof\tlive pass\tlive fail\tlive skip\tverdict\n' > "$OUT"

while read -r tag <&3; do # tags on fd 3; stdin is /dev/null so no command can eat the list
  img="owasp/modsecurity-crs:$tag"; log="$LOGS/$tag.log"
  echo "=== $tag"
  $DOCKER pull -q "$img" >/dev/null 2>&1
  $DOCKER rm -f "$PROBE" >/dev/null 2>&1
  $DOCKER run -d --name "$PROBE" -p 18891:8080 -e BACKEND=http://127.0.0.1:9 "$img" >/dev/null 2>&1
  for _ in $(seq 1 30); do [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:18891/ || true)" != "000" ] && break; sleep 1; done
  sleep 1
  prod=$($DOCKER logs "$PROBE" 2>&1 | grep -o '"producer":{[^}]*}' | head -1)
  msc=$(echo "$prod" | grep -o 'ModSecurity v[0-9.]*' | head -1)
  conn=$(echo "$prod" | grep -o 'ModSecurity-nginx v[0-9.]*' | head -1)
  crs=$(echo "$prod" | grep -o 'OWASP_CRS/[0-9.]*' | head -1)
  lua=$($DOCKER exec "$PROBE" sh -c 'ldd /usr/lib/nginx/modules/ngx_http_modsecurity_module.so 2>/dev/null | grep -o "liblua[^ ]*" | head -1' 2>/dev/null)
  $DOCKER rm -f "$PROBE" >/dev/null 2>&1
  CRS_IMAGE="$img" DOCKER=$DOCKER "$HERE/run.sh" > "$log" 2>&1 < /dev/null
  unit=$(grep -o 'test_[a-z0-9_]*: all [0-9]* checks passed' "$log" | awk '{ s += $3 } END { print s + 0 }')
  wyc=$(grep -o 'wycheproof [a-z0-9_-]*: [0-9]* vectors.*disagreements' "$log" \
    | sed -E 's/.*: ([0-9]+) vectors.*, ([0-9]+) disagreements/\1 \2/' \
    | awk '{ v += $1; d += $2 } END { if (NR) printf "%d vectors, %d disagree", v, d }')
  pass=$(grep -c '^PASS' "$log"); fail=$(grep -c '^FAIL' "$log"); skip=$(grep -c '^SKIP' "$log")
  if grep -q 'ALL LIVE CHECKS PASSED' "$log"; then v=PASS; elif grep -q 'FAIL  test stage' "$log"; then v="FAIL (test stage)"; else v=FAIL; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tag" "${msc:-?}" "${conn:-?}" "${crs:-?}" "${lua:-none}" \
    "$unit" "${wyc:-?}" "$pass" "$fail" "$skip" "$v" >> "$OUT"
  echo "    $v (unit $unit, live $pass pass / $fail fail / $skip skip, ${msc:-?}, ${lua:-no lua})"
  # Disk stays bounded: run.sh removes the images it built; this removes the
  # base image and the build cache those builds left (all of BuildKit's
  # cache, which only costs a slower next build).
  if [ "${KEEP_IMAGES:-0}" != 1 ]; then
    $DOCKER rmi "$img" >/dev/null 2>&1 || true
    $DOCKER builder prune -af >/dev/null 2>&1 || true
  fi
done 3< <(grep -v -e '^#' -e '^$' "$IMAGES") < /dev/null
COMPLETED=1
echo "=== results: $OUT   logs: $LOGS"
