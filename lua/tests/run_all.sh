#!/usr/bin/env bash
# run_all.sh: every suite, one exit code. Use it locally and as the CI step.
#
#   lua/tests/run_all.sh          Lua suites, both corpora, negative vectors,
#                                 mutants, fixture freshness, key-sync
#   lua/tests/run_all.sh --live   also the image's test stage (Lua 5.3,
#                                 test_crypto, Wycheproof and crypto.lua's
#                                 mutants against the shipped lua-openssl),
#                                 the live suite, the README Quick start, the
#                                 registry path, the real-IP checks, the
#                                 bot lists path, GETTING-STARTED.md on
#                                 Debian 13 (needs network: Debian, GitHub,
#                                 coreruleset.org) and the go-ftw tests in
#                                 tests/regression (needs go-ftw)
#   lua/tests/run_all.sh --suites-only   the Lua suites alone: what can differ
#                                 between Lua versions (CI runs everything on
#                                 one version and this on the other)
#
#   LUA=lua5.3 lua/tests/run_all.sh        another Lua interpreter
#   JOBS=2 lua/tests/run_all.sh            mutants in two shards at once
#   lua/tests/run_all.sh --live            (Finch by default; DOCKER=docker for Docker, both tested in CI)
#
# A tool that is missing (bun, node, a container CLI) is reported as SKIP,
# never as a pass. Exit status is non-zero if any step fails.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
export LUA=${LUA:-lua}
export DOCKER=${DOCKER:-finch}
LIVE=0 SUITES_ONLY=0
[ "${1:-}" = "--live" ] && LIVE=1
[ "${1:-}" = "--suites-only" ] && SUITES_ONLY=1
FAILED=() SKIPPED=()

step() { # name, command...
  local name=$1; shift
  echo "== $name"
  if "$@"; then echo "OK    $name"; else echo "FAIL  $name"; FAILED+=("$name"); fi
}
skip() { echo "SKIP  $1"; SKIPPED+=("$1"); }
have() { command -v "$1" >/dev/null 2>&1; }

cd "$REPO" || exit 1
echo "Lua: $("$LUA" -v 2>&1)"

for t in base64 structured_fields sf_corpus components sigbase keys sha256 coding replay verify negative_vectors entry log conf; do
  step "test_$t" "$LUA" "lua/tests/test_$t.lua"
done
# crypto.lua runs lua-openssl; where it loads, its suite runs here too.
if "$LUA" -e 'require "openssl"' >/dev/null 2>&1; then
  step "test_crypto" "$LUA" lua/tests/test_crypto.lua
  step "wycheproof" "$LUA" lua/tests/wycheproof/run.lua lua/tests/wycheproof/*.tsv
else
  skip "lua-openssl: test_crypto, Wycheproof and crypto.lua's mutants (the image's test stage runs them; --live)"
fi
if [ "$SUITES_ONLY" = 1 ]; then
  [ ${#FAILED[@]} -eq 0 ] || { printf 'FAILED: %s\n' "${FAILED[@]}"; exit 1; }
  echo "== ALL LUA SUITES PASSED ($LUA; mutants, fixtures and key-sync not run)"; exit 0
fi
step "mutants" bash lua/tests/mutants.sh
# The README shows recipes.conf exactly, both ways; the live suite runs the
# file, so the two must not drift apart.
step "README recipes are recipes.conf verbatim" bash lua/tests/recipes-match.sh
# Every reason in the README's Outcomes table has a unit test and a live one.
step "every documented reason is tested" bash lua/tests/reasons.sh

# Generated fixtures must match their generators (a hand-edited fixture fails).
# coding/vectors.tsv is checked, not regenerated: zlib builds compress the same
# input to different bytes, but must decode every vector as the file says.
if have bun; then
  step "query-param vectors are current (bun)" sh -c 'bun lua/tests/query-param/gen.ts | cmp -s - lua/tests/query-param/vectors.tsv'
  step "coding vectors agree with zlib (bun)" bun lua/tests/coding/gen.ts --check lua/tests/coding/vectors.tsv
  step "key-sync (bun)" bun test ./wba-keysync/keysync.test.ts ./wba-keysync/proof.test.ts ./wba-keysync/sweep.test.ts ./wba-keysync/validate.test.ts ./wba-keysync/report.test.ts ./wba-keysync/sign.test.ts ./wba-keysync/agents.test.ts ./wba-keysync/lists.test.ts ./wba-keysync/robots.test.ts ./.githooks/scan.test.ts
  # The issue forms testers see: the preview's overlay here, .github in a preview.
  for d in preview/overlay/.github/ISSUE_TEMPLATE .github/ISSUE_TEMPLATE; do
    [ -d "$d" ] && step "issue forms in $d" bun lua/tests/issue-forms.ts "$d"
  done
  # A preview snapshot exports cleanly from HEAD (not in a preview, which has no preview/).
  [ -f preview/make-preview.sh ] && step "preview snapshot exports from HEAD" sh -c 'd=$(mktemp -d) && bash preview/make-preview.sh "$d/p" >/dev/null && rm -rf "$d"'
else
  skip "bun: query-param and coding vectors, key-sync"
fi
if have node; then
  step "query-param vectors are current (node)" sh -c 'node --experimental-strip-types lua/tests/query-param/gen.ts 2>/dev/null | cmp -s - lua/tests/query-param/vectors.tsv'
  step "coding vectors agree with zlib (node)" node --experimental-strip-types lua/tests/coding/gen.ts --check lua/tests/coding/vectors.tsv
  step "key-sync (node)" node --test wba-keysync/keysync.test.ts wba-keysync/proof.test.ts wba-keysync/sweep.test.ts wba-keysync/validate.test.ts wba-keysync/report.test.ts wba-keysync/sign.test.ts wba-keysync/agents.test.ts wba-keysync/lists.test.ts wba-keysync/robots.test.ts
else
  skip "node: query-param and coding vectors, key-sync"
fi

if [ "$LIVE" = 1 ]; then
  if have "$DOCKER"; then
    step "live (image test stage, Wycheproof, live checks)" bash lua/tests/live/run.sh
    step "README Quick start, run as written" bash lua/tests/live/quickstart.sh
    if have bun; then step "registry: bots file, agents.ts, key sync, the WAF" bash lua/tests/live/registry.sh; else skip "bun: the registry path (registry.sh)"; fi
    step "real-IP placement: which address ModSecurity sees behind a proxy" bash lua/tests/live/real-ip.sh
    if have bun; then step "bot lists: bots file, lists.ts, the WAF" bash lua/tests/live/bot-lists.sh; else skip "bun: the bot lists path (bot-lists.sh)"; fi
    if have bun; then step "GETTING-STARTED.md on Debian 13, run as written" bash lua/tests/live/getting-started.sh; else skip "bun: GETTING-STARTED.md (getting-started.sh)"; fi
    if have bun && { have go-ftw || have ftw; }; then step "go-ftw tests (tests/regression), signed by a test bot" bash lua/tests/live/ftw.sh
    else skip "bun or go-ftw: the go-ftw tests (ftw.sh; brew install coreruleset/tap/go-ftw)"; fi
  else
    skip "$DOCKER not found: live suites (DOCKER=docker to use Docker)"
  fi
fi

echo
[ ${#SKIPPED[@]} -gt 0 ] && printf 'SKIPPED: %s\n' "${SKIPPED[@]}"
if [ ${#FAILED[@]} -gt 0 ]; then
  printf 'FAILED: %s\n' "${FAILED[@]}"
  exit 1
fi
echo "== ALL SUITES PASSED"
