#!/usr/bin/env bash
# recipes-match.sh: the README shows recipes.conf exactly, both ways. Every
# rule line of recipes.conf (comments and blank lines aside) is a whole line
# of a code block under the README's "### Rule examples" heading, and every
# line of those code blocks is a whole line of recipes.conf. The live suite
# runs recipes.conf, so a rule shown only on the page was never tested. Run
# by run_all.sh.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
README=${README:-$REPO/lua/wba/README.md}
CONF=${CONF:-$REPO/lua/wba/recipes.conf}

shown=$(awk '/^### Rule examples/ { on = 1; next } on && /^#{1,3} / { on = 0 }
  on && /^```/ { block = !block; next } on && block && NF' "$README")
rules=$(grep -v -e '^#' -e '^[[:space:]]*$' "$CONF")
[ -n "$shown" ] || { echo "FAIL  no code blocks under \"### Rule examples\" in $README"; exit 1; }

FAIL=0
while IFS= read -r l; do
  printf '%s\n' "$shown" | grep -qxF -- "$l" || { echo "FAIL  in recipes.conf, not in the README: $l"; FAIL=1; }
done <<< "$rules"
while IFS= read -r l; do
  printf '%s\n' "$rules" | grep -qxF -- "$l" || { echo "FAIL  in the README, not in recipes.conf: $l"; FAIL=1; }
done <<< "$shown"
[ "$FAIL" = 0 ] && echo "PASS  $(printf '%s\n' "$rules" | wc -l | tr -d ' ') recipe lines, the same in README.md and recipes.conf"
exit "$FAIL"
