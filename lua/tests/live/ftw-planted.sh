#!/usr/bin/env bash
# ftw-planted.sh: shows the go-ftw tests can fail. Each case plants one bug in
# a copy of the plugin (never in this checkout), runs ftw.sh against it, and
# passes only if go-ftw fails the test written for that rule. A run where
# go-ftw loses its log markers counts as an error, not as a planted bug caught.
# Eight image builds: a few minutes. Not in run_all.sh.
#
#   bash lua/tests/live/ftw-planted.sh                (Finch)
#   DOCKER=docker bash lua/tests/live/ftw-planted.sh  (Docker)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
COPY=$WORK/repo
mkdir -p "$COPY"
cp -R "$REPO/lua" "$REPO/wba-keysync" "$REPO/tests" "$COPY/"

# name | the go-ftw test that must fail | file | perl substitution (last: it may hold "|")
# shellcheck disable=SC2016 # $1 and $2 are perl's, not the shell's
cases=(
  'no-920274-exemption|920274-1|lua/wba/wba.conf|s/^SecRuleUpdateTargetById 920274 .*\n//m'
  'malformed-403|9534107-1|lua/wba/wba.conf|s/id:9534107,phase:1,deny,status:400/id:9534107,phase:1,deny,status:403/'
  'switch-never-off|9534109-1|lua/wba/wba.conf|s/(SecRule TX:web-bot-auth-plugin_enabled "\@eq )0(" \\\n    "id:9534109)/${1}2$2/'
  'no-expiry-check|9534103-3|lua/wba/verify.lua|s/^    if now >= e \+ \(policy.expiry_grace or 0\) then return result\("invalid", "expired"\) end\n//m'
  'no-site-check|9534103-6|lua/wba/verify.lua|s/if pol.authorities and req.authority and not pol.authorities\[req.authority\] then/if false then/'
  'recipe-a-no-lowercase|9534130-4|lua/wba/recipes.conf|s/(id:9534130,phase:2,deny,status:460,log,t:none,t:urlDecodeUni,t:normalizePath,)t:lowercase,/$1/'
  'recipe-a-no-normalize|9534130-5|lua/wba/recipes.conf|s/(id:9534130,phase:2,deny,status:460,log,t:none,t:urlDecodeUni,)t:normalizePath,/$1/'
  'recipe-f-no-bad-signature|9534135-1|lua/wba/recipes.conf|s/\(\?:foreign-authority\|bad-signature\|/(?:foreign-authority|/'
)
CAUGHT=0
for c in "${cases[@]}"; do
  IFS='|' read -r name want file expr <<<"$c"
  cp "$REPO/$file" "$COPY/$file"
  perl -0pi -e "$expr" "$COPY/$file"
  if cmp -s "$REPO/$file" "$COPY/$file"; then echo "STALE   $name: the substitution matched nothing ($file changed?)"; continue; fi
  out=$(bash "$COPY/lua/tests/live/ftw.sh" 2>&1)
  failed=$(printf '%s\n' "$out" | grep -oE 'running [0-9]+-[0-9]+: - [0-9]+-[0-9]+ failed' | awk '{print $2}' | tr -d ':' | tr '\n' ' ')
  if printf '%s\n' "$out" | grep -q 'Error: failed to find'; then
    echo "ERROR   $name: go-ftw lost its log markers"
  elif [[ " $failed" == *" $want "* ]]; then
    echo "CAUGHT  $name: failed ${failed% }"; CAUGHT=$((CAUGHT + 1))
  else
    echo "MISSED  $name: $want did not fail (failed: ${failed:-none})"
  fi
  cp "$REPO/$file" "$COPY/$file"
done
echo "== $CAUGHT of ${#cases[@]} planted bugs caught"
[ "$CAUGHT" = "${#cases[@]}" ]
