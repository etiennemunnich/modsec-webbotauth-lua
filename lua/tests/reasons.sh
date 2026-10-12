#!/usr/bin/env bash
# reasons.sh: every outcome reason README.md documents is tested twice: by a
# unit suite (lua/tests/test_*.lua) and live, through ModSecurity
# (lua/tests/live/*.sh). Each must assert "<status>/<reason>" with the status
# README.md's Outcomes table gives that reason. A reason the live suites
# cannot reach from outside is listed in UNIT_ONLY with why; a stale entry
# there fails too. LIVE_ONLY is the reverse: set by a ModSecurity rule, so no
# Lua unit can produce it. Run by run_all.sh.
#
# Only real assertions count, never a comment, a table or a message:
#   unit  The Lua files are tokenized (comments dropped, strings read as
#         strings), and two call forms count:
#           expect(<request>, "<status>", "<reason>"[, msg])   test_verify.lua's helper
#           H.eq(<outcome>, "<status>/<reason>"[, msg])        test_entry, test_log and
#                                                              test_negative_vectors
#   live  Shell comments are dropped, and only the expected value of a line
#         that starts with an assertion command counts:
#           expect <case> <status>/<reason>                    run.sh
#           expect1 <case> <status>/<reason>                   run.sh (phase 1)
#           check <what> <actual> "<status>/<reason> <agent>"  registry.sh
# An assertion of a documented reason under another status than the
# README's fails, and so does one of a reason the README does not document.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO"
LUA=${LUA:-lua}

# Reasons no request can produce from outside, by design.
UNIT_ONLY="
crypto-error         lua-openssl raising on a key the store accepted: the store never holds one
internal-error       an error in the verifier itself, caught so it fails closed: no request causes one
too-many-signatures  a cap only CONFIG.policy in modsecurity_entry.lua sets (the draft makes verifiers check every signature, so there is no default)
"
# Reasons no Lua unit can produce: set by a ModSecurity rule, not by the verifier.
LIVE_ONLY="
engine-error         wba.conf rule 3, when the Lua entry never ran (lua-openssl missing): live, run.sh hides the module
"

# "<status>/<reason>" for every reason in the Outcomes table: the first
# column is the status, the second its reasons (the verified row's "(empty)"
# is no reason), the third is prose and never read.
pairs=$(sed -n '/^## Outcomes and reasons/,/^## For bot operators/p' lua/wba/README.md \
  | awk -F'|' '$2 ~ /^ *`[a-z-]+` *$/ { s = $2; gsub(/[ `]/, "", s)
      n = split($3, w, "`"); for (i = 2; i <= n; i += 2) if (w[i] ~ /^[a-z][a-z-]*$/) print s "/" w[i] }' | sort -u)
[ -n "$pairs" ] || { echo "FAIL  no reasons found in README.md"; exit 1; }
statuses=$(printf '%s\n' "$pairs" | cut -d/ -f1 | sort -u)
status_of() { printf '%s\n' "$pairs" | awk -F/ -v r="$1" '$2 == r { print $1 }'; }

# Unit assertions: "<status>/<reason> <file>:<line>", one per call. (A
# function, not a here-document inside $(...), which bash 3.2 can misparse.)
unit_assertions() { "$LUA" - "$@" <<'LUA'
local function tokens(src) -- names, strings (their text) and punctuation, with their line; comments dropped
    local out, i, n, line = {}, 1, #src, 1
    local function skip_to(j) line = line + select(2, src:sub(i, j - 1):gsub("\n", "")); i = j end
    while i <= n do
        local c, long = src:sub(i, i), src:match("^%[(=*)%[", i)
        if c:match("%s") then
            skip_to(i + 1)
        elseif src:sub(i, i + 1) == "--" then -- --[[ ... ]] (any level), else to the end of the line
            local eqs, e = src:match("^%[(=*)%[", i + 2), nil
            if eqs then e = select(2, src:find("]" .. eqs .. "]", i + 4 + #eqs, true)) end
            skip_to((e or (src:find("\n", i, true) or n + 1) - 1) + 1)
        elseif long then -- [[ ... ]]
            local s = i + #long + 2
            local e = select(2, src:find("]" .. long .. "]", s, true)) or n
            out[#out + 1] = { t = "str", v = src:sub(s, e - #long - 2), line = line }
            skip_to(e + 1)
        elseif c == '"' or c == "'" then
            local j = i + 1
            while j <= n and src:sub(j, j) ~= c do j = j + (src:sub(j, j) == "\\" and 2 or 1) end
            out[#out + 1] = { t = "str", v = src:sub(i + 1, j - 1), line = line }
            skip_to(j + 1)
        elseif c:match("[%w_]") then
            local w = src:match("^[%w_]+", i)
            out[#out + 1] = { t = "name", v = w, line = line }
            skip_to(i + #w)
        else
            out[#out + 1] = { t = "op", v = c, line = line }
            skip_to(i + 1)
        end
    end
    return out
end
local OPEN, CLOSE = { ["("] = true, ["{"] = true, ["["] = true }, { [")"] = true, ["}"] = true, ["]"] = true }
local function args(tk, k) -- tk[k] is a call's "(": its arguments, each a list of tokens
    local list, cur, depth = {}, {}, 0
    for j = k, #tk do
        local t, keep = tk[j], true
        if t.t == "op" and OPEN[t.v] then
            depth = depth + 1
            keep = depth > 1
        elseif t.t == "op" and CLOSE[t.v] then
            depth = depth - 1
            if depth == 0 then list[#list + 1] = cur; return list end
        elseif depth == 1 and t.t == "op" and t.v == "," then
            list[#list + 1], cur, keep = cur, {}, false
        end
        if keep then cur[#cur + 1] = t end
    end
    return list
end
local function str(a) return a and #a == 1 and a[1].t == "str" and a[1].v end -- the argument is one string literal
local function op(t, v) return t and t.t == "op" and t.v == v end
for _, file in ipairs(arg) do
    local f = assert(io.open(file))
    local tk = tokens(f:read("a"))
    f:close()
    for k, t in ipairs(tk) do
        local prev = tk[k - 1]
        if t.t == "name" and op(tk[k + 1], "(") then
            if t.v == "expect" and not (op(prev, ".") or op(prev, ":") or prev and prev.v == "function") then
                local a = args(tk, k + 1)
                if str(a[2]) and str(a[3]) then print(str(a[2]) .. "/" .. str(a[3]) .. " " .. file .. ":" .. t.line) end
            elseif t.v == "eq" and op(prev, ".") and tk[k - 2] and tk[k - 2].t == "name" and tk[k - 2].v == "H" then
                local want = str(args(tk, k + 1)[2])
                if want and want:find("^[a-z-]+/") then print(want .. " " .. file .. ":" .. t.line) end
            end
        end
    end
end
LUA
}
unit_found=$(unit_assertions lua/tests/test_*.lua) || { echo "FAIL  $LUA could not read the unit suites"; exit 1; }

# Live assertions: the same shape, from the assertion commands' expected value.
live_found=$(awk '
  /^[[:space:]]*#/ { next }
  { line = $0; sub(/[[:space:]]+#.*$/, "", line)
    split(line, w, /[[:space:]]+/); i = (w[1] == "") ? 2 : 1; want = ""
    if (w[i] == "expect" || w[i] == "expect1") want = w[i + 2]
    else if (w[i] == "check" && match(line, /("[^"]*"|[^[:space:]"]+)[[:space:]]*$/)) {
      want = substr(line, RSTART, RLENGTH); gsub(/"/, "", want); sub(/^[[:space:]]+/, "", want); sub(/[[:space:]].*$/, "", want)
    }
    if (want ~ /^[a-z-]+\/[a-z-]*$/) print want, FILENAME ":" FNR }' lua/tests/live/*.sh)

count() { printf '%s\n' "$2" | awk -v p="$1" '$1 == p' | wc -l | tr -d ' '; }
FAIL=0 n=0
for p in $pairs; do
  r=${p#*/} n=$((n + 1))
  [ "$(status_of "$r" | wc -l | tr -d ' ')" = 1 ] || { echo "FAIL  $r: README.md lists it under more than one status"; FAIL=1; }
  unit=$(count "$p" "$unit_found")
  live=$(count "$p" "$live_found")
  why=$(printf '%s\n' "$UNIT_ONLY" | awk -v r="$r" '$1 == r { $1 = ""; print substr($0, 2) }')
  live_only=$(printf '%s\n' "$LIVE_ONLY" | awk -v r="$r" '$1 == r { $1 = ""; print substr($0, 2) }')
  if [ "$unit" = 0 ] && [ -z "$live_only" ]; then echo "FAIL  $p: no unit test asserts it"; FAIL=1; fi
  if [ "$unit" != 0 ] && [ -n "$live_only" ]; then echo "FAIL  $p: a unit test asserts it now; remove it from LIVE_ONLY"; FAIL=1; fi
  if [ "$live" = 0 ] && [ -z "$why" ]; then echo "FAIL  $p: no live test asserts it through ModSecurity"; FAIL=1; fi
  if [ "$live" != 0 ] && [ -n "$why" ]; then echo "FAIL  $p: tested live now; remove it from UNIT_ONLY"; FAIL=1; fi
  if [ -z "$why" ]; then printf 'PASS  %-40s unit %-3s live %s\n' "$p" "$unit" "$live"
  else printf 'PASS  %-40s unit %-3s unit only: %s\n' "$p" "$unit" "$why"; fi
done
# Every assertion of a documented reason uses the README's status, and every
# asserted reason is documented.
while read -r p where; do
  [ -n "$p" ] || continue
  s=${p%%/*} r=${p#*/}
  printf '%s\n' "$statuses" | grep -qx -- "$s" || continue   # not an outcome (a path, say)
  [[ "$r" =~ ^[a-z][a-z-]*$ ]] || continue                   # "verified/" and the like: no reason named
  doc=$(status_of "$r")
  if [ -z "$doc" ]; then echo "FAIL  $where asserts $p, a reason README.md does not document"; FAIL=1
  elif [ "$doc" != "$s" ]; then echo "FAIL  $where asserts $p, but README.md lists $r under $doc"; FAIL=1; fi
done <<< "$(printf '%s\n%s\n' "$unit_found" "$live_found")"
for list in UNIT_ONLY LIVE_ONLY; do
  for u in $(printf '%s\n' "${!list}" | awk 'NF { print $1 }'); do
    [ -n "$(status_of "$u")" ] || { echo "FAIL  $list names $u, which README.md does not document"; FAIL=1; }
  done
done
[ "$FAIL" = 0 ] && echo "== ALL $n DOCUMENTED REASONS ARE TESTED" || { echo "== REASONS WITHOUT TESTS"; exit 1; }
