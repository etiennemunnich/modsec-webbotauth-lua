-- test_replay.lua: replay.lua, the per-host use counter (draft 5.3; RFC
-- 9421 7.2.2). Concurrency is tested with separate processes, as nginx
-- workers are.
-- Run: lua lua/tests/test_replay.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local replay = require("wba.replay")

local function fresh_dir(name)
    local d = H.tmp(name)
    assert(H.sh(("rm -rf '%s' && mkdir -p '%s'"):format(d, d)))
    return d
end
local A, B = ("a"):rep(64), ("0123456789abcdef"):rep(4)
local E = 1790990000 -- a signature's expires: part of a statement counter's name

-- 1. Counts start at 1 and go up by one per use; signatures and nonces, and
-- different hashes, are counted apart.
local dir = fresh_dir("replay1")
H.eq(replay.count(dir, "s", A, E), 1)
H.eq(replay.count(dir, "s", A, E), 2)
H.eq(replay.count(dir, "s", A, E), 3)
H.eq(replay.count(dir, "n", A), 1, "a nonce is counted apart from a statement with the same hash")
H.eq(replay.count(dir, "s", B, E), 1)
H.eq(#H.read(dir .. "/s." .. E .. "." .. A), 3, "one byte per use, in s.<expires>.<hash>")
H.eq(#H.read(dir .. "/n." .. A), 1, "a nonce's file is n.<hash>")
H.pass("counts start at 1 and rise by one per use; kinds and hashes counted apart; names carry the expiry")

-- 2. Nothing but a fixed prefix and 64 lowercase hex characters reaches a
-- file name, and a refused key creates no file.
for _, bad in ipairs({ { "x", A, E }, { "s", A:upper(), E }, { "s", A:sub(2), E }, { "s", A .. "a", E },
                       { "s", ("a"):rep(61) .. "../", E }, { "s", ("a"):rep(63) .. "/", E }, { "", A, E },
                       { "s", A }, { "s", A, -1 }, { "s", A, 1.5 }, { "s", A, "1790990000" }, { "s", A, 1000000000000000 },
                       { "n", A, E }, { "s", nil, E } }) do
    local n, err = replay.count(dir, bad[1], bad[2], bad[3])
    H.eq(n, nil, ("refused: %s %s %s"):format(bad[1], tostring(bad[2]), tostring(bad[3])))
    H.eq(err, "bad key")
end
local p = io.popen(("ls -A '%s' | wc -l"):format(dir))
H.eq(tonumber(p:read("a")), 3, "only the three files counted above")
p:close()
H.pass("only s.<expires>.<hex> and n.<hex> reach a path; a missing, negative, fractional, string or 16-digit expiry, or one on a nonce, is refused and creates nothing")

-- 3. A directory that is missing or not writable: no count, and why.
local n, err = replay.count(dir .. "/missing", "s", A, E)
H.eq(n, nil)
H.eq(type(err) == "string" and #err > 0, true, "an error message")
local ro = fresh_dir("replay-ro")
assert(H.sh(("chmod 0500 '%s'"):format(ro)))
local is_root = H.sh("test \"$(id -u)\" = 0")
if not is_root then -- root writes anyway
    n, err = replay.count(ro, "s", A, E)
    H.eq(n, nil, "read-only directory")
    H.eq(type(err), "string")
end
assert(H.sh(("chmod 0700 '%s'"):format(ro)))
H.pass(is_root and "a missing directory gives nil and the reason (read-only not checked: root writes there anyway)"
    or "a missing or read-only directory gives nil and the reason")

-- 4. Concurrency: 40 processes count the same signature at once. Each gets
-- its own count, 1 to 40, none repeated, none lost.
local cdir = fresh_dir("replay-concurrent")
local out = H.tmp("replay-concurrent.out")
local lua = arg[-1] or "lua"
local chunk = ("package.path=%q..package.path; local r=require('wba.replay'); io.write(assert(r.count(%q,'s',%q,%d)),'\\n')")
    :format(H.here .. "../?.lua;", cdir, A, E)
assert(H.sh(("rm -f '%s'; for i in $(seq 1 40); do '%s' -e %q >> '%s' & done; wait"):format(out, lua, chunk, out)))
local seen, count = {}, 0
for line in io.lines(out) do
    local v = tonumber(line)
    H.eq(v ~= nil and v >= 1 and v <= 40, true, "count in 1..40: " .. line)
    H.eq(seen[v], nil, "count repeated: " .. line)
    seen[v], count = true, count + 1
end
H.eq(count, 40, "40 counts")
H.eq(#H.read(cdir .. "/s." .. E .. "." .. A), 40, "40 bytes: no use lost")
H.pass("40 concurrent processes: counts 1 to 40, each once, none lost")

H.done("test_replay")
