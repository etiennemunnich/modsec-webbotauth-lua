--[[
replay.lua: how many times this host has seen a verified signature, and a
nonce. Web Bot Auth draft 5.3: "An Origin that detects a signature or nonce
has been used more often than its policy permits MAY request a new signature
and respond with 429"; RFC 9421 7.2.2 leaves the tracking to the verifier.

One file per signed statement, s.<last>.<hash of the signature base>
(verify.lua's basehash: every valid signature over one base, ECDSA variants
included, is the same statement; last is the last second any of them can
verify: expires, or created plus max_age when sooner), and one per nonce,
n.<SHA-256 of the nonce>, in a directory the operator names
(tx.wba_replay_dir), on a local filesystem. A use appends one byte and reads back this descriptor's offset.
O_APPEND moves the offset to the end and writes in one step (POSIX write(2);
Linux holds the inode lock across both), so concurrent requests, in any
nginx worker, each get a different count: 200 at once in the CRS image got
200 different counts, none lost (TESTING.md, Replay accounting).
libmodsecurity's persistent collections cannot count: setvar reads and
writes in separate LMDB transactions, and 201 increments the same way left
the counter at 70 in one run and 62 in another. A network filesystem can break the append guarantee.

Names are a fixed prefix, that last second (digits) and 64 lowercase
hex characters: nothing from the request reaches a path. Only verified
signatures are counted, so only the holder of an allowlisted key can add a
file. Nothing here reads or deletes files: wba-keysync/sweep.ts, on the
operator's timer, removes a statement's file once that second has passed,
and a nonce's once it has gone unused for the longest window (README, Replay
accounting).
--]]

local M = {}

--- Counts one use of a signed statement ("s") or a nonce ("n").
--- @param dir string, the directory (no trailing slash)
--- @param kind "s" | "n"
--- @param hash string, 64 lowercase hex characters
--- @param last integer, the last second a signature over it can verify (kind "s" only)
--- @return the number of uses on this host, this one included; or nil and why
function M.count(dir, kind, hash, last)
    if type(hash) ~= "string" or #hash ~= 64 or hash:find("[^0-9a-f]") then return nil, "bad key" end
    local name
    if kind == "s" and math.type(last) == "integer" and last >= 0 and last < 10 ^ 15 then
        name = ("s.%d.%s"):format(last, hash)
    elseif kind == "n" and last == nil then
        name = "n." .. hash
    else
        return nil, "bad key"
    end
    local f, err = io.open(dir .. "/" .. name, "ab")
    if not f then return nil, err end
    f:setvbuf("no") -- the byte reaches write(2) here, so seek reports its end
    local pos, why = f:write("x")
    if pos then pos, why = f:seek("cur") end
    f:close()
    if not pos then return nil, why end
    return pos
end

return M
