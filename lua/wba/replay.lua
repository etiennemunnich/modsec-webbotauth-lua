--[[
replay.lua: how many times this host has seen a verified signature, and a
nonce. Web Bot Auth draft 5.3: "An Origin that detects a signature or nonce
has been used more often than its policy permits MAY request a new signature
and respond with 429"; RFC 9421 7.2.2 leaves the tracking to the verifier.

One file per signed statement, s.<expires>.<hash of the signature base>
(verify.lua's basehash: every valid signature over one base, ECDSA variants
included, is the same statement; expires is the signature's own, which the
base covers, so the name comes from the signature alone and one statement
keeps one count under every server block's tx.wba_expiry_grace and
tx.wba_max_age), and one per nonce, n.<SHA-256 of the nonce>, in a
directory the operator names (tx.wba_replay_dir), on a local filesystem.
A use appends one byte and reads back this descriptor's offset.
O_APPEND moves the offset to the end and writes in one step (POSIX write(2);
Linux holds the inode lock across both), so concurrent requests, in any
nginx worker, each get a different count: 200 at once in the CRS image got
200 different counts, none lost (TESTING.md, Replay accounting).
libmodsecurity's persistent collections cannot count: setvar reads and
writes in separate LMDB transactions, and 201 increments the same way left
the counter at 70 in one run and 62 in another. A network filesystem can break the append guarantee.

Names are a fixed prefix, that expires (digits) and 64 lowercase hex
characters: nothing from the request reaches a path. Only verified
signatures are counted, so only the holder of an allowlisted key can add a
file. Nothing here reads or deletes files: wba-keysync/sweep.ts, on the
operator's timer, removes a file once nothing it counts can verify again:
a statement's once its expires has passed (none verifies after expires plus
tx.wba_expiry_grace, at most 60 s, inside the sweeper's 5-minute margin),
and a statement's or a nonce's once it has gone unused for longer than any
signature can count (tx.wba_max_age, an hour by default; every signature
over one base shares its created, so none verifies more than max_age plus
the 60 s clock skew after the statement's first use). So the store holds
about an hour of verified traffic, whatever expires a bot chooses (README,
Replay accounting).
--]]

local M = {}

--- Counts one use of a signed statement ("s") or a nonce ("n").
--- @param dir string, the directory (no trailing slash)
--- @param kind "s" | "n"
--- @param hash string, 64 lowercase hex characters
--- @param expires integer, the signature's own expires (kind "s" only)
--- @return the number of uses on this host, this one included; or nil and why
function M.count(dir, kind, hash, expires)
    if type(hash) ~= "string" or #hash ~= 64 or hash:find("[^0-9a-f]") then return nil, "bad key" end
    local name
    if kind == "s" and math.type(expires) == "integer" and expires >= 0 and expires < 10 ^ 15 then
        name = ("s.%d.%s"):format(expires, hash)
    elseif kind == "n" and expires == nil then
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
