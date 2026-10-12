-- bench.lua: what coding.lua's paths cost, to set its block charges and
-- the default decoding budget (TESTING.md, Content codings). Not a test.
--   lua lua/tests/coding/bench.lua
local here = arg[0]:match("(.*/)") or "./"
package.path = here .. "../../?.lua;" .. here .. "?.lua;" .. package.path
local coding = require("wba.coding")
local sha256 = require("wba.sha256")
local W = require("bits")

local function best(f)
    local t = math.huge
    for _ = 1, 3 do
        local t0 = os.clock()
        f()
        t = math.min(t, os.clock() - t0)
    end
    return t
end
local N = 1 << 20

local function rate(name, src, out_len)
    local dt = best(function() assert(#coding.inflate_raw(src) == out_len) end)
    print(("%-34s %6.1f MB/s"):format(name, out_len / dt / 1e6))
    return dt / out_len
end

-- Literals on fixed codes: five 9-bit ones reach a byte boundary, then 8-bit ones.
local w = W.new():put(1, 1):put(1, 2)
for _ = 1, 5 do w:fixed(200) end
local eight = W.new()
for _ = 1, 8 do eight:fixed(65) end
local n8 = (N - 5) // 8
rate("literals, fixed 8-bit codes", w:bytes() .. eight:bytes():rep(n8) .. W.new():fixed(256):bytes(), 5 + n8 * 8)

-- Literals on 15-bit codes (two lookups each): the slowest bytes there are.
local lit = {}
for s = 0, 285 do lit[s] = 0 end
for s = 0, 13 do lit[s] = s + 1 end
lit[65], lit[256] = 15, 15
local codes = W.canon(lit, 286)
w = W.new():dynamic(1, lit, 286, { [0] = 0 }, 1)
local k = 0
while not w:aligned() do w:code(codes[65], 15); k = k + 1 end
eight = W.new()
for _ = 1, 8 do eight:code(codes[65], 15) end
local n15 = (N - k) // 8
local per_byte = rate("literals, 15-bit codes", w:bytes() .. eight:bytes():rep(n15) .. W.new():code(codes[256], 15):bytes(),
    k + n15 * 8)

-- Matches of 258 at distance 1 (a bomb).
w = W.new():put(1, 1):put(1, 2):fixed(65):fixed(285):code(0, 5) -- 3 + 8 + 13 bits = 3 bytes
eight = W.new()
for _ = 1, 8 do eight:fixed(285):code(0, 5) end
local nm = (N // 258) // 8
rate("matches of 258 at distance 1", w:bytes() .. eight:bytes():rep(nm) .. W.new():fixed(256):bytes(), 1 + 258 + nm * 8 * 258)

local data = ("0123456789abcdef"):rep(4096):sub(1, 65535)
w = W.new()
for i = 1, 16 do w:stored(i == 16 and 1 or 0, data) end
rate("stored blocks", w:bytes(), 16 * 65535)

-- Typical data: the gzip CLI (-6) over 1 MiB of JSON-like lines, with the CRC.
do
    local t, seed = {}, 1
    local words = { "agent", "digest", "signature", "web", "bot", "auth", "keyid", "created", "expires", "path" }
    while #t < 30000 do
        seed = (seed * 1103515245 + 12345) & 0x7fffffff
        t[#t + 1] = ('{"%s": %d, "%s": "%s"},\n'):format(words[seed % 10 + 1], seed % 100000, words[(seed >> 8) % 10 + 1],
            words[(seed >> 16) % 10 + 1])
    end
    local text = table.concat(t):sub(1, N)
    local f = os.tmpname()
    local h = assert(io.open(f, "wb")); h:write(text); h:close()
    assert(os.execute(("gzip -6 -n -c '%s' > '%s.gz'"):format(f, f)))
    h = assert(io.open(f .. ".gz", "rb")); local gz = h:read("a"); h:close()
    os.remove(f); os.remove(f .. ".gz")
    local dt = best(function() assert(coding.decode(gz, { "gzip" }, math.maxinteger) == text) end)
    print(("%-34s %6.1f MB/s (ratio %.1f)"):format("gzip -6 of JSON-like text, CRC", N / dt / 1e6, N / #gz))
end

local s = ("x"):rep(N)
print(("%-34s %6.1f MB/s"):format("CRC-32", N / best(function() coding.crc32(s) end) / 1e6))
print(("%-34s %6.1f MB/s"):format("Adler-32", N / best(function() coding.adler32(s) end) / 1e6))
print(("%-34s %6.1f MB/s"):format("SHA-256 (sha256.lua), for scale", N / best(function() sha256.digest(s) end) / 1e6))

-- Empty blocks: cost each, in bytes of the slowest decoding.
local function per_block(name, one, count)
    local x = W.new()
    for _ = 1, count do one(x) end
    x:put(1, 1):put(1, 2):fixed(256)
    local src = x:bytes()
    local t = best(function() assert(coding.inflate_raw(src) == "") end) / count
    print(("%-34s %8.2f us = %4.0f slowest bytes"):format(name, t * 1e6, t / per_byte))
end
per_block("empty fixed block", function(x) x:put(0, 1):put(1, 2):fixed(256) end, 20000)
per_block("empty stored block", function(x) x:stored(0, "") end, 20000)
local L, D = {}, {}
for i = 0, 285 do L[i] = i < 226 and 8 or 9 end
for i = 0, 29 do D[i] = i < 2 and 4 or 5 end
local lc = W.canon(L, 286)
per_block("empty dynamic block", function(x) x:dynamic(0, L, 286, D, 30):code(lc[256], L[256]) end, 3000)
-- The largest tables a code can force: 4 short codes leave 32 root slots,
-- each the root of 7 long codes (10..15, 15): 32 subtables of 64 entries.
local WL = {}
for i = 0, 285 do WL[i] = 0 end
local sym = 0
for l = 1, 4 do WL[sym] = l; sym = sym + 1 end
for _ = 1, 32 do
    for _, l in ipairs({ 10, 11, 12, 13, 14, 15, 15 }) do
        if sym == 256 then sym = sym + 1 end
        WL[sym] = l
        sym = sym + 1
    end
end
WL[256], WL[3] = WL[3], 0 -- end of block takes symbol 3's 4-bit code
local wc = W.canon(WL, 286)
per_block("dynamic block, 32 subtables", function(x) x:dynamic(0, WL, 286, D, 30):code(wc[256], WL[256]) end, 3000)
print(("worst decode with CRC-32: %.1f MB/s; 128 KiB in %.0f ms"):format(
    1 / (per_byte + 1 / (N / best(function() coding.crc32(s) end))) / 1e6,
    131072 * (per_byte + best(function() coding.crc32(s) end) / N) * 1e3))
