-- test_coding.lua: content codings for Unencoded-Digest (coding.lua).
--
-- Ground truth comes from outside this code: zlib decided every vector in
-- coding/vectors.tsv (gen.ts; checked again by Bun's and Node's zlib in
-- run_all.sh); the RFC 9530 and unencoded-digest draft examples carry their
-- own digests; the gzip CLI builds the bombs. Shapes too large for the file
-- are built with coding/bits.lua, and their expected output is plain
-- arithmetic. Run: lua lua/tests/test_coding.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. ((arg[0]:match("(.*/)") or "./") .. "coding/?.lua;")
    .. package.path
local H = require("helpers")
local coding = require("wba.coding")
local sha256 = require("wba.sha256")
local b64 = require("wba.base64")
local W = require("bits")

local function hex(raw) return (raw:gsub(".", function(c) return ("%02x"):format(c:byte()) end)) end
local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end
local BIG = math.maxinteger

local function run(kind, input, budget)
    if kind == "raw" then return coding.inflate_raw(input, budget) end
    return coding.decode(input, { kind == "zlib" and "deflate" or "gzip" }, budget or BIG)
end

-- 1. Every vector zlib decided: the same outcome, and the same bytes.
local count, ok_count, families = 0, 0, {}
for line in io.lines(H.here .. "coding/vectors.tsv") do
    if line:sub(1, 1) ~= "#" then
        local name, kind, input, want = line:match("^([^\t]+)\t([^\t]+)\t([^\t]*)\t([^\t]+)$")
        assert(name, "bad vector line: " .. line:sub(1, 60))
        local good, got, why = pcall(run, kind, unhex(input))
        if not good then error(name .. ": raised (a bug, not a decoding outcome): " .. tostring(got)) end
        if want == "err" then
            H.eq(got, nil, name .. " decoded, zlib refused it")
        else
            local len, digest = want:match("^ok (%d+) (%x+)$")
            if got == nil then error(name .. ": refused (" .. tostring(why) .. "), zlib decoded it") end
            H.eq(#got, tonumber(len), name .. " length")
            H.eq(hex(sha256.digest(got)), digest, name .. " content")
            ok_count = ok_count + 1
        end
        count = count + 1
        local family = name:match("^([a-z]+)")
        families[family] = (families[family] or 0) + 1
    end
end
H.eq(count > 2500, true, "the vector file is all there")
H.pass(("%d zlib-decided vectors agree (%d decode, %d refused): zlib output %d, crafted %d, truncations %d, bit flips %d, random %d")
    :format(count, ok_count, count - ok_count, families.zlib or 0, families.craft or 0, families.cut or 0,
        families.flip or 0, families.random or 0))

-- 2. The specifications' own examples.
-- RFC 9530 Appendix A, Figure 2: {"hello": "world"} + LF, gzip-coded; B.1
-- gives the SHA-256 of the decoded bytes.
local FIG2 = unhex("1F8B08008841376400FFAB56CA48CDC9C957B252502ACF2FCA4951AAE50200D9E431E713000000")
local got = coding.decode(FIG2, { "gzip" }, BIG)
H.eq(got, '{"hello": "world"}\n')
H.eq(b64.encode(sha256.digest(got)), "RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=", "RFC 9530 B.1 sha-256")
-- draft-ietf-httpbis-unencoded-digest-05 6, Figure 2: its Repr-Digest is over
-- the coded bytes, its Unencoded-Digest over the decoded ones.
local UD = unhex("1f8b0800791f086400ff73cc5328cd4bad484e2d28c9cccf4bcc51282e29cacc4be702007eaf074418000000")
got = coding.decode(UD, { "gzip" }, BIG)
H.eq(got, "An unexceptional string\n")
H.eq(b64.encode(sha256.digest(UD)), "kwcdt3RBGcsLaj7QSz9AW8MuwJaLjOJqUU/jKixF2oU=", "draft 6 Repr-Digest (coded)")
H.eq(b64.encode(sha256.digest(got)), "5Bv3NIx05BPnh0jMph6v1RJ5Q7kl9LKMtQxmvc9+Z7Y=", "draft 3 Unencoded-Digest sha-256")
H.eq(b64.encode(H.sha512(got)), "WjyMuMD9EI/v0RoJchcevbo6lF498VyE9564OgXf+98iJptoSvb1Czo9uVJu2bVU/tOv90huiMG3+YaMX1kipw==",
    "draft 3 Unencoded-Digest sha-512")
H.pass("RFC 9530 Figure 2 and the unencoded-digest draft's Figure 2 decode to their published digests")

-- 3. Format rules where zlib-based runtimes disagree with the text, so the
-- expectation is the RFC's (gen.ts says why these are not in the file).
local function kind_of(input, codings) return select(2, coding.decode(input, codings, BIG)) end
H.eq(coding.decode(FIG2 .. UD, { "gzip" }, BIG), '{"hello": "world"}\n' .. "An unexceptional string\n",
    "RFC 1952 2.2: a gzip file is a series of members, all decoded")
for _, tail in ipairs({ "\0", "\0\0\0\0", "garbage", "\31\139", "\31\139\8\0\0\0\0\0\0\255" }) do
    H.eq(kind_of(FIG2 .. tail, { "gzip" }), "corrupt", "bytes after the last member that are not a member: " .. hex(tail))
end
local hello_raw = W.new():put(1, 1):put(1, 2)
for c in ('{"hello": "world"}\n'):gmatch(".") do hello_raw:fixed(c:byte()) end
hello_raw:fixed(256)
local deflated = hello_raw:bytes()
local adler = coding.adler32('{"hello": "world"}\n')
local zstream = "\120\156" .. deflated .. string.pack(">I4", adler)
H.eq(coding.decode(zstream, { "deflate" }, BIG), '{"hello": "world"}\n', "a zlib stream built by hand")
H.eq(kind_of(zstream .. "\0", { "deflate" }), "corrupt", "RFC 1950: one stream; a trailing byte is an error (zlib itself ignores it)")
H.eq(kind_of(zstream .. zstream, { "deflate" }), "corrupt", "two zlib streams are not the deflate coding")
H.eq(kind_of("", { "gzip" }), "corrupt", "an empty body is not a gzip file")
H.eq(kind_of("", { "deflate" }), "corrupt", "nor a zlib stream")
H.eq(kind_of(deflated, { "deflate" }), "corrupt", "raw deflate is not the deflate coding (RFC 9110 8.4.1.2)")
H.pass("RFC 1952 members, RFC 1950 single streams: trailing bytes and wrong wrappers are corrupt")

-- 4. Codings, stacked and unknown.
local fdict = "\120\187" .. string.pack(">I4", 1) .. deflated .. string.pack(">I4", adler) -- FLG 0xbb: FDICT, check ok
H.eq(((0x78 << 8) | 0xbb) % 31, 0)
H.eq(kind_of(fdict, { "deflate" }), "corrupt", "RFC 1950 2.3: HTTP has no preset dictionary, so FDICT must not be set")
H.eq(kind_of(FIG2, { "br" }), "unsupported")
H.eq(kind_of(FIG2, { "gzip", "zstd" }), "unsupported", "an unsupported coding anywhere: nothing decoded")
H.eq(coding.decode("as is", {}, BIG), "as is", "no codings")
-- Stacked: Content-Encoding "deflate, gzip" means deflate was applied first.
local function gzip_of(data)
    local f = H.tmp("stack.in")
    H.write(f, data)
    assert(H.sh(("gzip -n -9 -c '%s' > '%s.gz'"):format(f, f)))
    return H.read(f .. ".gz")
end
local gz_of_z = gzip_of(zstream)
H.eq(coding.decode(gz_of_z, { "deflate", "gzip" }, BIG), '{"hello": "world"}\n', "deflate, gzip: gzip removed first")
H.eq(kind_of(gz_of_z, { "gzip", "deflate" }), "corrupt", "the wrong order fails")
H.eq(coding.decode(gzip_of(gzip_of("twice")), { "gzip", "gzip" }, BIG), "twice", "gzip, gzip")
H.pass("stacked codings are removed last-applied first; FDICT is corrupt; br, zstd and unknown codings are unsupported")

-- 5. Stored blocks (RFC 1951 3.2.4), and the 32 KiB window across them.
local function rnd(n, s)
    local t = {}
    for i = 1, n do
        s = (s * 1103515245 + 12345) & 0x7fffffff
        t[i] = string.char(s >> 16 & 255)
    end
    return table.concat(t)
end
local A, B = rnd(65535, 1), rnd(40000, 2)
local st = W.new():stored(0, A):stored(0, B):put(1, 1):put(1, 2)
st:fixed(285):code(29, 5):put(32768 - 24577, 13) -- length 258, distance 32768
st:fixed(257):code(0, 5)                         -- length 3, distance 1
st:fixed(256)
local hist = A .. B
local copy = hist:sub(#hist - 32768 + 1, #hist - 32768 + 258)
local last = copy:sub(-1)
H.eq(coding.inflate_raw(st:bytes()), hist .. copy .. last:rep(3), "LEN 65535, then a match 32768 back into the stored bytes")
H.eq(coding.inflate_raw(W.new():stored(1, ""):bytes()), "", "an empty stored block")
H.pass("stored blocks of every length keep the last 32 KiB for later matches")

-- 6. The budget: output, block charges and FHCRC headers all count.
H.eq(coding.decode(FIG2, { "gzip" }, 19 + coding.BLOCK_COST), '{"hello": "world"}\n', "19 bytes + one fixed block")
H.eq(kind_of(FIG2, { "gzip" }), nil)
H.eq(select(2, coding.decode(FIG2, { "gzip" }, 19 + coding.BLOCK_COST - 1)), "limit", "one unit short")
H.eq(coding.BLOCK_COST, 16)
H.eq(coding.DYNAMIC_BLOCK_COST, 1024)
local dyn_ok -- craft-dyn-ok from the vector file: one dynamic block, 291 bytes
for line in io.lines(H.here .. "coding/vectors.tsv") do
    local input = line:match("^craft%-dyn%-ok\traw\t(%x+)\t")
    if input then dyn_ok = unhex(input) end
end
H.eq(#coding.inflate_raw(dyn_ok, 291 + 1024), 291, "291 bytes + one dynamic block")
H.eq(select(2, coding.inflate_raw(dyn_ok, 291 + 1023)), "limit")

local DEFAULT = 131072
local function timed(f)
    local t0 = os.clock()
    local a, b2, c = f()
    return os.clock() - t0, a, b2, c
end
local function bomb(name, input, codings)
    local dt, res, kind = timed(function() return coding.decode(input, codings, DEFAULT) end)
    H.eq(res, nil, name)
    H.eq(kind, "limit", name)
    H.eq(dt < 0.5, true, name .. (" took %.0f ms"):format(dt * 1000))
    return dt
end
local zeros = H.tmp("zeros")
assert(H.sh(("head -c 10485760 /dev/zero > '%s' && gzip -n -9 -c '%s' > '%s.gz' && gzip -n -9 -c '%s.gz' > '%s.gz.gz'")
    :format(zeros, zeros, zeros, zeros, zeros)))
local gz1, gz2 = H.read(zeros .. ".gz"), H.read(zeros .. ".gz.gz")
H.eq(#gz1 < 11000, true, "gzip -9 packs 10 MiB of zeros into about 10 KB")
bomb("10 MiB of zeros, gzip -9 (ratio ~1000)", gz1, { "gzip" })
bomb("the same, gzipped again (gzip, gzip)", gz2, { "gzip", "gzip" })

-- Floods of empty blocks: zlib accepts them (vectors many-empty-*), each
-- costs work, none produces output.
local function flood(name, one, count2)
    local w = W.new()
    for _ = 1, count2 do one(w) end
    w:put(1, 1):put(1, 2):fixed(256)
    local src = w:bytes()
    local dt, res, kind = timed(function() return coding.inflate_raw(src, DEFAULT) end)
    H.eq(res, nil, name)
    H.eq(kind, "limit", name)
    H.eq(dt < 0.5, true, name .. (" took %.0f ms"):format(dt * 1000))
    H.eq(coding.inflate_raw(src, BIG), "", name .. " decodes with no budget")
end
flood("8193 empty fixed blocks", function(w) w:put(0, 1):put(1, 2):fixed(256) end, DEFAULT // 16 + 1)
flood("8193 empty stored blocks", function(w) w:stored(0, "") end, DEFAULT // 16 + 1)
local L, D = {}, {}
for s = 0, 285 do L[s] = s < 226 and 8 or 9 end
for s = 0, 29 do D[s] = s < 2 and 4 or 5 end
local lc = W.canon(L, 286)
flood("129 empty dynamic blocks", function(w) w:dynamic(0, L, 286, D, 30):code(lc[256], L[256]) end, DEFAULT // 1024 + 1)

-- Every literal on a 15-bit code: the slowest bytes there are, still bounded.
local lit = {}
for s = 0, 285 do lit[s] = 0 end
for s = 0, 13 do lit[s] = s + 1 end
lit[65], lit[256] = 15, 15
local codes = W.canon(lit, 286)
local w15, k = W.new():dynamic(1, lit, 286, { [0] = 0 }, 1), 0
while not w15:aligned() do w15:code(codes[65], 15); k = k + 1 end -- 15 is odd: aligned within 8
local eight = W.new()
for _ = 1, 8 do eight:code(codes[65], 15) end
local long15 = w15:bytes() .. eight:bytes():rep(17500) .. W.new():code(codes[256], 15):bytes()
H.eq(coding.inflate_raw(long15, BIG), ("A"):rep(k + 140000), "15-bit codes decode through the subtables")
local dt15, res15, kind15 = timed(function() return coding.inflate_raw(long15, DEFAULT) end)
H.eq(res15, nil)
H.eq(kind15, "limit")
H.eq(dt15 < 0.5, true, ("128 KiB of 15-bit literals took %.0f ms"):format(dt15 * 1000))

-- FHCRC over a long FCOMMENT is work too.
local huge = "\31\139\8\18\0\0\0\0\0\255" .. ("c"):rep(1 << 20) .. "\0"
local hcrc = coding.crc32(huge) & 0xffff
local hdr = huge .. string.char(hcrc & 255, hcrc >> 8) .. deflated .. string.pack("<I4I4", coding.crc32('{"hello": "world"}\n'), 19)
H.eq(coding.decode(hdr, { "gzip" }, BIG), '{"hello": "world"}\n', "a 1 MiB FCOMMENT under FHCRC is valid")
local dth, resh, kindh = timed(function() return coding.decode(hdr, { "gzip" }, DEFAULT) end)
H.eq(resh, nil)
H.eq(kindh, "limit", "hashing it would cost more than the budget")
H.eq(dth < 0.1, true, ("refused in %.0f ms, before hashing"):format(dth * 1000))
H.pass("output, blocks (16, dynamic 1024) and FHCRC headers count; bombs, stacked bombs, block floods and 15-bit codes stop at the budget")

-- 7. Every truncation of a dynamic-Huffman gzip stream is corrupt, never a crash.
local letters = rnd(4000, 7):gsub(".", function(c) return string.char(97 + c:byte() % 16) end)
local gz = gzip_of(letters)
H.eq((gz:byte(11) >> 1) & 3, 2, "gzip -9 chose a dynamic block")
for n = 0, #gz - 1 do
    local good, res, kind = pcall(coding.decode, gz:sub(1, n), { "gzip" }, BIG)
    H.eq(good, true, "prefix " .. n .. " raised")
    H.eq(res, nil, "prefix " .. n)
    H.eq(kind, "corrupt", "prefix " .. n)
end
H.eq(coding.decode(gz, { "gzip" }, BIG), letters)
H.pass(("all %d prefixes of a %d-byte dynamic-Huffman gzip stream are corrupt"):format(#gz, #gz))

H.done("test_coding")
