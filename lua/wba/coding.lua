--[[
coding.lua: the HTTP content codings an Unencoded-Digest check has to undo
(draft-ietf-httpbis-unencoded-digest-05 5: "a recipient needs to decode the
message in order to calculate the digest"). Pure Lua 5.3+.

  gzip     RFC 9110 8.4.1.3: the gzip file format, RFC 1952 (x-gzip is the
           same coding, 8.4.1.3: "SHOULD consider ... equivalent")
  deflate  RFC 9110 8.4.1.2: the zlib format, RFC 1950. Raw deflate without
           the zlib wrapper (8.4.1.2's note on non-conformant senders) is not
           the deflate coding and fails the zlib header check.

Both carry RFC 1951 deflate data, decoded here. Nothing else is: compress
(LZW), br (RFC 7932), zstd (RFC 8878), aes128gcm (RFC 8188) and unknown
codings are reported as unsupported before any byte is decoded (digest.lua).

Strict, as the formats are written, so the bytes this accepts decode the
same way in zlib (the reference implementation, behind most origins' decoders):
  * RFC 1952 2.2: a gzip file is a series of members, each decoded in turn;
    bytes after the last member that do not form a member are an error
    (zlib-based tools differ here: some stop at the first member, some skip
    trailing zeros; DESIGN.md, Body digests, says what that means for origins).
  * RFC 1952 2.3.1.2: reserved FLG bits set are an error; FHCRC, CRC32 and
    ISIZE are checked, as zlib does.
  * RFC 1950 2.2/2.3: CMF/FLG check, CM 8, CINFO <= 7 and ADLER32 are
    checked. FDICT is an error too: HTTP defines no preset dictionary, so
    "the compressor must not set the FDICT flag" and a decompressor "must
    give an error indication" (2.3). One zlib stream: trailing bytes are an
    error.
  * RFC 1951: block type 3, LEN/NLEN mismatch, over-subscribed codes,
    incomplete codes (except a single one-bit code, zlib's inflate_table
    rule), a missing end-of-block code, too many length or distance codes,
    literal/length 286-287, distance 30-31 and a distance before the start
    of the output are all errors, each as zlib reports it.

Bounded: decoding works against a budget of units and stops, "limit", the
moment the budget would go negative. Every byte any decoding stage produces
costs one unit; every deflate block costs M.BLOCK_COST more, a dynamic one
M.DYNAMIC_BLOCK_COST (its header builds Huffman tables); a gzip header
hashed for FHCRC costs its length. So a flood of empty blocks, or a huge
header, is bounded like a flood of output. Every symbol decodes with at most
two table lookups whatever code lengths the sender picks (zlib's two-level
tables), so no code makes a byte cost more than the measured worst case
(TESTING.md, Content codings). digest.lua sets the budget from
max_decoded_body and max_decode_ratio.

Errors are raised as { coding = "corrupt" | "limit" | "unsupported", why }
and caught by M.decode(); anything else raised is a bug and propagates.
--]]

local M = {}

local byte, char, concat, unpack = string.byte, string.char, table.concat, table.unpack

-- What a deflate block costs beyond its output, in units of one decoded byte
-- (TESTING.md, Content codings): an empty stored or fixed block costs at most
-- 3, so 16; a dynamic block's header and tables at most 892, so 1024.
M.BLOCK_COST, M.DYNAMIC_BLOCK_COST = 16, 1024

local function fail(kind, why) error({ coding = kind, why = why }, 0) end

-- RFC 1951 3.2.5: base values and extra bits for length codes 257..285 and
-- distance codes 0..29.
local LBASE = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
                131, 163, 195, 227, 258 }
local LEXT = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 }
local DBASE = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
                2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 }
local DEXT = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 }
-- RFC 1951 3.2.7: order of the code length code lengths.
local CLORDER = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 }

-- Decoding tables, as zlib builds them: the next ROOT bits index a root
-- table; a code longer than ROOT bits continues in a subtable, indexed by
-- the bits after the first ROOT. So every symbol costs at most two lookups,
-- whatever lengths a hostile code assigns. An entry is (symbol << 4) |
-- length; a link to a subtable is -((offset << 4) | subtable bits); nil is
-- a bit pattern no code uses.
local ROOT = 9
local RMASK9 = (1 << ROOT) - 1

--- Canonical Huffman code (RFC 1951 3.2.2) for symbols 0..n-1 whose code
--- lengths are lens[base + s]. `partial`: an incomplete code is allowed when
--- it is a single one-bit code (zlib inflate_table: literal/length and
--- distance codes; never the code length code). No codes at all is allowed
--- here; decoding a symbol from it fails.
local function build(lens, base, n, partial)
    local count = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
    local max = 0
    for s = base, base + n - 1 do
        local l = lens[s]
        if l > 0 then
            count[l] = count[l] + 1
            if l > max then max = l end
        end
    end
    local t = {}
    if max == 0 then return t end
    local left = 1
    for len = 1, 15 do
        left = (left << 1) - count[len]
        if left < 0 then fail("corrupt", "over-subscribed code") end
    end
    if left > 0 and not (partial and max == 1) then fail("corrupt", "incomplete code") end
    local nextcode, code = {}, 0
    for len = 1, 15 do
        nextcode[len] = code
        code = (code + count[len]) << 1
    end
    local long, sub = {}, {} -- codes over ROOT bits as r, length, symbol; longest per root index
    for s = 0, n - 1 do
        local l = lens[base + s]
        if l > 0 then
            local c = nextcode[l]
            nextcode[l] = c + 1
            -- Codes are packed most significant bit first (RFC 1951 3.1.1),
            -- so tables are indexed by the code reversed.
            local r = 0
            for _ = 1, l do
                r = (r << 1) | (c & 1)
                c = c >> 1
            end
            if l <= ROOT then
                local e = (s << 4) | l
                for i = r, RMASK9, 1 << l do t[i] = e end
            else
                long[#long + 1], long[#long + 2], long[#long + 3] = r, l, s
                local p = r & RMASK9
                if (sub[p] or 0) < l then sub[p] = l end
            end
        end
    end
    -- A prefix-free code never puts a short code on a long code's root index.
    local off = RMASK9 + 1
    for i = 1, #long, 3 do
        local p = long[i] & RMASK9
        local l = sub[p]
        if l then
            t[p] = -((off << 4) | (l - ROOT))
            off = off + (1 << (l - ROOT))
            sub[p] = nil
        end
    end
    for i = 1, #long, 3 do
        local r, l = long[i], long[i + 1]
        local link = -t[r & RMASK9]
        local at, e = link >> 4, (long[i + 2] << 4) | l
        for j = r >> ROOT, (1 << (link & 15)) - 1, 1 << (l - ROOT) do t[at + j] = e end
    end
    return t
end

--- The table entry for the code at the front of bb (bc valid bits), or a failure.
local function entry(t, bb, bc)
    local e = t[bb & RMASK9]
    if e and e < 0 then
        e = -e
        e = t[(e >> 4) + ((bb >> ROOT) & ((1 << (e & 15)) - 1))]
    end
    if not e then
        if bc < 15 then fail("corrupt", "unexpected end of data") end
        fail("corrupt", "invalid code")
    end
    if e & 15 > bc then fail("corrupt", "unexpected end of data") end
    return e
end

local fixed_lit, fixed_dist
local function fixed()
    if not fixed_lit then
        local l = {}
        for s = 0, 143 do l[s] = 8 end
        for s = 144, 255 do l[s] = 9 end
        for s = 256, 279 do l[s] = 7 end
        for s = 280, 287 do l[s] = 8 end
        fixed_lit = build(l, 0, 288, false)
        local d = {}
        for s = 0, 29 do d[s] = 5 end
        d[30], d[31] = 5, 5 -- coded, but invalid when used (RFC 1951 3.2.6)
        fixed_dist = build(d, 0, 32, false)
    end
    return fixed_lit, fixed_dist
end

local RING, RMASK = 65536, 65535 -- holds the 32 KiB window plus unflushed output
local ROOM = RING - 258          -- flush before a symbol once this much is unflushed

--- Inflates the RFC 1951 data in src starting at byte pos.
--- @param b budget { left = units }; left is reduced by what this costs
--- @return chunks (list of strings), length, position after the last byte used
local function inflate(src, pos, b)
    local srclen = #src
    local bitbuf, bitcnt = 0, 0
    local ring = {}
    local op, flushed = 0, 0 -- bytes produced; bytes moved from ring to chunks
    local chunks = {}
    local limit = b.left     -- op may not pass limit

    local function flush()
        local a = flushed
        while a < op do
            local s = (a & RMASK) + 1
            local n = op - a
            if n > RING - s + 1 then n = RING - s + 1 end
            if n > 4096 then n = 4096 end
            chunks[#chunks + 1] = char(unpack(ring, s, s + n - 1))
            a = a + n
        end
        flushed = op
    end

    local function bits(n)
        while bitcnt < n do
            if pos > srclen then fail("corrupt", "unexpected end of data") end
            bitbuf = bitbuf | (byte(src, pos) << bitcnt)
            pos = pos + 1
            bitcnt = bitcnt + 8
        end
        local v = bitbuf & ((1 << n) - 1)
        bitbuf = bitbuf >> n
        bitcnt = bitcnt - n
        return v
    end

    local function decode(t)
        while bitcnt < 15 and pos <= srclen do
            bitbuf = bitbuf | (byte(src, pos) << bitcnt)
            pos = pos + 1
            bitcnt = bitcnt + 8
        end
        local e = entry(t, bitbuf, bitcnt)
        local n = e & 15
        bitbuf = bitbuf >> n
        bitcnt = bitcnt - n
        return e >> 4
    end

    -- Huffman-coded block data (RFC 1951 3.2.5), the hot loop. The shared
    -- state is copied into locals here and written back on the way out.
    local function codes(lt, dt)
        local lim = limit
        local bb, bc, p, o, fl = bitbuf, bitcnt, pos, op, flushed
        while true do
            if bc < 48 then
                if bc <= 32 and p + 3 <= srclen then
                    local a1, a2, a3, a4 = byte(src, p, p + 3)
                    bb = bb | (((a4 << 24) | (a3 << 16) | (a2 << 8) | a1) << bc)
                    p = p + 4
                    bc = bc + 32
                end
                while bc <= 56 and p <= srclen do
                    bb = bb | (byte(src, p) << bc)
                    p = p + 1
                    bc = bc + 8
                end
            end
            local e = lt[bb & RMASK9]
            if not e or e < 0 then e = entry(lt, bb, bc) end
            local s, n = e >> 4, e & 15
            if n > bc then fail("corrupt", "unexpected end of data") end
            bb = bb >> n
            bc = bc - n
            if s < 256 then
                if o >= lim then fail("limit", "decoded size") end
                if o - fl > ROOM then
                    op = o
                    flush()
                    fl = o
                end
                ring[(o & RMASK) + 1] = s
                o = o + 1
            elseif s == 256 then
                bitbuf, bitcnt, pos, op = bb, bc, p, o
                return
            else
                s = s - 256
                if s > 29 then fail("corrupt", "invalid literal/length code") end
                local len, x = LBASE[s], LEXT[s]
                if x > 0 then
                    if x > bc then fail("corrupt", "unexpected end of data") end
                    len = len + (bb & ((1 << x) - 1))
                    bb = bb >> x
                    bc = bc - x
                end
                e = dt[bb & RMASK9]
                if not e or e < 0 then e = entry(dt, bb, bc) end
                s, n = e >> 4, e & 15
                if n > bc then fail("corrupt", "unexpected end of data") end
                bb = bb >> n
                bc = bc - n
                if s > 29 then fail("corrupt", "invalid distance code") end
                local d
                d, x = DBASE[s + 1], DEXT[s + 1]
                if x > 0 then
                    if x > bc then fail("corrupt", "unexpected end of data") end
                    d = d + (bb & ((1 << x) - 1))
                    bb = bb >> x
                    bc = bc - x
                end
                if d > o then fail("corrupt", "invalid distance too far back") end
                if o + len > lim then fail("limit", "decoded size") end
                if o - fl > ROOM then
                    op = o
                    flush()
                    fl = o
                end
                local from = o - d
                for i = 0, len - 1 do
                    ring[((o + i) & RMASK) + 1] = ring[((from + i) & RMASK) + 1]
                end
                o = o + len
            end
        end
    end

    local function stored()
        bitbuf, bitcnt = bitbuf >> (bitcnt & 7), bitcnt - (bitcnt & 7) -- RFC 1951 3.2.4: to a byte boundary
        local len, nlen = bits(16), bits(16)
        if len ~= (~nlen & 0xffff) then fail("corrupt", "invalid stored block lengths") end
        pos = pos - (bitcnt >> 3) -- give back whole bytes already read ahead
        bitbuf, bitcnt = 0, 0
        if pos + len - 1 > srclen then fail("corrupt", "unexpected end of data") end
        if op + len > limit then fail("limit", "decoded size") end
        flush()
        if len > 0 then chunks[#chunks + 1] = src:sub(pos, pos + len - 1) end
        -- Only the last 32 KiB can be referred to later: keep that in the ring.
        local keep = len < 32768 and len or 32768
        local first = pos + len - keep
        for i = 0, keep - 1, 256 do
            local m = keep - i < 256 and keep - i or 256
            local t = { byte(src, first + i, first + i + m - 1) }
            local at = op + len - keep + i
            for k = 1, m do ring[((at + k - 1) & RMASK) + 1] = t[k] end
        end
        pos = pos + len
        op = op + len
        flushed = op
    end

    local function dynamic()
        local nlen, ndist, ncode = bits(5) + 257, bits(5) + 1, bits(4) + 4
        if nlen > 286 or ndist > 30 then fail("corrupt", "too many length or distance symbols") end
        local cl = {}
        for i = 0, 18 do cl[i] = 0 end
        for i = 1, ncode do cl[CLORDER[i]] = bits(3) end
        local clh = build(cl, 0, 19, false)
        local lens, n = {}, 0
        while n < nlen + ndist do
            local s = decode(clh)
            if s < 16 then
                lens[n] = s
                n = n + 1
            else
                local v, rep = 0
                if s == 16 then
                    if n == 0 then fail("corrupt", "invalid bit length repeat") end
                    v, rep = lens[n - 1], 3 + bits(2)
                elseif s == 17 then
                    rep = 3 + bits(3)
                else
                    rep = 11 + bits(7)
                end
                if n + rep > nlen + ndist then fail("corrupt", "invalid bit length repeat") end
                for _ = 1, rep do
                    lens[n] = v
                    n = n + 1
                end
            end
        end
        if lens[256] == 0 then fail("corrupt", "invalid code -- missing end-of-block") end
        return build(lens, 0, nlen, true), build(lens, nlen, ndist, true)
    end

    repeat
        local last, kind = bits(1), bits(2)
        limit = limit - (kind == 2 and M.DYNAMIC_BLOCK_COST or M.BLOCK_COST)
        if op > limit then fail("limit", "blocks") end
        if kind == 0 then
            stored()
        elseif kind == 1 then
            codes(fixed())
        elseif kind == 2 then
            codes(dynamic())
        else
            fail("corrupt", "invalid block type")
        end
    until last == 1
    flush()
    b.left = limit - op
    -- The rest of the last byte is padding; whole bytes read ahead are not used.
    return chunks, op, pos - (bitcnt >> 3)
end

-- CRC-32 (RFC 1952 8) and Adler-32 (RFC 1950 9), over strings.
local CRC = {}
for n = 0, 255 do
    local c = n
    for _ = 1, 8 do
        if c & 1 == 1 then c = 0xedb88320 ~ (c >> 1) else c = c >> 1 end
    end
    CRC[n] = c
end

local function crc32(crc, s, i, j)
    crc = ~crc & 0xffffffff
    for k = i, j, 64 do
        local t = { byte(s, k, k + 63 < j and k + 63 or j) }
        for m = 1, #t do crc = CRC[(crc ~ t[m]) & 0xff] ~ (crc >> 8) end
    end
    return ~crc & 0xffffffff
end

local function adler32(a, s)
    local s1, s2 = a & 0xffff, a >> 16
    local n = #s
    for k = 1, n, 64 do
        local t = { byte(s, k, k + 63 < n and k + 63 or n) }
        for m = 1, #t do
            s1 = s1 + t[m]
            s2 = s2 + s1
        end
        s1, s2 = s1 % 65521, s2 % 65521 -- 64 bytes cannot overflow 64-bit integers
    end
    return (s2 << 16) | s1
end
M.crc32 = function(s) return crc32(0, s, 1, #s) end
M.adler32 = function(s) return adler32(1, s) end

local function u32le(s, i)
    local a, b, c, d = byte(s, i, i + 3)
    return a | (b << 8) | (c << 16) | (d << 24)
end

--- RFC 1952: every member of a gzip file, in order.
local function gunzip(src, b)
    local n, pos, out = #src, 1, {}
    if n == 0 then fail("corrupt", "unexpected end of data") end
    repeat
        if pos + 9 > n then fail("corrupt", "unexpected end of data") end
        local id1, id2, cm, flg = byte(src, pos, pos + 3)
        if id1 ~= 0x1f or id2 ~= 0x8b then fail("corrupt", "incorrect header check") end
        if cm ~= 8 then fail("corrupt", "unknown compression method") end
        if flg & 0xe0 ~= 0 then fail("corrupt", "unknown header flags set") end
        local start = pos
        pos = pos + 10
        if flg & 4 ~= 0 then -- FEXTRA
            if pos + 1 > n then fail("corrupt", "unexpected end of data") end
            local x1, x2 = byte(src, pos, pos + 1)
            pos = pos + 2 + (x1 | (x2 << 8))
        end
        for _, f in ipairs({ 8, 16 }) do -- FNAME, FCOMMENT: zero-terminated
            if flg & f ~= 0 then
                local z = src:find("\0", pos, true)
                if not z then fail("corrupt", "unexpected end of data") end
                pos = z + 1
            end
        end
        if flg & 2 ~= 0 then -- FHCRC: the low 16 bits of the header's CRC-32
            if pos + 1 > n then fail("corrupt", "unexpected end of data") end
            -- FNAME and FCOMMENT can be as long as the body: hashing them is work.
            b.left = b.left - (pos - start)
            if b.left < 0 then fail("limit", "header size") end
            local h1, h2 = byte(src, pos, pos + 1)
            if (h1 | (h2 << 8)) ~= crc32(0, src, start, pos - 1) & 0xffff then
                fail("corrupt", "header crc mismatch")
            end
            pos = pos + 2
        end
        if pos > n then fail("corrupt", "unexpected end of data") end
        local chunks, size, after = inflate(src, pos, b)
        pos = after
        if pos + 7 > n then fail("corrupt", "unexpected end of data") end
        local crc = 0
        for _, c in ipairs(chunks) do crc = crc32(crc, c, 1, #c) end
        if u32le(src, pos) ~= crc then fail("corrupt", "incorrect data check") end
        if u32le(src, pos + 4) ~= size & 0xffffffff then fail("corrupt", "incorrect length check") end
        pos = pos + 8
        out[#out + 1] = concat(chunks)
    until pos > n
    return concat(out)
end

--- RFC 1950: one zlib stream, nothing after it.
local function unzlib(src, b)
    local n = #src
    if n < 2 then fail("corrupt", "unexpected end of data") end
    local cmf, flg = byte(src, 1, 2)
    if ((cmf << 8) | flg) % 31 ~= 0 then fail("corrupt", "incorrect header check") end
    if cmf & 15 ~= 8 then fail("corrupt", "unknown compression method") end
    if cmf >> 4 > 7 then fail("corrupt", "invalid window size") end
    if flg & 0x20 ~= 0 then fail("corrupt", "preset dictionary") end
    local chunks, _, pos = inflate(src, 3, b)
    if pos + 3 > n then fail("corrupt", "unexpected end of data") end
    local a = 1
    for _, c in ipairs(chunks) do a = adler32(a, c) end
    local b1, b2, b3, b4 = byte(src, pos, pos + 3)
    if ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4) ~= a then fail("corrupt", "incorrect data check") end
    if pos + 4 <= n then fail("corrupt", "trailing data after the zlib stream") end
    return concat(chunks)
end

M.DECODERS = { gzip = gunzip, deflate = unzlib }

--- Removes `codings` (Content-Encoding order, i.e. the order applied) from
--- body, last applied first (RFC 9110 8.4).
--- @param budget units of work allowed (see the header comment)
--- @return the decoded string; or nil, "corrupt" | "limit" | "unsupported", why
function M.decode(body, codings, budget)
    local b = { left = budget }
    local ok, res = pcall(function()
        local data = body
        for i = #codings, 1, -1 do
            local d = M.DECODERS[codings[i]]
            if not d then fail("unsupported", codings[i]) end
            data = d(data, b)
        end
        return data
    end)
    if ok then return res end
    if type(res) == "table" and res.coding then return nil, res.coding, res.why end
    error(res, 0)
end

--- Raw RFC 1951 data, for tests: the decoded string and the position after
--- the last byte used; or nil, kind, why.
function M.inflate_raw(src, budget)
    local ok, chunks, _, after = pcall(inflate, src, 1, { left = budget or math.maxinteger })
    if ok then return concat(chunks), after end
    if type(chunks) == "table" and chunks.coding then return nil, chunks.coding, chunks.why end
    error(chunks, 0)
end

return M
