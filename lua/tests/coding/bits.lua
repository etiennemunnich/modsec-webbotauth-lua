--[[
bits.lua: builds RFC 1951 streams for test_coding.lua, for the shapes too
large to keep in vectors.tsv (bombs, floods of empty blocks, hostile codes).
Small shapes of every kind are in vectors.tsv, where zlib decided them.
--]]

local W = {}
W.__index = W

function W.new() return setmetatable({ out = {}, acc = 0, n = 0 }, W) end

--- n bits of v, least significant first (RFC 1951 3.1.1).
function W:put(v, n)
    for i = 0, n - 1 do
        self.acc = self.acc | (((v >> i) & 1) << self.n)
        self.n = self.n + 1
        if self.n == 8 then
            self.out[#self.out + 1] = string.char(self.acc)
            self.acc, self.n = 0, 0
        end
    end
    return self
end

--- A Huffman code, most significant bit first.
function W:code(c, len)
    for i = len - 1, 0, -1 do self:put((c >> i) & 1, 1) end
    return self
end

function W:aligned() return self.n == 0 end

--- Appends bytes; only at a byte boundary.
function W:raw(s)
    assert(self.n == 0, "raw bytes off a byte boundary")
    self.out[#self.out + 1] = s
    return self
end

function W:bytes()
    if self.n > 0 then self.out[#self.out + 1] = string.char(self.acc) end
    self.acc, self.n = 0, 0
    return table.concat(self.out)
end

--- Canonical codes from code lengths (RFC 1951 3.2.2); lens[s] for s = 0..n-1.
function W.canon(lens, n)
    local count, next_code, codes = {}, {}, {}
    for b = 0, 15 do count[b] = 0 end
    for s = 0, n - 1 do if lens[s] > 0 then count[lens[s]] = count[lens[s]] + 1 end end
    local code = 0
    for b = 1, 15 do
        code = (code + count[b - 1]) << 1
        next_code[b] = code
    end
    for s = 0, n - 1 do
        local l = lens[s]
        if l > 0 then
            codes[s] = next_code[l]
            next_code[l] = next_code[l] + 1
        end
    end
    return codes
end

--- Fixed Huffman literal/length code (RFC 1951 3.2.6).
function W:fixed(s)
    if s < 144 then return self:code(0x30 + s, 8) end
    if s < 256 then return self:code(0x190 + s - 144, 9) end
    if s < 280 then return self:code(s - 256, 7) end
    return self:code(0xc0 + s - 280, 8)
end

--- A dynamic block header (RFC 1951 3.2.7) for literal/length lengths
--- lit[0..nlen-1] and distance lengths dist[0..ndist-1], each written as is
--- with a complete code length code (13 symbols of 4 bits, 6 of 5).
function W:dynamic(last, lit, nlen, dist, ndist)
    local ORDER = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 }
    local cl = {}
    for s = 0, 18 do cl[s] = s >= 13 and 5 or 4 end
    local clc = W.canon(cl, 19)
    self:put(last, 1):put(2, 2):put(nlen - 257, 5):put(ndist - 1, 5):put(19 - 4, 4)
    for i = 1, 19 do self:put(cl[ORDER[i]], 3) end
    for s = 0, nlen - 1 do self:code(clc[lit[s]], cl[lit[s]]) end
    for s = 0, ndist - 1 do self:code(clc[dist[s]], cl[dist[s]]) end
    return self
end

--- A stored block (RFC 1951 3.2.4) holding data.
function W:stored(last, data)
    self:put(last, 1):put(0, 2)
    if self.n > 0 then self:put(0, 8 - self.n) end
    local n = #data
    return self:raw(string.char(n & 255, n >> 8, ~n & 255, (~n >> 8) & 255) .. data)
end

return W
