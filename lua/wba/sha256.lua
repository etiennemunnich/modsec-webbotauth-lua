--[[
sha256.lua: SHA-256 (FIPS 180-4, section 6.2) in pure Lua 5.3+.

RFC 9530 Content-Digest checks need SHA-256. When this was written nothing
the CRS images load provided it: libmodsecurity's transformations stop at
sha1 and md5, and luamonocypher had SHA-512 only. lua-openssl (crypto.lua)
now has it; moving to it would lift the 128 KiB body cap (DESIGN.md, Crypto
dependency) and is a separate change. Lua 5.3 integers are 64-bit, so every
32-bit word is kept in range with & 0xffffffff after any operation that can
carry past bit 31.

Tested against the FIPS 180-4 example vectors and against openssl for every
message length from 0 to 1000 bytes (lua/tests/test_sha256.lua).
--]]

local M = {}

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local unpack16 = ">" .. ("I4"):rep(16)
local spack, sunpack = string.pack, string.unpack

--- Compresses the 64-byte block of s starting at byte i into state H.
local function block(H, W, s, i)
    W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8],
    W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] = sunpack(unpack16, s, i)
    for j = 17, 64 do
        local x, y = W[j - 15], W[j - 2]
        local s0 = (x >> 7 | x << 25) ~ (x >> 18 | x << 14) ~ (x >> 3)
        local s1 = (y >> 17 | y << 15) ~ (y >> 19 | y << 13) ~ (y >> 10)
        W[j] = (W[j - 16] + s0 + W[j - 7] + s1) & 0xffffffff
    end
    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for j = 1, 64 do
        -- The rotations leave bits above 31; the final mask clears them.
        local S1 = (e >> 6 | e << 26) ~ (e >> 11 | e << 21) ~ (e >> 25 | e << 7)
        local ch = (e & f) ~ (~e & g)
        local t1 = (h + S1 + ch + K[j] + W[j]) & 0xffffffff
        local S0 = (a >> 2 | a << 30) ~ (a >> 13 | a << 19) ~ (a >> 22 | a << 10)
        local maj = (a & b) ~ (a & c) ~ (b & c)
        h, g, f = g, f, e
        e = (d + t1) & 0xffffffff
        d, c, b = c, b, a
        a = (t1 + S0 + maj) & 0xffffffff
    end
    H[1], H[2], H[3], H[4] = (H[1] + a) & 0xffffffff, (H[2] + b) & 0xffffffff, (H[3] + c) & 0xffffffff, (H[4] + d) & 0xffffffff
    H[5], H[6], H[7], H[8] = (H[5] + e) & 0xffffffff, (H[6] + f) & 0xffffffff, (H[7] + g) & 0xffffffff, (H[8] + h) & 0xffffffff
end

--- The 32-byte SHA-256 digest of string s.
function M.digest(s)
    local H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
    local W = {}
    local n = #s
    local full = n - n % 64
    for i = 1, full, 64 do block(H, W, s, i) end
    -- Padding (5.1.1): 0x80, zeros to 56 mod 64, then the bit length. Built
    -- from the tail only, so a large body is never copied.
    local tail = s:sub(full + 1) .. "\128" .. ("\0"):rep((55 - n) % 64) .. spack(">I8", n * 8)
    for i = 1, #tail, 64 do block(H, W, tail, i) end
    return spack(">I4I4I4I4I4I4I4I4", H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8])
end

return M
