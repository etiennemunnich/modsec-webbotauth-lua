-- test_sha256.lua: sha256.lua against the FIPS 180-4 example vectors and,
-- as an independent oracle, openssl for every message length 0..1000 (every
-- padding boundary: 55/56/63/64 bytes and their multi-block repeats). Where
-- lua-openssl loads (the image's test stage, which sets
-- WBA_REQUIRE_OPENSSL=1 so it cannot be skipped there), wba.crypto's sha512
-- gets the same comparison.
-- Run: lua lua/tests/test_sha256.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local sha256 = require("wba.sha256")

local function hex(s) return (s:gsub(".", function(c) return ("%02x"):format(c:byte()) end)) end

-- 1. FIPS 180-4 / NIST CSRC example vectors.
H.eq(hex(sha256.digest("")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
H.eq(hex(sha256.digest("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
H.eq(hex(sha256.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
H.eq(hex(sha256.digest("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
H.eq(hex(sha256.digest(("a"):rep(1000000))), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
H.pass("FIPS 180-4 vectors: empty, abc, 448-bit, 896-bit, one million 'a'")

-- 2. RFC 9421 7.2.8's Content-Digest example.
local base64 = require("wba.base64")
H.eq(base64.encode(sha256.digest('{"hello": "world"}')), "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
H.pass("RFC 9421 7.2.8: sha-256 of {\"hello\": \"world\"}")

-- 3. Differential against openssl, lengths 0..1000, all 256 byte values.
local N = 1000
local seed = 0x9e3779b9
local function byte()
    seed = (seed * 1103515245 + 12345) & 0x7fffffff
    return seed >> 16 & 0xff
end
local files = {}
for n = 0, N do
    local t = {}
    for i = 1, n do t[i] = string.char(byte()) end
    local f = H.tmp(("m%04d"):format(n))
    H.write(f, table.concat(t))
    files[#files + 1] = f
end
local out = H.tmp("openssl.txt")
assert(H.sh(("cd '%s' && openssl dgst -sha256 -r m* > '%s'"):format(H.tmp(""), out)))
local want = {}
for digest, name in H.read(out):gmatch("(%x+) %*?([^\n]+)") do want[name:match("m%d+$")] = digest end
local checked = 0
for n = 0, N do
    local name = ("m%04d"):format(n)
    H.eq(hex(sha256.digest(H.read(files[n + 1]))), want[name], "length " .. n)
    checked = checked + 1
end
H.eq(checked, N + 1)
H.pass(checked .. " messages, lengths 0.." .. N .. ", agree with openssl")

-- 4. wba.crypto's SHA-512 (lua-openssl), the other digest provider, the same way.
local ok, crypto = pcall(require, "wba.crypto")
if ok then
    assert(H.sh(("cd '%s' && openssl dgst -sha512 -r m* > '%s'"):format(H.tmp(""), out)))
    local want512 = {}
    for digest, name in H.read(out):gmatch("(%x+) %*?([^\n]+)") do want512[name:match("m%d+$")] = digest end
    for n = 0, N do
        H.eq(hex(crypto.sha512(H.read(files[n + 1]))), want512[("m%04d"):format(n)], "sha512 length " .. n)
    end
    H.pass("wba.crypto sha512: " .. (N + 1) .. " messages agree with openssl")
elseif os.getenv("WBA_REQUIRE_OPENSSL") == "1" then
    error("lua-openssl required here but did not load: " .. tostring(crypto))
else
    print("SKIP: lua-openssl not installed; wba.crypto's sha512 is compared in the image's test stage")
end

H.done("test_sha256")
