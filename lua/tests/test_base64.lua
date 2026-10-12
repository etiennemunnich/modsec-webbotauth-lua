-- test_base64.lua: RFC 4648 section 10 vectors, RFC 9651 leniency, rejection.
-- Run: lua lua/tests/test_base64.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local b64 = require("wba.base64")

local vectors = {
    { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" },
    { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" },
}
for _, v in ipairs(vectors) do
    H.eq(b64.encode(v[1]), v[2], "encode " .. v[1])
    H.eq(b64.decode(v[2]), v[1], "decode " .. v[2])
end
H.pass("RFC 4648 section 10 test vectors encode and decode")

local all = {}
for n = 0, 255 do all[#all + 1] = string.char(n) end
all = table.concat(all)
for len = 0, 70 do
    local s = all:sub(1, len)
    H.eq(b64.decode(b64.encode(s)), s, "round trip length " .. len)
end
H.pass("every byte value round-trips at lengths 0..70")

-- RFC 9651 4.2.7: parsers SHOULD NOT fail on missing padding or non-zero pad bits.
H.eq(b64.decode("Zg"), "f", "missing padding")
H.eq(b64.decode("Zm8"), "fo", "missing padding")
H.eq(b64.decode("Zh=="), "f", "non-zero pad bits")
H.eq(b64.decode("Zg="), "f", "partial padding")
H.pass("missing or partial '=' padding and non-zero pad bits are tolerated (RFC 9651 4.2.7)")

for _, bad in ipairs({ "Z", "Zm9v=", "Zm8==", "Z===", "Zg==Zg==", "Zm9v!", "Zm 9v", "Zm9v\n", "Zm-_", "=Zg=" }) do
    H.eq(b64.decode(bad), nil, "must reject " .. bad)
end
H.pass("impossible lengths, misplaced or excess '=', and non-alphabet bytes are rejected")

H.done("test_base64")
