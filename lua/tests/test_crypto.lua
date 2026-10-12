-- test_crypto.lua: crypto.lua, the lua-openssl adapter, against signatures
-- the openssl CLI makes and the published RFC 9421 and draft vectors.
-- Needs lua-openssl: it runs in the image's test stage, where
-- WBA_REQUIRE_OPENSSL=1 makes a missing module a failure; elsewhere it is
-- skipped (reported, never passed). Wycheproof vectors: wycheproof/run.lua.
-- Run: lua lua/tests/test_crypto.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")

local ok, crypto = pcall(require, "wba.crypto")
if not ok then
    if os.getenv("WBA_REQUIRE_OPENSSL") == "1" then error("lua-openssl required here but did not load: " .. tostring(crypto)) end
    print("SKIP: lua-openssl not installed; crypto.lua is tested in the image's test stage")
    H.done("test_crypto")
    return
end
local openssl = require("openssl")
local sf = require("wba.structured_fields")
local sigbase = require("wba.sigbase")
local b64 = require("wba.base64")
local V = require("rfc_vectors")

local function raises(fn, msg) H.eq(pcall(fn), false, msg) end
local function quiet_queue(msg) H.eq(openssl.error(), nil, msg .. ": OpenSSL error queue left empty") end

-- 1. Every algorithm, against openssl-made signatures: a good one verifies,
-- a changed message or signature does not.
local keys = { ed25519 = H.new_key("ed25519"), p256 = H.new_key("p256"), p384 = H.new_key("p384"),
               rsa2048 = H.new_key("rsa", 2048), rsa3072 = H.new_key("rsa", 3072), rsa4096 = H.new_key("rsa", 4096) }
local cases = {
    { keys.ed25519, "ed25519" }, { keys.p256, "ecdsa-p256-sha256" }, { keys.p384, "ecdsa-p384-sha384" },
    { keys.rsa2048, "rsa-pss-sha512" }, { keys.rsa2048, "rsa-v1_5-sha256" }, { keys.rsa3072, "rsa-pss-sha512" },
    { keys.rsa3072, "rsa-v1_5-sha256" }, { keys.rsa4096, "rsa-pss-sha512" }, { keys.rsa4096, "rsa-v1_5-sha256" },
}
local signed = 0
for _, c in ipairs(cases) do
    local key, alg = c[1], c[2]
    for n = 1, (key.type:match("^ec") and 8 or 2) do -- 8 ECDSA signatures: r or s with its top bit set, and not
        local msg = ("signature base %d for %s"):format(n, alg)
        local sig = H.sign(key, msg, alg)
        H.eq(crypto.verify(alg, key.entry, sig, msg), true, alg .. " good")
        H.eq(crypto.verify(alg, key.entry, sig, msg .. "x"), false, alg .. " changed message")
        quiet_queue(alg .. " failure")
        local flipped = sig:sub(1, 10) .. string.char(sig:byte(11) ~ 1) .. sig:sub(12)
        H.eq(crypto.verify(alg, key.entry, flipped, msg), false, alg .. " changed signature")
        signed = signed + 1
    end
end
H.pass(signed .. " openssl signatures over 5 algorithms (RSA 2048, 3072, 4096 bits) verify; changed messages and signatures do not")

-- 2. The published vectors: RFC 9421 B.2.1-B.2.4 (rsa-pss-sha512 and
-- ecdsa-p256-sha256) and B.2.6 (ed25519); the draft's E.1 (rsa-pss-sha512)
-- and E.2 (ed25519) bases, as test_sigbase rebuilds them.
local function base_for(sig_input, label, values)
    local member = sf.parse_dictionary(sig_input)[label]
    local covered = {}
    for n, item in ipairs(member.items) do covered[n] = { item = item, value = values[sf.serialize_item(item)] } end
    return assert(sigbase.build(covered, member.params))
end
H.eq(crypto.verify("rsa-pss-sha512", V.RSA_PSS_KEY, b64.decode(V.B2[1].sig),
    '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"'), true, "B.2.1")
for n = 2, 4 do
    local v = V.B2[n]
    H.eq(crypto.verify(v.alg, v.key, b64.decode(v.sig), base_for(v.input, v.label, v.values)), true, v.name)
end
for _, v in ipairs(V.E1) do H.eq(crypto.verify("rsa-pss-sha512", V.RSA_PSS_KEY, V.sig_bytes(v.sig), v.base), true, v.name) end
local ed_rfc = { type = "ed25519", key = H.RFC_KEY_RAW }
H.eq(crypto.verify("ed25519", ed_rfc,
    b64.decode("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="),
    '"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@method": POST\n"@path": /foo\n"@authority": example.com\n'
    .. '"content-type": application/json\n"content-length": 18\n'
    .. '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'),
    true, "RFC 9421 B.2.6")
H.pass("RFC 9421 B.2.1-B.2.4 and B.2.6, draft E.1.1 and E.1.2 verify with lua-openssl")

-- 3. RSA-PSS is exactly RFC 9421 3.3.1: SHA-512, MGF1 with SHA-512, sLen 64.
local rsa = keys.rsa2048
local msg = "pss parameters"
local function pss(o)
    local m, s = H.tmp("pss.msg"), H.tmp("pss.sig")
    H.write(m, msg)
    assert(H.sh(("openssl dgst -%s -sign '%s' -sigopt rsa_padding_mode:pss -sigopt rsa_mgf1_md:%s -sigopt rsa_pss_saltlen:%d -out '%s' '%s'")
        :format(o.md or "sha512", rsa.priv, o.mgf1 or "sha512", o.salt or 64, s, m)))
    return crypto.verify("rsa-pss-sha512", rsa.entry, H.read(s), msg)
end
H.eq(pss({}), true, "SHA-512, MGF1-SHA-512, salt 64")
for _, salt in ipairs({ 0, 32, 63, 65 }) do H.eq(pss({ salt = salt }), false, "salt " .. salt .. " (never auto-detected)") end
H.eq(pss({ mgf1 = "sha256" }), false, "MGF1 with SHA-256")
H.eq(pss({ md = "sha256", salt = 32 }), false, "SHA-256")
H.eq(crypto.verify("rsa-pss-sha512", rsa.entry, H.sign(rsa, msg, "rsa-v1_5-sha256"), msg), false, "a v1.5 signature as PSS")
H.eq(crypto.verify("rsa-v1_5-sha256", rsa.entry, H.sign(rsa, msg, "rsa-pss-sha512"), msg), false, "a PSS signature as v1.5")
quiet_queue("PSS")
H.pass("RSA-PSS: salt 0, 32, 63 or 65, MGF1-SHA-256 and SHA-256 refused; PSS and v1.5 never confused")

-- 4. ECDSA is r || s at its exact width (RFC 9421 3.3.4, 3.3.5); DER is
-- refused; out-of-range r or s fail inside OpenSSL.
for _, key in ipairs({ keys.p256, keys.p384 }) do
    local alg = H.DEFAULT_ALG[key.type]
    local der = H.sign(key, msg, alg, { der = true })
    raises(function() crypto.verify(alg, key.entry, der, msg) end, alg .. ": a DER signature (" .. #der .. " bytes)")
    local raw = H.sign(key, msg, alg)
    raises(function() crypto.verify(alg, key.entry, raw .. "\0", msg) end, alg .. ": one byte more")
    raises(function() crypto.verify(alg, key.entry, raw:sub(2), msg) end, alg .. ": one byte less")
    local half = #raw // 2
    H.eq(crypto.verify(alg, key.entry, ("\0"):rep(half) .. raw:sub(half + 1), msg), false, alg .. ": r = 0")
    H.eq(crypto.verify(alg, key.entry, raw:sub(1, half) .. ("\0"):rep(half), msg), false, alg .. ": s = 0")
    H.eq(crypto.verify(alg, key.entry, raw:sub(half + 1) .. raw:sub(1, half), msg), false, alg .. ": r and s swapped")
    quiet_queue(alg)
end
H.pass("ECDSA: DER and wrong widths raise, r = 0, s = 0 and swapped halves fail")

-- 5. A key is only ever used for its own algorithms, and must be a key.
raises(function() crypto.verify("ecdsa-p256-sha256", keys.ed25519.entry, ("\1"):rep(64), msg) end, "Ed25519 key, ECDSA")
raises(function() crypto.verify("ed25519", keys.p256.entry, ("\1"):rep(64), msg) end, "P-256 key, Ed25519")
raises(function() crypto.verify("ecdsa-p384-sha384", keys.p256.entry, ("\1"):rep(96), msg) end, "P-256 key, P-384")
raises(function() crypto.verify("rsa-pss-sha512", keys.p256.entry, ("\1"):rep(256), msg) end, "P-256 key, RSA-PSS")
raises(function() crypto.verify("hmac-sha256", rsa.entry, ("\1"):rep(32), msg) end, "hmac-sha256 (draft 6.4)")
local off = { type = "ec-p256", key = keys.p256.entry.key:sub(1, -2) .. string.char(keys.p256.entry.key:byte(-1) ~ 1) }
raises(function() crypto.verify("ecdsa-p256-sha256", off, H.sign(keys.p256, msg), msg) end, "a P-256 point not on the curve")
raises(function() crypto.verify("ecdsa-p256-sha256", { type = "ec-p256", key = keys.p384.entry.key }, ("\1"):rep(64), msg) end,
    "a P-384 point as P-256")
quiet_queue("unusable keys")
H.pass("an algorithm for another key type raises; an off-curve or wrong-curve point raises")

H.done("test_crypto")
