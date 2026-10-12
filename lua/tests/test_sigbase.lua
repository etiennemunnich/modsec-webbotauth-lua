-- test_sigbase.lua: signature bases must match published vectors byte-for-byte,
-- and the published signatures must verify over them (openssl oracle).
-- Vectors: RFC 9421 Appendix B.2.6; draft-ietf-webbotauth-httpsig-protocol
-- Appendix E.2.1 and E.2.2. Run: lua lua/tests/test_sigbase.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local sf = require("wba.structured_fields")
local sigbase = require("wba.sigbase")
local b64 = require("wba.base64")

--- Build a base from a Signature-Input member and a name -> value map, the
--- same way verify.lua does, then compare with the published base text.
local function base_for(sig_input, label, values_by_id)
    local member = sf.parse_dictionary(sig_input)[label]
    local covered = {}
    for n, item in ipairs(member.items) do
        covered[n] = { item = item, value = values_by_id[sf.serialize_item(item)] }
    end
    return sigbase.build(covered, member.params)
end

-- 1. RFC 9421 B.2.6
local rfc_base = base_for(
    'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    "sig-b26", {
        ['"date"'] = "Tue, 20 Apr 2021 02:07:55 GMT", ['"@method"'] = "POST", ['"@path"'] = "/foo",
        ['"@authority"'] = "example.com", ['"content-type"'] = "application/json", ['"content-length"'] = "18",
    })
H.eq(rfc_base,
    '"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@method": POST\n"@path": /foo\n"@authority": example.com\n'
    .. '"content-type": application/json\n"content-length": 18\n'
    .. '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    "RFC 9421 B.2.6 base")
H.eq(H.ed25519_verify(H.RFC_KEY_RAW,
    b64.decode("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="), rfc_base),
    true, "RFC signature over our base")
H.pass("RFC 9421 B.2.6: base byte-exact, RFC signature verifies over it")

-- 2. Draft E.2.1 (dictionary Signature-Agent, covered with ;key="agent2")
local e21_input = 'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"'
local e21_base = base_for(e21_input, "sig2", {
    ['"@authority"'] = "example.com",
    ['"signature-agent";key="agent2"'] = '"https://signature-agent.test"',
})
H.eq(e21_base,
    '"@authority": example.com\n"signature-agent";key="agent2": "https://signature-agent.test"\n'
    .. '"@signature-params": ("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"',
    "draft E.2.1 base")
H.eq(H.ed25519_verify(H.RFC_KEY_RAW,
    b64.decode("RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg=="), e21_base),
    true, "draft E.2.1 signature")
H.pass("draft E.2.1: base byte-exact, published signature verifies over it")

-- 3. Draft E.2.2 (legacy bare-string Signature-Agent)
local e22_input = 'sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"'
local e22_base = base_for(e22_input, "sig2", {
    ['"@authority"'] = "example.com",
    ['"signature-agent"'] = '"https://signature-agent.test"',
})
H.eq(e22_base,
    '"@authority": example.com\n"signature-agent": "https://signature-agent.test"\n'
    .. '"@signature-params": ("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"',
    "draft E.2.2 base")
H.eq(H.ed25519_verify(H.RFC_KEY_RAW,
    b64.decode("jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA=="), e22_base),
    true, "draft E.2.2 signature")
H.pass("draft E.2.2: base byte-exact, published signature verifies over it")

-- 3b. RSA-PSS and ECDSA: RFC 9421 B.2.1-B.2.4 and the draft's E.1.1 and
-- E.1.2. Those signatures are randomized (RFC 9421 7.3.5), so a base one
-- byte off cannot pass: each verifying (openssl) over the base built here
-- shows the base is byte-exact.
local V = require("rfc_vectors")
H.eq(H.entry_thumbprint(V.RSA_PSS_KEY), V.RSA_PSS_KEYID, "test-key-rsa-pss's thumbprint is the draft's E.1 keyid")
H.eq(H.entry_thumbprint(V.ECC_P256_KEY), V.ECC_P256_KEYID)
-- B.2.1 covers no component, which sigbase.build refuses (Web Bot Auth
-- needs @authority): its base is the RFC's printed one.
local b21 = V.B2[1]
H.eq(H.crypto_verify(b21.alg, b21.key, b64.decode(b21.sig),
    '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"'), true, b21.name)
for n = 2, 4 do
    local v = V.B2[n]
    local base = base_for(v.input, v.label, v.values)
    H.eq(H.crypto_verify(v.alg, v.key, b64.decode(v.sig), base), true, v.name .. " signature over our base")
    H.eq(H.crypto_verify(v.alg, v.key, b64.decode(v.sig), base .. " "), false, v.name .. ": one byte more")
end
for _, v in ipairs(V.E1) do
    local base = base_for(v.input, "sig2", { ['"@authority"'] = "example.com",
        ['"signature-agent";key="agent2"'] = '"https://signature-agent.test"',
        ['"signature-agent"'] = '"https://signature-agent.test"' })
    H.eq(base, v.base, v.name .. " base")
    H.eq(H.crypto_verify("rsa-pss-sha512", V.RSA_PSS_KEY, V.sig_bytes(v.sig), base), true, v.name .. " signature")
end
H.pass("RFC 9421 B.2.1-B.2.3 (rsa-pss-sha512), B.2.4 (ecdsa-p256-sha256), draft E.1.1 and E.1.2 verify over the bases built here")

-- 4. Error paths return reason codes, never a partial base.
local item = sf.parse_item('"@authority"')
local b, why = sigbase.build({}, {})
H.eq(b, nil); H.eq(why, "no-covered-components")
b, why = sigbase.build({ { item = item, value = "a" }, { item = item, value = "a" } }, {})
H.eq(b, nil); H.eq(why, "duplicate-component")
b, why = sigbase.build({ { item = item, value = nil } }, {})
H.eq(b, nil); H.eq(why, "missing-component")
b, why = sigbase.build({ { item = item, value = "a\nb" } }, {})
H.eq(b, nil); H.eq(why, "bad-component-value")
H.pass("empty, duplicate, missing, and newline-carrying components are refused with a reason")

-- 5. Component identity (RFC 9421 2, 2.1.2): what counts as a repeat.
local id = function(s) return sigbase.identity(sf.parse_item(s)) end
H.eq(id('"foo";bar;baz'), id('"foo";baz;bar'), "parameter order is not significant")
H.eq(id('"d";key="a";sf') == id('"d";sf;key="a"'), true)
H.eq(id('"d";key="a"'), id('"d";key="a";sf'), ";sf beside ;key is redundant")
H.eq(id('"d";key="a"') ~= id('"d";key="b"'), true, "different keys are different components")
H.eq(id('"d"') ~= id('"d";sf'), true, "a field and its ;sf form differ")
H.eq(id('"foo";bar=1') ~= id('"foo";bar=2'), true, "parameter values count")
H.eq(id('"d";key="a"') ~= id('"d";key="a";tr'), true, "beside ;key only ;sf is redundant; other parameters still count (RFC 9421 2)")
why = select(2, sigbase.build({ { item = sf.parse_item('"x";a;b'), value = "1" }, { item = sf.parse_item('"x";b;a'), value = "1" } }, {}))
H.eq(why, "duplicate-component", "sigbase refuses the reordered repeat too")
why = select(2, sigbase.build({ { item = item, value = "exa\tmple.com" } }, {}))
H.eq(why, "bad-component-value", "HTAB in a derived component (2.5 ABNF)")
H.eq((sigbase.build({ { item = sf.parse_item('"x-a"'), value = "a\tb" } }, {})) ~= nil, true, "HTAB in field content")
H.pass("identity: parameter order ignored, ;sf beside ;key redundant, values and keys distinguish")

-- A value checked once for a request is not scanned again for its next
-- signature (memo, per request): 55 signatures over one 16 KiB field in
-- three forms cost one scan, not 165 (security review).
local big_value = ("a"):rep(16384)
local three = { { item = sf.parse_item('"x-a"'), value = big_value }, { item = sf.parse_item('"x-a";bs'), value = big_value },
    { item = sf.parse_item('"x-a";sf'), value = big_value } }
local function scans(memo)
    return H.searches(big_value, function()
        for _ = 1, 55 do assert(sigbase.build(three, {}, memo)) end
    end)
end
local unmemo, memoed = scans(nil), scans({})
H.eq(unmemo, 165, "without the memo: each of the 3 components scanned in each of 55 bases")
H.eq(memoed, 1, "with the memo: the 16 KiB value scanned once for the request")
H.pass("a request's values are checked once: 55 bases over 3 x 16 KiB scan the value once, not 165 times")

H.done("test_sigbase")
