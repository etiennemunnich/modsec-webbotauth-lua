--[[
helpers.lua: shared test helpers.

The openssl CLI is the independent crypto oracle for every algorithm: tests
sign with openssl over hand-written signature bases and verify with openssl,
so the verifier is checked against something other than its own code. Every
encoding the oracle needs (an RSA or EC SubjectPublicKeyInfo, an ECDSA
signature between r || s and DER) is made by openssl itself (asn1parse),
never by crypto.lua's encoder. Needs `openssl` (3.x) on PATH.
--]]

local here = (arg and arg[0] and arg[0]:match("(.*/)")) or "./"
package.path = here .. "../?.lua;" .. here .. "?.lua;" .. package.path

local base64 = require("wba.base64")

local H = { here = here, passed = 0 }

function H.eq(got, want, msg)
    if got ~= want then
        error((msg or "mismatch") .. "\n  got:  " .. tostring(got) .. "\n  want: " .. tostring(want), 2)
    end
end

function H.pass(msg)
    H.passed = H.passed + 1
    print("PASS: " .. msg)
end

function H.raises(fn, msg)
    if pcall(fn) then error("expected an error: " .. msg, 2) end
end

--- How many string.find and string.gmatch calls search `subject` while fn
--- runs. A count of passes over a large text proves a shortcut is taken
--- whatever the machine's load, where comparing two timings does not (a
--- busy VM failed "3 times faster" at 2.7). Code reaches both through the
--- string metatable (text:find), which looks them up at each call.
function H.searches(subject, fn)
    local find, gmatch, n = string.find, string.gmatch, 0
    -- luacheck: push ignore 122 (counting searches means replacing them for the call)
    string.find = function(s, ...) if s == subject then n = n + 1 end return find(s, ...) end
    string.gmatch = function(s, ...) if s == subject then n = n + 1 end return gmatch(s, ...) end
    local ok, err = pcall(fn)
    string.find, string.gmatch = find, gmatch
    -- luacheck: pop
    if not ok then error(err, 0) end
    return n
end

local function sh(cmd)
    local a = os.execute(cmd)
    return a == true or a == 0
end
H.sh = sh

function H.write(path, s)
    local f = assert(io.open(path, "wb"))
    f:write(s)
    f:close()
end

function H.read(path)
    local f = assert(io.open(path, "rb"))
    local s = f:read("a")
    f:close()
    return s
end

local tmpdir
function H.tmp(name)
    if not tmpdir then
        local base = os.tmpname()
        os.remove(base)
        tmpdir = base .. ".wba-test"
        assert(sh("mkdir -p '" .. tmpdir .. "'"))
    end
    return tmpdir .. "/" .. name
end

function H.cleanup()
    if tmpdir then sh("rm -rf '" .. tmpdir .. "'") end
    tmpdir = nil
end

-- A failing check raises an error, so H.done never runs (every killed mutant
-- is such a run). The interpreter still closes its state on the way out, and
-- that runs this finalizer. Kept in H, so it lives as long as the state.
H._reaper = setmetatable({}, { __gc = function() H.cleanup() end })

function H.done(name)
    H.cleanup()
    print(("\n%s: all %d checks passed"):format(name, H.passed))
end

function H.b64url(raw)
    return (base64.encode(raw):gsub("%+", "-"):gsub("/", "_"):gsub("=", ""))
end

-- SubjectPublicKeyInfo DER prefix for a raw Ed25519 key (RFC 8410).
local DER_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"

function H.pem_from_raw(raw)
    return "-----BEGIN PUBLIC KEY-----\n" .. base64.encode(DER_PREFIX .. raw)
        .. "\n-----END PUBLIC KEY-----\n"
end

--- RFC 7638 thumbprint of a raw Ed25519 key, computed with openssl.
function H.thumbprint(raw)
    local f = H.tmp("thumb.json")
    H.write(f, '{"crv":"Ed25519","kty":"OKP","x":"' .. H.b64url(raw) .. '"}')
    assert(sh(("openssl dgst -sha256 -binary -out '%s.bin' '%s'"):format(f, f)))
    return H.b64url(H.read(f .. ".bin"))
end

function H.hex(raw) return (raw:gsub(".", function(c) return ("%02x"):format(c:byte()) end)) end
function H.unhex(h) return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) end

local function capture(cmd)
    local p = assert(io.popen(cmd))
    local out = p:read("a")
    p:close()
    return out
end

--- The INTEGER values openssl asn1parse finds in a DER file, as lowercase hex.
local function der_integers(path)
    local out = {}
    for v in capture(("openssl asn1parse -inform DER -in '%s'"):format(path)):gmatch("INTEGER%s*:(%x+)") do
        out[#out + 1] = v:lower()
    end
    return out
end

--- DER written by openssl from an asn1parse -genconf description.
local function genconf(conf)
    local c, d = H.tmp("gen.cnf"), H.tmp("gen.der")
    H.write(c, conf)
    assert(sh(("openssl asn1parse -genconf '%s' -out '%s' -noout"):format(c, d)))
    return d
end

local function sha256_b64url(s)
    local f = H.tmp("thumb.json")
    H.write(f, s)
    assert(sh(("openssl dgst -sha256 -binary -out '%s.bin' '%s'"):format(f, f)))
    return H.b64url(H.read(f .. ".bin"))
end

-- What each algorithm needs from the oracle: written out here, independently
-- of algorithms.lua (RFC 9421 3.3.1, 3.3.2, 3.3.4, 3.3.5, 3.3.6).
H.PSS = "-sigopt rsa_padding_mode:pss -sigopt rsa_mgf1_md:sha512 -sigopt rsa_pss_saltlen:"
local ORACLE = {
    ed25519 = { key = "ed25519", len = 64 },
    ["ecdsa-p256-sha256"] = { key = "ec-p256", len = 64, md = "sha256" },
    ["ecdsa-p384-sha384"] = { key = "ec-p384", len = 96, md = "sha384" },
    ["rsa-v1_5-sha256"] = { key = "rsa", md = "sha256", opts = "" },
    ["rsa-pss-sha512"] = { key = "rsa", md = "sha512", opts = H.PSS .. "64" },
}
local CURVE = { ["ec-p256"] = { "P-256", "prime256v1", 65 }, ["ec-p384"] = { "P-384", "secp384r1", 97 } }
H.DEFAULT_ALG = { ed25519 = "ed25519", ["ec-p256"] = "ecdsa-p256-sha256", ["ec-p384"] = "ecdsa-p384-sha384",
                  rsa = "rsa-pss-sha512" }

--- RFC 7638 thumbprint of a key-store entry, by openssl (RFC 8037 A.3 for
--- Ed25519; RFC 7638 3.2's members, in order, for EC and RSA).
function H.entry_thumbprint(entry)
    if entry.type == "ed25519" then return H.thumbprint(entry.key) end
    if entry.type == "rsa" then
        return sha256_b64url(('{"e":"%s","kty":"RSA","n":"%s"}'):format(H.b64url(entry.e), H.b64url(entry.n)))
    end
    local size = (#entry.key - 1) // 2
    return sha256_b64url(('{"crv":"%s","kty":"EC","x":"%s","y":"%s"}'):format(CURVE[entry.type][1],
        H.b64url(entry.key:sub(2, size + 1)), H.b64url(entry.key:sub(size + 2))))
end

local key_count = 0
--- A fresh key generated by openssl. kind: "ed25519" (default), "p256",
--- "p384" or "rsa" (bits, default 2048). Returns { priv = pem path, type,
--- entry = key-store entry (keys.lua shape), raw (Ed25519 and EC key bytes),
--- keyid = thumbprint }. With path, the private key is kept there and reused
--- if it exists (the live generator runs once per mode).
function H.new_key(kind, bits, path)
    kind = kind or "ed25519"
    key_count = key_count + 1
    local priv = path or H.tmp("key" .. key_count .. ".pem")
    local gen = ({ ed25519 = "-algorithm ed25519", p256 = "-algorithm EC -pkeyopt ec_paramgen_curve:P-256",
                   p384 = "-algorithm EC -pkeyopt ec_paramgen_curve:P-384",
                   rsa = "-algorithm RSA -pkeyopt rsa_keygen_bits:" .. (bits or 2048) })[kind]
    local f = path and io.open(priv)
    if f then f:close() else assert(sh(("openssl genpkey %s -out '%s' 2>/dev/null"):format(gen, priv))) end
    local entry
    if kind == "rsa" then
        assert(sh(("openssl rsa -in '%s' -RSAPublicKey_out -outform DER -out '%s.der' 2>/dev/null"):format(priv, priv)))
        local ints = der_integers(priv .. ".der")
        entry = { type = "rsa", n = H.unhex(ints[1]), e = H.unhex(ints[2]) }
    else
        assert(sh(("openssl pkey -in '%s' -pubout -outform DER -out '%s.der' 2>/dev/null"):format(priv, priv)))
        local t = ({ ed25519 = "ed25519", p256 = "ec-p256", p384 = "ec-p384" })[kind]
        entry = { type = t, key = H.read(priv .. ".der"):sub(t == "ed25519" and -32 or -CURVE[t][3]) }
    end
    return { priv = priv, type = entry.type, entry = entry, raw = entry.key, keyid = H.entry_thumbprint(entry) }
end

--- A signature over msg, by openssl: alg defaults to the key type's own
--- (RSA: rsa-pss-sha512). ECDSA comes back as r || s unless o.der; o.saltlen
--- signs RSA-PSS with another salt length.
function H.sign(key, msg, alg, o)
    o = o or {}
    alg = alg or H.DEFAULT_ALG[key.type]
    local m, s = H.tmp("sign.msg"), H.tmp("sign.sig")
    H.write(m, msg)
    if alg == "ed25519" then
        assert(sh(("openssl pkeyutl -sign -rawin -inkey '%s' -in '%s' -out '%s'"):format(key.priv, m, s)))
        return H.read(s)
    end
    local a = ORACLE[alg]
    local opts = alg == "rsa-pss-sha512" and (H.PSS .. (o.saltlen or 64)) or (a.opts or "")
    assert(sh(("openssl dgst -%s -sign '%s' %s -out '%s' '%s'"):format(a.md, key.priv, opts, s, m)))
    if a.key == "rsa" or o.der then return H.read(s) end
    local half = a.len // 2
    local r = ""
    for _, v in ipairs(der_integers(s)) do r = r .. H.unhex(("0"):rep(2 * half - #v) .. v) end
    return r
end

local pem_cache, pem_count = {}, 0
--- A public key PEM for an EC or RSA key-store entry, built by openssl.
local function entry_pem(entry)
    local id = entry.type .. ":" .. (entry.key or (entry.n .. ":" .. entry.e))
    if pem_cache[id] then return pem_cache[id] end
    local der
    if entry.type == "rsa" then
        der = genconf(("asn1=SEQUENCE:spki\n[spki]\nalg=SEQUENCE:alg\nkey=BITWRAP,SEQUENCE:rsakey\n"
            .. "[alg]\noid=OID:rsaEncryption\nparams=NULL\n[rsakey]\nn=INTEGER:0x%s\ne=INTEGER:0x%s\n")
            :format(H.hex(entry.n), H.hex(entry.e)))
    else
        der = genconf(("asn1=SEQUENCE:spki\n[spki]\nalg=SEQUENCE:alg\nkey=FORMAT:HEX,BITSTRING:%s\n"
            .. "[alg]\noid=OID:id-ecPublicKey\ncurve=OID:%s\n"):format(H.hex(entry.key), CURVE[entry.type][2]))
    end
    pem_count = pem_count + 1
    local p = H.tmp("pub" .. pem_count .. ".pem")
    assert(sh(("openssl pkey -pubin -inform DER -in '%s' -out '%s' 2>/dev/null"):format(der, p)))
    pem_cache[id] = p
    return p
end

-- Curve orders (SEC 2, 2.4.2 and 2.5.1): (r, n - s) is a second valid ECDSA
-- signature over the same message, which any holder of (r, s) can make.
local ECDSA_N = {
    ["ecdsa-p256-sha256"] = H.unhex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
    ["ecdsa-p384-sha384"] = H.unhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
}
--- r || (n - s) for an r || s signature.
function H.ecdsa_negate_s(sig, alg)
    local n, half = ECDSA_N[alg], #sig // 2
    local s, out, borrow = sig:sub(half + 1), {}, 0
    for i = half, 1, -1 do
        local d = n:byte(i) - s:byte(i) - borrow
        if d < 0 then d, borrow = d + 256, 1 else borrow = 0 end
        out[i] = string.char(d)
    end
    return sig:sub(1, half) .. table.concat(out)
end

--- r || s as DER, by openssl.
function H.ecdsa_der(sig)
    local half = #sig // 2
    return H.read(genconf(("asn1=SEQUENCE:sig\n[sig]\nr=INTEGER:0x%s\ns=INTEGER:0x%s\n")
        :format(H.hex(sig:sub(1, half)), H.hex(sig:sub(half + 1)))))
end

--- openssl as the crypto oracle, with the production seam's signature
--- (verify.lua's crypto_verify, crypto.lua's verify). Like crypto.lua, it
--- raises on a key that is not for alg or a signature of the wrong length,
--- so verify.lua's own checks are what the tests exercise.
function H.crypto_verify(alg, entry, sig, msg)
    local a = ORACLE[alg]
    if not a or a.key ~= entry.type then error(("oracle: %s is not for a %s key"):format(alg, entry.type)) end
    if #sig ~= (a.len or #entry.n) then error("bad signature size") end
    if alg == "ed25519" then return H.ed25519_verify(entry.key, sig, msg) end
    local p, s, m = entry_pem(entry), H.tmp("cv.sig"), H.tmp("cv.msg")
    H.write(s, a.key == "rsa" and sig or H.ecdsa_der(sig))
    H.write(m, msg)
    return sh(("openssl dgst -%s %s -verify '%s' -signature '%s' '%s' >/dev/null 2>&1"):format(a.md, a.opts or "", p, s, m))
end

--- A key-store line (keys.lua format v2) for a key; proof defaults to "none\t-".
function H.store_line(identifier, key, alg, proof, nbf, exp)
    local e = key.entry
    local text = e.type == "rsa" and (H.hex(e.n) .. ":" .. H.hex(e.e)) or H.hex(e.key)
    return table.concat({ identifier, key.keyid, e.type, alg or "-", text, nbf and tostring(nbf) or "-", exp and tostring(exp) or "-",
        proof or "none\t-" }, "\t")
end

--- Ed25519 verification by openssl, raw key in, boolean out; raises on a
--- wrong-length signature or key.
function H.ed25519_verify(raw_pub, sig, msg)
    if #sig ~= 64 then error("bad signature size") end
    if #raw_pub ~= 32 then error("bad key size") end
    local p, s, m = H.tmp("v.pem"), H.tmp("v.sig"), H.tmp("v.msg")
    H.write(p, H.pem_from_raw(raw_pub))
    H.write(s, sig)
    H.write(m, msg)
    return sh(("openssl pkeyutl -verify -rawin -pubin -inkey '%s' -sigfile '%s' -in '%s' >/dev/null 2>&1"):format(p, s, m))
end

--- Raw SHA-512 of msg, by openssl (stands in for crypto.lua's sha512).
function H.sha512(msg)
    local m = H.tmp("sha512.msg")
    H.write(m, msg)
    assert(sh(("openssl dgst -sha512 -binary -out '%s.bin' '%s'"):format(m, m)))
    return H.read(m .. ".bin")
end

-- RFC 9421 Appendix B.1.4 Ed25519 test key (used by the WBA draft's E.2 vectors).
H.RFC_KEY_RAW = base64.decode("MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs="):sub(-32)
H.RFC_KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"

H.AGENT = "https://agent.example"
H.AGENT_ID = "https://agent.example/.well-known/http-message-signatures-directory"

--- Request table in the shape verify.verify() takes.
--- t.headers: list of { name, value } in arrival order.
function H.request(t)
    local fields = {}
    for _, h in ipairs(t.headers or {}) do
        local n = h[1]:lower()
        fields[n] = fields[n] or {}
        table.insert(fields[n], h[2])
    end
    local req = { fields = fields, method = t.method or "GET", path = t.path or "/",
                  query = t.query, scheme = t.scheme or "https", authority = "example.com" }
    if t.authority ~= nil then req.authority = t.authority or nil end
    return req
end

return H
