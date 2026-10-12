--[[
crypto.lua: the one place cryptography runs. Two functions:

  verify(alg, entry, signature, message) -> boolean
      RFC 9421 3.3's HTTP_VERIFY for alg (algorithms.lua) with a key-store
      entry (keys.lua). Raises if the key cannot be used for alg, or the
      signature has the wrong length: verify.lua checks both first, so a
      raise here means a bug, and the caller makes it unverified/crypto-error.
  sha512(data) -> the raw 64-byte SHA-512 of data (RFC 9530 body digests)

Backed by lua-openssl (zhaozg/lua-openssl 0.11.1) over the system OpenSSL
3's EVP interface. Tests substitute an oracle with the same two functions
(package.loaded["wba.crypto"]); test_crypto.lua and the Wycheproof runner
check this module itself.

How each algorithm maps onto OpenSSL:

  ed25519            EVP_DigestVerify with no digest: pure Ed25519 (3.3.6)
  ecdsa-p256-sha256  EVP_DigestVerify, SHA-256. The signature arrives as r || s,
  ecdsa-p384-sha384  32 or 48 bytes each (3.3.4, 3.3.5); OpenSSL takes DER, so
                     it is re-encoded here, and only from exactly that length:
                     a DER signature on the wire is the wrong length, refused.
  rsa-v1_5-sha256    EVP_DigestVerify, SHA-256, PKCS #1 v1.5 padding (3.3.2)
  rsa-pss-sha512     EVP_PKEY_verify over the SHA-512 of the message, with PSS
                     padding, SHA-512, MGF1 with SHA-512 and a salt length of
                     exactly 64 (3.3.1), never "auto", which would accept any

Keys are rebuilt per call as DER SubjectPublicKeyInfo from the store's raw
fields (RFC 5280 4.1.2.7; RFC 8410 for Ed25519, RFC 5480 for EC, RFC 8017
A.1.1 for RSA) and parsed by OpenSSL, which also checks that an EC point is
on its curve.
--]]

local openssl = require("openssl")
local algorithms = require("wba.algorithms")

-- luaossl installs a module named "openssl" too; anything but lua-openssl
-- stops this chunk here (unverified/engine-error, wba.conf rule 3).
if type(openssl) ~= "table" or type(openssl.pkey) ~= "table" or type(openssl.digest) ~= "table" then
    error("the module named openssl is not lua-openssl")
end

local pkey, digest = openssl.pkey, openssl.digest

local M = {}

local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end

-- DER (X.690 8.1): tag, definite length, content.
local function tlv(tag, content)
    local n, len = #content, ""
    if n < 128 then
        len = string.char(n)
    else
        while n > 0 do len, n = string.char(n % 256) .. len, n // 256 end
        len = string.char(0x80 + #len) .. len
    end
    return string.char(tag) .. len .. content
end

-- A non-negative big-endian integer as a DER INTEGER: minimal, with a 00
-- byte in front when the top bit is set (X.690 8.3).
local function integer(bytes)
    bytes = bytes:gsub("^\0+", "")
    if bytes == "" or bytes:byte(1) >= 0x80 then bytes = "\0" .. bytes end
    return tlv(0x02, bytes)
end

-- SubjectPublicKeyInfo up to the key bytes, for the fixed-size key types.
local SPKI_PREFIX = {
    ed25519 = unhex("302a300506032b6570032100"),                                  -- id-Ed25519
    ["ec-p256"] = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200"),   -- id-ecPublicKey, prime256v1
    ["ec-p384"] = unhex("3076301006072a8648ce3d020106052b81040022036200"),         -- id-ecPublicKey, secp384r1
}
local RSA_ALGORITHM = unhex("300d06092a864886f70d0101010500") -- rsaEncryption, NULL parameters

local function public_key(entry)
    local der
    if entry.type == "rsa" then
        local rsa_public_key = tlv(0x30, integer(entry.n) .. integer(entry.e))
        der = tlv(0x30, RSA_ALGORITHM .. tlv(0x03, "\0" .. rsa_public_key))
    else
        der = SPKI_PREFIX[entry.type] .. entry.key
    end
    local key = pkey.read(der, false, "der")
    if not key then
        openssl.clear_error()
        error("key material not usable: " .. tostring(entry.type))
    end
    return key
end

-- r || s, `size` bytes each, as the DER ECDSA-Sig-Value OpenSSL verifies.
local function ecdsa_der(signature, size)
    return tlv(0x30, integer(signature:sub(1, size)) .. integer(signature:sub(size + 1)))
end

local ECDSA = { ["ecdsa-p256-sha256"] = { 32, "sha256" }, ["ecdsa-p384-sha384"] = { 48, "sha384" } }

-- RFC 9421 3.3.1, as EVP_PKEY_CTX_ctrl_str settings, applied in this order
-- (OpenSSL needs PSS padding set before the PSS-only parameters).
local PSS = { { "rsa_padding_mode", "pss" }, { "digest", "sha512" }, { "rsa_mgf1_md", "sha512" },
              { "rsa_pss_saltlen", "64" } }

local function pss_verify(key, signature, message)
    local ctx = key:ctx()
    local ready = ctx:verify_init()
    for _, setting in ipairs(PSS) do ready = ready and ctx:ctrl(setting[1], setting[2]) end
    if not ready then
        openssl.clear_error()
        error("RSA-PSS parameters refused")
    end
    -- lua-openssl hands its first argument to EVP_PKEY_verify as the
    -- signature and its second as the digest that was signed.
    return ctx:verify(signature, digest.digest("sha512", message, true))
end

function M.verify(alg, entry, signature, message)
    local a = algorithms.ALGORITHMS[alg]
    if not a or a.key ~= entry.type then
        error(("%s is not an algorithm for a %s key"):format(tostring(alg), tostring(entry.type)))
    end
    if #signature ~= algorithms.signature_length(alg, entry) then error("bad signature size") end
    local key = public_key(entry)
    local ok
    if alg == "rsa-pss-sha512" then
        ok = pss_verify(key, signature, message)
    elseif alg == "rsa-v1_5-sha256" then
        ok = key:verify(message, signature, "sha256")
    elseif ECDSA[alg] then
        ok = key:verify(message, ecdsa_der(signature, ECDSA[alg][1]), ECDSA[alg][2])
    else
        ok = key:verify(message, signature) -- ed25519
    end
    -- A failed check leaves its reason on this thread's OpenSSL error queue,
    -- which the nginx worker shares; leave it empty.
    openssl.clear_error()
    return ok == true
end

function M.sha512(data)
    local d = digest.digest("sha512", data, true)
    if type(d) ~= "string" or #d ~= 64 then
        openssl.clear_error()
        error("sha512 failed")
    end
    return d
end

return M
