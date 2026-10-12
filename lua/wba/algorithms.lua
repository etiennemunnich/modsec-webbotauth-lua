--[[
algorithms.lua: which signature algorithms this verifier accepts, with which
keys, and how one is chosen for a signature. Pure data and rules, no crypto:
keys.lua, verify.lua and crypto.lua share it.

The algorithms are the HTTP Signature Algorithms registry's entries in RFC
9421 3.3 that the Web Bot Auth draft allows: all of them except hmac-sha256,
because "Implementations MUST NOT use shared HMAC" (draft 6.4).

  rsa-pss-sha512      3.3.1  RSASSA-PSS, SHA-512, MGF1 with SHA-512, salt 64
  rsa-v1_5-sha256     3.3.2  RSASSA-PKCS1-v1_5, SHA-256
  ecdsa-p256-sha256   3.3.4  ECDSA P-256, SHA-256; signature r || s, 64 bytes
  ecdsa-p384-sha384   3.3.5  ECDSA P-384, SHA-384; signature r || s, 96 bytes
  ed25519             3.3.6  Ed25519 (pure, no prehash); 64 bytes

Key types, as the key store names them (keys.lua):

  ed25519   JWK kty OKP, crv Ed25519 (RFC 8037)
  ec-p256   JWK kty EC, crv P-256    (RFC 7518 6.2)
  ec-p384   JWK kty EC, crv P-384
  rsa       JWK kty RSA              (RFC 7518 6.3)

RSA keys must have a modulus of 2048 to 16384 bits. The floor is RFC 7518's
for the JOSE algorithms identical to these two ("A key of size 2048 bits or
larger MUST be used", 3.3 for RS256, 3.5 for PS512), and RFC 9421 3.2.1 names
key size as an application requirement. The ceiling is OpenSSL's own
(OPENSSL_RSA_MAX_MODULUS_BITS): a larger key could not verify anyway. The
public exponent is odd and at least 3 (RFC 8017 3.1: 3 <= e <= n - 1, and
odd, since GCD(e, lambda(n)) = 1) and below 2^256 (the upper bound FIPS
186-5 sets for e), because verification cost grows with its length and any
client can make the verifier pay it by naming a held keyid.
--]]

local M = {}

M.ALGORITHMS = {
    ["rsa-pss-sha512"]    = { key = "rsa" },
    ["rsa-v1_5-sha256"]   = { key = "rsa" },
    ["ecdsa-p256-sha256"] = { key = "ec-p256", signature_bytes = 64 },
    ["ecdsa-p384-sha384"] = { key = "ec-p384", signature_bytes = 96 },
    ["ed25519"]           = { key = "ed25519", signature_bytes = 64 },
}

-- The one algorithm a key type allows, where it allows only one: the
-- algorithm "determined from the keying material" (RFC 9421 3.2 step 6.3).
-- An RSA key allows two, so its type alone determines none.
M.ONLY = { ed25519 = "ed25519", ["ec-p256"] = "ecdsa-p256-sha256", ["ec-p384"] = "ecdsa-p384-sha384" }

M.RSA_MIN_BITS, M.RSA_MAX_BITS, M.RSA_MAX_E_BITS = 2048, 16384, 256
-- Above 3072 bits OpenSSL verifies only with e of at most 64 bits
-- (OPENSSL_RSA_SMALL_MODULUS_BITS, OPENSSL_RSA_MAX_PUBEXP_BITS): a wider e
-- there is a key that can never verify, so it is not stored.
M.RSA_LARGE_BITS, M.RSA_LARGE_MAX_E_BITS = 3072, 64

--- The exact signature length in bytes for `alg` with key-store entry
--- `entry`: fixed for ECDSA and Ed25519; for RSA the modulus length k (RFC
--- 8017 8.1.2 and 8.2.2 step 1: any other length is "invalid signature").
function M.signature_length(alg, entry)
    local a = M.ALGORITHMS[alg]
    if a.signature_bytes then return a.signature_bytes end
    return #entry.n
end

--- Before any key is looked up: could a signature of `len` bytes be valid
--- for `declared` (the alg parameter, or nil)? Refuses what no held key
--- could accept, so a malformed signature never costs a key-store read.
function M.plausible_length(declared, len)
    local a = declared and M.ALGORITHMS[declared]
    if a and a.signature_bytes then return len == a.signature_bytes end
    local most = M.RSA_MAX_BITS // 8
    if a then return len >= M.RSA_MIN_BITS // 8 and len <= most end
    return len >= 64 and len <= most
end

--- RFC 9421 3.2 step 6 for one key-store entry: the algorithm to verify
--- with, or nil and a reason.
---   6.3  from the key: the JWK's alg (stored), else the one algorithm its
---        type allows (none for RSA)
---   6.4  from the signature parameters: `declared`, a name already checked
---        to be in M.ALGORITHMS (6.1)
---   6.5  stated in both places: they MUST be the same
--- A declared algorithm for another key type fails too: step 8 applies the
--- algorithm only "if the key material is appropriate" for it.
function M.select(declared, entry)
    local from_key = entry.alg or M.ONLY[entry.type]
    if declared then
        if M.ALGORITHMS[declared].key ~= entry.type then return nil, "alg-mismatch" end
        if from_key and from_key ~= declared then return nil, "alg-mismatch" end
        return declared
    end
    if from_key then return from_key end
    return nil, "alg-undetermined"
end

return M
