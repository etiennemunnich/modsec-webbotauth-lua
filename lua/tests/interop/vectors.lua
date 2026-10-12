-- vectors.lua: verify.lua against the request test vectors of the LATEST
-- editor's copy of the Web Bot Auth draft, as extracted by vectors.ts.
--
--   bun lua/tests/interop/vectors.ts > v.json && lua lua/tests/interop/vectors.lua v.json
--
-- The vectors are signed with RFC 9421's published test keys (B.1.2 RSA-PSS,
-- B.1.4 Ed25519), which the verifier refuses by default (draft 6.8), and some
-- carry a 100-year window; so, as test_verify.lua does for the pinned copies,
-- they run with reject_test_keys and max_window off, at created + 100 s.
-- Signatures are checked by the openssl CLI (helpers.lua), no lua-openssl.
-- This file sits one level below lua/tests: helpers.lua and rfc_vectors.lua
-- are in ../, the wba.* modules in ../../ (helpers.lua assumes lua/tests/).
local here = arg[0]:match("(.*/)") or "./"
package.path = here .. "../?.lua;" .. here .. "../../?.lua;" .. package.path
local H = require("helpers")
local verify = require("wba.verify")
local V = require("rfc_vectors")
local json = require("json")

local f = assert(io.open(assert(arg[1], "usage: lua vectors.lua <vectors.json>"), "rb"))
local doc = json.decode(f:read("a"))
f:close()

local DIR = "https://signature-agent.test/.well-known/http-message-signatures-directory"
local KEYS = {
    ["rsa-pss-sha512"] = { [V.RSA_PSS_KEYID] = V.RSA_PSS_KEY },
    ed25519 = { [H.RFC_KEYID] = { type = "ed25519", key = H.RFC_KEY_RAW } },
}

print("== the latest draft vectors (" .. doc.source .. ") through verify.lua")
local failed = 0
for _, v in ipairs(doc.vectors) do
    local req = H.request({ headers = { { "Signature-Agent", v.agent }, { "Signature-Input", v.input }, { "Signature", v.sig } } })
    local r = verify.verify(req, { [DIR] = KEYS[v.alg] }, v.created + 100, H.crypto_verify,
        { reject_test_keys = false, max_window = false })
    local got = r.status .. "/" .. r.reason
    local ok = got == "verified/"
    if not ok then failed = failed + 1 end
    print(("%s  %s: %s"):format(ok and "PASS" or "FAIL", v.name, got))
end
for _, s in ipairs(doc.skipped or {}) do print("SKIP  " .. s) end
print(("== %d of %d draft vectors verify"):format(#doc.vectors - failed, #doc.vectors))
os.exit(failed == 0 and 0 or 1)
