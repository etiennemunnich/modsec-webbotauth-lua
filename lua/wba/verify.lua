--[[
verify.lua: Web Bot Auth verification (draft-ietf-webbotauth-httpsig-protocol
over RFC 9421). Pure Lua 5.3+, no I/O: the caller supplies the request, the
key store and the HTTP_VERIFY primitive (crypto.lua), so every rule here is
testable offline.

"verified" means exactly this, and nothing weaker:
  * a signature tagged web-bot-auth, with created and expires, fresh within
    policy, alg absent or one of RFC 9421 3.3's algorithms other than
    hmac-sha256 (draft 6.4; algorithms.lua);
  * covering @authority (or @target-uri) and the Signature-Agent member it is
    attributed to (draft 5.2.1: "Its member ... MUST be signed");
  * that member is an https URL of type directory (an origin, resolved at its
    well-known key directory), jwks_uri or cimd (draft 5.5), and its
    identifier is in normal form (identifier.lua);
  * the key store holds a current key for exactly that (identifier, keyid)
    pair (draft 5.4: lookup MUST be keyed on the pair, never keyid alone);
  * the algorithm is determined as RFC 9421 3.2 step 6 says (from the key,
    from the alg parameter, and the two agree when both state one), and it
    verifies the RFC 9421 signature base built from this request.

Outcomes follow the draft's Appendix C.1, plus not-signed:
  verified    as above; only here are agent and keyid returned
  invalid     a check failed (freshness, coverage, syntax, bad signature)
  unverified  cannot decide (unknown agent or key, store unavailable)
  not-signed  no Web Bot Auth signature on the request

A signature that covers Content-Digest, Repr-Digest or Unencoded-Digest also
binds the body, so it verifies only once the body matches (RFC 9421 7.2.8,
RFC 9530; digest.lua). Without the body (ModSecurity phase 1) such a
signature is unverified/digest-pending; phase 2 decides it.

Each web-bot-auth signature is checked independently (draft 5.2.2). The
request's outcome is the best of them, ranked verified > digest-pending >
invalid > unverified: a pending signature may still verify in phase 2.
--]]

local sf = require("wba.structured_fields")
local sigbase = require("wba.sigbase")
local keys = require("wba.keys")
local components = require("wba.components")
local digest = require("wba.digest")
local sha256 = require("wba.sha256")
local algorithms = require("wba.algorithms")

local M = {}

M.DEFAULT_POLICY = {
    clock_skew = 60,          -- seconds a signature's created may run ahead of this clock (not-yet-valid)
    expiry_grace = 0,         -- seconds past expires still accepted: 0 is strict (the default); at most 60
    max_age = 3600,           -- now - created ceiling (RFC 9421 3.2.1): a signature counts for an hour; false disables
    max_window = nil,         -- expires - created ceiling, an operator's own limit (RFC 9421 3.2.1). Unset,
                              -- it is a day only when max_age is off: draft 5.2's 24 h is advice to signers,
                              -- and max_age already bounds how long any signature counts. false disables
    authorities = nil,        -- set of this site's @authority values; a signed request for any other is
                              -- invalid/foreign-authority. false: none configured, so nothing verifies
                              -- (unverified/no-site-names); nil: not checked (library use only)
    malformed = "ignore",     -- RFC 9651 4.2: an unparsable Signature-Input or Signature is ignored (the
                              -- request is then not signed), or with "reject" the message is malformed
    max_signatures = nil,     -- optional local cap on web-bot-auth signatures; over it: unverified
    reject_test_keys = true,  -- draft 6.8
    max_sha256_body = 131072, -- largest body hashed with SHA-256, in Lua at ~4 MB/s (RFC 9530 6.7; digest.lua)
    max_decoded_body = 131072, -- Unencoded-Digest: decoding budget (coding.lua units), ~40 ms at worst in Lua
    max_decode_ratio = 200,   -- and at most this many units per byte received (Apache mod_deflate's default)
    require_components = nil, -- optional list of component names every signature must cover; else unverified
    require_nonce = false,    -- draft 5.3: true makes a signature without a nonce unverified/missing-nonce
    replay_keys = false,      -- true (replay accounting on): verified results carry the keys replay.lua counts
    strict_field_lines = false, -- RFC 9651 4.2's MAY: true fails a field when one of its lines does not parse alone
}

-- JWK thumbprints of published test keys, whose private half anyone can
-- read (draft 6.8: "including the example keys in [RFC 9421]"). Same list
-- as wba-keysync.
M.TEST_KEY_THUMBPRINTS = {
    -- RFC 9421 B.1.4 (Ed25519; every draft E.2 example), B.1.1 (RSA),
    -- B.1.2 (RSA-PSS; the draft's E.1 examples), B.1.3 (ECC P-256).
    ["poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"] = true, ["BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo"] = true,
    ["oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA"] = true, ["ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI"] = true,
    -- RFC 8032 7.1's five Ed25519 keys (TEST 1 is also RFC 8037 A's).
    ["kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"] = true, ["FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk"] = true,
    ["FVV5umTuau890q59V-4Ga_R6qWb7ON_ivJc4EjvCwTM"] = true, ["lZI1vM7tnlYapaF5-cy86ptx0tT_8Av721hhiNB5ti4"] = true,
    ["iiDHHfFVNG6ICMUTsicgrWf1igtFYZEK73xlobt1ah4"] = true,
    -- The JOSE examples: RFC 7517 A.2's RSA (RFC 7638 3.1's thumbprint
    -- example) and P-256 keys, RFC 7515 A.2's RSA and A.3's P-256 keys.
    ["NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"] = true, ["cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"] = true,
    ["IsUn6_e04MaShXFIISMp4kG62LWzMIPy_MvSA5pJgX8"] = true, ["oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"] = true,
}

local TAG = "web-bot-auth"
local RANK = { verified = 4, invalid = 2, unverified = 1 }

local function hex(raw) return (raw:gsub(".", function(ch) return ("%02x"):format(ch:byte()) end)) end

local function result(status, reason, extra)
    local r = extra or {}
    r.status, r.reason = status, reason
    return r
end

local function rank(r)
    if r.reason == "digest-pending" then return 3 end
    if r.status == "verified" and r.agent then return 5 end -- attributed beats URL-less
    return RANK[r.status]
end

-- resolve_agent()'s answer when the request carries no Signature-Agent at all
-- (draft 4.3): the identifier is the keyid thumbprint itself.
local URL_LESS = {}

-- Signature-Agent member types (draft 5.5); all three resolve to a JWKS.
local AGENT_TYPES = { directory = true, jwks_uri = true, cimd = true }

-- Component values live in components.lua (RFC 9421 2.1, 2.2). trim_ows and
-- ascii_lower are re-exported for modsecurity_entry.lua.
M.trim_ows, M.ascii_lower = components.trim_ows, components.ascii_lower
local field_value = components.field_value

--- The key-directory identifier this signature is attributed to, or
--- nil, status, reason.
---
--- Which member. Draft 5.2.1 names the member keyed to the signature's
--- label; 5.2.2 forbids one the signature does not cover. But the label is
--- not in the signature base (RFC 9421 7.2.5 lets intermediaries relabel),
--- and the draft's own E.2 vectors sign key="agent2" under label sig2. So:
---   exactly one covered member, named by ;key=  -> that member
---   otherwise                                   -> the member keyed to the
---     label, which must be covered (D.2: an outer signer also covers the
---     inner signer's member, as evidence, not as its own identity)
--- A relabel can only choose among members the signer covered, and the key
--- must still be listed under that directory to verify (draft 5.4).
local function resolve_agent(label, items, req, agent_field, ignore_malformed)
    local count, whole, keyed, only = 0, false, {}, nil
    for _, item in ipairs(items) do
        if item.value.type == "string" and item.value.value == "signature-agent" then
            count = count + 1
            local k = sf.param(item.params, "key") -- a String: components.value() checked
            if k then
                keyed[k.value], only = true, k.value
            else
                whole = true
            end
        end
    end
    if count == 0 then
        -- Draft 4.3: with the header absent, the identifier is the keyid
        -- thumbprint; a verifier that holds that key verifies the request
        -- and attributes it no further than the key's holder. A header
        -- present but not covered breaks 5.2.1's MUST: a failed check.
        if agent_field == nil then return URL_LESS end
        return nil, "invalid", "agent-not-covered"
    end
    local want
    if count == 1 and only then
        want = only
    elseif whole or keyed[label] then
        want = label
    else
        return nil, "invalid", "ambiguous-agent"
    end

    -- Invariant: components.value() already resolved every covered
    -- signature-agent component, so agent_field is present, and a ;key=
    -- component over a legacy bare string has already failed as a dictionary.
    -- Parsed once per request (components.parsed), not once per signature:
    -- 150 labels over an 8 KiB field otherwise cost 195 ms of CPU.
    local legacy = agent_field:sub(1, 1) == '"'
    local parsed = components.parsed(req, "signature-agent", legacy)
    if not parsed then return nil, "invalid", ignore_malformed and "unparsable-agent" or "malformed-headers" end
    local member = parsed
    if not legacy then
        member = parsed[want]
        if member == nil then return nil, "invalid", "agent-not-covered" end
    end
    -- Legacy bare-string form (draft 5.2.1: a verifier MAY accept it, as a
    -- one-member dictionary keyed by the label; here want == label).

    -- From here the draft says an unusable member is ignored, which leaves
    -- no URL to resolve: unverified, not invalid.
    if member.kind ~= "item" or member.value.type ~= "string" then
        return nil, "unverified", "bad-agent-url"
    end
    -- Draft 5.2.1: type is a Token naming the discovery mechanism, directory
    -- when absent; a type this verifier does not support is ignored, and the
    -- mechanism is never inferred from the URL.
    local t = sf.param(member.params, "type")
    local kind = "directory"
    if t ~= nil then
        if t.type ~= "token" or not AGENT_TYPES[t.value] then
            return nil, "unverified", "unsupported-agent-type"
        end
        kind = t.value
    end
    -- Draft 5.2.1: the scheme MUST be https. Another scheme fails a check
    -- (C.1: invalid). Draft 5.5: a directory member that is not an origin is
    -- ignored, whatever its scheme, which leaves nothing to resolve
    -- (unverified); so only an origin with another scheme is invalid.
    local value = member.value.value
    local scheme = value:match("^([A-Za-z][A-Za-z0-9+.%-]*):")
    if scheme and components.ascii_lower(scheme) ~= "https" then
        if kind == "directory" and not keys.identifier("https" .. value:sub(#scheme + 1), true) then
            return nil, "unverified", "bad-agent-url"
        end
        return nil, "invalid", "agent-not-https"
    end
    -- Draft 5.5: the identifier is the URL resolved, query and fragment
    -- discarded, in normal form. directory: strictly the ASCII serialization
    -- of an origin (RFC 6454 6.2), so an explicit default port is ignored.
    -- jwks_uri and cimd: the member value itself. Lookup is keyed on that
    -- identifier alone (5.4: the (URL, key) pair); key-sync resolved it.
    local id
    if kind == "directory" then
        id = keys.identifier(member.value.value, true)
    else
        id = keys.url_identifier(member.value.value)
    end
    if not id then return nil, "unverified", "bad-agent-url" end
    return id
end

--- Draft Appendix B fact for a key from the store: the directory's
--- possession proof for it as key-sync last validated it, "expired" once the
--- proof's own expires has passed (5.5.3: valid only until then).
local function proof_of(k, now)
    if k.proof == "valid" and k.proof_exp and now >= k.proof_exp then return "expired" end
    return k.proof or "none"
end

local function verify_one(label, entry, sig_member, req, agent_field, store, now, crypto_verify, policy, hash, digests)
    local p = entry.params
    local created, expires = sf.param(p, "created"), sf.param(p, "expires")
    local keyid, alg, nonce = sf.param(p, "keyid"), sf.param(p, "alg"), sf.param(p, "nonce")

    if not (created and expires and keyid) then return result("invalid", "missing-param") end
    if created.type ~= "integer" or expires.type ~= "integer" or keyid.type ~= "string"
        or (nonce and nonce.type ~= "string") then
        return result("invalid", "bad-param")
    end
    -- RFC 9421 3.2 step 6.1: an alg outside the allowed set fails. That set
    -- is 3.3's registry entries less hmac-sha256 (draft 6.4: MUST NOT).
    local declared
    if alg then
        if not (alg.type == "string" and algorithms.ALGORITHMS[alg.value]) then
            return result("invalid", "unsupported-alg")
        end
        declared = alg.value
    end
    if #keyid.value ~= 43 or not keyid.value:match("^[A-Za-z0-9_%-]+$") then
        return result("invalid", "bad-keyid")
    end

    local c, e = created.value, expires.value
    if e <= c then return result("invalid", "bad-param") end
    local window = policy.max_window
    if window == nil and not policy.max_age then window = 86400 end
    if window and e - c > window then return result("invalid", "window-too-long") end
    if c > now + policy.clock_skew then return result("invalid", "not-yet-valid") end
    if now >= e + (policy.expiry_grace or 0) then return result("invalid", "expired") end
    -- RFC 9421 3.2.1: a verifier may set a maximum age from created. Without
    -- one, a captured signature replays until its own expires, up to 24 h.
    if policy.max_age and now - c > policy.max_age then return result("invalid", "too-old") end

    -- RFC 9421 2.5: a repeated component identifier is an error, found before
    -- any value is derived, so a long list of repeats costs nothing to refuse.
    -- Repeated means the same identity (sigbase.identity: parameter order and
    -- a redundant ;sf beside ;key do not make two components distinct).
    local covered, seen, binds_authority = {}, {}, false
    for n, item in ipairs(entry.items) do
        local ok, id = pcall(sigbase.identity, item)
        if not ok then return result("invalid", "malformed-headers") end
        if seen[id] then return result("invalid", "duplicate-component") end
        seen[id] = true
        local v, why = components.value(req, item)
        if v == nil then return result("invalid", why) end
        local name = item.value.value
        if name == "@authority" or name == "@target-uri" then binds_authority = true end
        covered[n] = { item = item, value = v }
    end
    if not binds_authority then return result("invalid", "authority-not-covered") end

    local identifier, st, why = resolve_agent(label, entry.items, req, agent_field, policy.malformed ~= "reject")
    if not identifier then return result(st, why) end
    local url_less = identifier == URL_LESS

    if policy.reject_test_keys and M.TEST_KEY_THUMBPRINTS[keyid.value] then
        return result("invalid", "test-key")
    end
    -- The exact length depends on the key (RSA), known only after lookup;
    -- a length no allowed key could accept is refused before the store read.
    if not sig_member or sig_member.kind ~= "item" or sig_member.value.type ~= "binary"
        or not algorithms.plausible_length(declared, #sig_member.value.value) then
        return result("invalid", "bad-signature")
    end
    local signature = sig_member.value.value

    -- Loaded on first use (malformed requests never pay for the read), and
    -- only the lines this lookup needs.
    store = store(url_less and { keyid = keyid.value } or { identifier = identifier })
    if store == nil then return result("unverified", "keystore-unavailable") end
    local held = {} -- the current key-store entries this signature's key resolves to
    local function current(ke) return not ((ke.nbf and now < ke.nbf) or (ke.exp and now >= ke.exp)) end
    if url_less then
        -- Draft 4.3: held means held under any directory. A keyid is the
        -- key's own thumbprint, so every entry for it is the same key.
        -- Nothing is attributed to those directories.
        local found = false
        for _, agent_keys in pairs(store) do
            local ke = agent_keys[keyid.value]
            if ke then
                found = true
                if current(ke) then held[#held + 1] = ke end
            end
        end
        if not found then return result("unverified", "agent-absent") end
        if #held == 0 then return result("unverified", "key-not-current") end
    else
        local agent_keys = store[identifier]
        if agent_keys == nil then return result("unverified", "unknown-agent") end
        local ke = agent_keys[keyid.value]
        if ke == nil then return result("unverified", "unknown-key") end
        if not current(ke) then return result("unverified", "key-not-current") end
        held[1] = ke
    end

    -- RFC 9421 3.2 step 6: the algorithm. URL-less, every current entry for
    -- the key must give the same one, so a directory that pins the key to
    -- rsa-pss-sha512 is never bypassed through one that does not (7.3.6).
    local use, unusable
    for _, ke in ipairs(held) do
        local a, why_not = algorithms.select(declared, ke)
        if not a then use, unusable = nil, why_not break end
        if use and a ~= use then use, unusable = nil, "alg-mismatch" break end
        use = a
    end
    if not use then return result("invalid", unusable) end
    local k = held[1]
    if #signature ~= algorithms.signature_length(use, k) then return result("invalid", "bad-signature") end

    local memo = components.memo(req)
    local base, berr = sigbase.build(covered, p, memo)
    if not base then return result("invalid", berr) end

    local ok, good = pcall(crypto_verify, use, k, signature, base)
    if not ok then return result("unverified", "crypto-error") end
    if good ~= true then
        -- RFC 9421 2.2.8: a space in a covered query parameter is "+" by the
        -- steps' serializer and "%20" in the RFC's own example (CONFORMANCE.md,
        -- choice 9). Both spell the same decoded parameters, so the other
        -- spelling is tried when one is covered and has a space, and at most
        -- once per request, so it cannot double the work of a hostile one.
        local spaced, alt = false, {}
        for n, comp in ipairs(covered) do
            alt[n] = comp
            if comp.item.value.value == "@query-param" and comp.value:find("+", 1, true) then
                alt[n], spaced = { item = comp.item, value = (comp.value:gsub("%+", "%%20")) }, true
            end
        end
        local alt_base = spaced and not memo.query_alt and sigbase.build(alt, p, memo)
        if spaced then memo.query_alt = true end
        if alt_base then ok, good = pcall(crypto_verify, use, k, signature, alt_base) end
        if not (alt_base and ok and good == true) then return result("invalid", "bad-signature") end
        base = alt_base
    end

    -- Local policy: components every signature must cover (README,
    -- Controls). Checked once the signature is known good, so the reason
    -- never hides a forgery, and before any body is hashed for it.
    local names, has = {}, {}
    for _, comp in ipairs(covered) do
        local name = comp.item.value.value
        if not has[name] then has[name], names[#names + 1] = true, name end
    end
    -- @target-uri holds the path, so it meets a required @path, as it does
    -- for a grant (modsecurity_entry.lua, covers_all).
    for _, name in ipairs(policy.require_components or {}) do
        if not (has[name] or (name == "@path" and has["@target-uri"])) then
            return result("unverified", "insufficient-coverage")
        end
    end
    if policy.require_nonce and not nonce then return result("unverified", "missing-nonce") end

    -- RFC 9421 7.2.8: a covered digest binds the body only once checked.
    -- Only a good signature from a key in the store gets this far, so no
    -- other request can make the WAF hash its body.
    local fields = digest.covered(covered)
    if fields then
        local checks, unsure = digest.plan(req, fields, hash, policy.strict_field_lines)
        if not checks then return result("invalid", unsure) end
        if #checks > 0 then
            if req.body == nil then return result("unverified", "digest-pending") end
            local data, complete = req.body()
            local dst, dwhy = digest.compare(checks, data, complete, hash, policy, digests)
            if dst then return result(dst, dwhy) end
        end
        if unsure then return result("unverified", unsure) end
    end
    -- Everything below comes from the verified signature itself or is
    -- computed here; sighash lets logs spot a replayed signature without
    -- ever holding the signature, a bearer credential until it expires.
    local facts = { keyid = keyid.value, label = label, created = c, expires = e, covered = names,
                    sighash = hex(sha256.digest(sig_member.value.value)) }
    if policy.replay_keys then
        -- What replay.lua counts: the signed statement, not its signature
        -- bytes. ECDSA's (r, n - s) verifies as well as (r, s), and a signer
        -- can make any number of ECDSA signatures over one base, so bytes
        -- would let a captured request through once more per variant. The
        -- base is the same for all of them (and includes keyid, created and
        -- expires). Hashed in C where lua-openssl is loaded: a signer could
        -- otherwise cover one large header from many signatures and make Lua
        -- hash it each time. The nonce, at most one per signature, is short.
        local h = hash["sha-512"]
        facts.basehash = h and hex(h(base)):sub(1, 64) or hex(sha256.digest(base))
        facts.noncehash = nonce and hex(sha256.digest(nonce.value)) or nil
    end
    if url_less then return result("verified", "url-less", facts) end
    facts.agent, facts.proof = identifier, proof_of(k, now)
    return result("verified", "", facts)
end

--- @param req { fields = { [lowercase name] = { value, ... } }, method, authority,
---              path, query, scheme, body? } (see modsecurity_entry.lua).
---   body: nil while the body is not available yet; else a function
---   returning the body and whether it is complete (called at most once per
---   signature, only for a good signature that covers a digest)
--- @param store key store from keys.lua, a function returning one (called at
---   most once, only when a signature gets as far as key lookup), or nil
--- @param now integer Unix time
--- @param crypto_verify function(alg, entry, signature, message) -> boolean:
---   RFC 9421 3.3's HTTP_VERIFY for `alg` with key-store entry `entry`
---   (keys.lua), only ever called with an algorithm appropriate for the
---   entry and a signature of the exact length (crypto.lua)
--- @param policy table, fields default to M.DEFAULT_POLICY
--- @param hash table, { ["sha-256"] = fn, ["sha-512"] = fn } returning raw
---   digests; defaults to SHA-256 alone (sha256.lua)
--- @return { status, reason, agents?, and on verified only: agent? and proof?
---   (both absent when URL-less; proof is valid, invalid, expired or none:
---   the directory's Appendix B possession proof for the key), keyid, label,
---   created, expires, covered (component names in signature order, each
---   once), sighash (hex SHA-256 of the signature bytes); with
---   policy.replay_keys, basehash (hex: SHA-512's first 256 bits of the
---   signature base where hash has sha-512, else SHA-256), noncehash (hex
---   SHA-256 of the nonce) when it has one, and replay: { basehash, noncehash,
---   expires (the signature's own, which names its counter) } for EVERY
---   verified signature in the request, so each one is counted, not only the
---   one reported }
function M.verify(req, store, now, crypto_verify, policy, hash)
    hash = hash or { ["sha-256"] = sha256.digest }
    local pol = {}
    for k, v in pairs(M.DEFAULT_POLICY) do pol[k] = v end
    for k, v in pairs(policy or {}) do pol[k] = v end -- max_window = false disables the window check

    local cached = {} -- one load per distinct lookup, false for none
    local function get_store(want)
        if type(store) ~= "function" then return store end
        local k = want.identifier and "i " .. want.identifier or "k " .. want.keyid
        if cached[k] == nil then cached[k] = store(want) or false end
        return cached[k] or nil
    end

    local input_field = field_value(req, "signature-input")
    local sig_field = field_value(req, "signature")
    if not input_field and not sig_field then return result("not-signed", "no-signature") end

    -- RFC 9651 4.2: a field that fails to parse is ignored, or the message is
    -- malformed. Ignored (the default), Signature-Input or Signature is then
    -- absent, and RFC 9421 needs both: not signed. A draft-cavage Signature
    -- header (ActivityPub, Mastodon) is such a field. "reject" takes the
    -- other branch (wba.conf answers malformed-* with 400; draft 5.4 allows it).
    local function unparsable()
        if pol.malformed == "reject" then return result("invalid", "malformed-headers") end
        return result("not-signed", "unparsable-field")
    end
    local ok1, inputs, order = pcall(sf.parse_dictionary, input_field or "")
    local ok2, sigs, sig_order = pcall(sf.parse_dictionary, sig_field or "")
    if not ok1 or not ok2 then return unparsable() end
    -- RFC 9651 4.2's MAY, when the operator takes it: the combined value
    -- parsed, but a line on its own must too. Signature-Agent is part of
    -- every Web Bot Auth request, so it is held to the same rule here.
    if pol.strict_field_lines then
        for _, name in ipairs({ "signature-input", "signature", "signature-agent" }) do
            if not sf.every_line(req.fields[name], sf.parse_dictionary) then return unparsable() end
        end
    end

    -- RFC 9421 4: "The presence of a label in one field but not the other is
    -- an error", for every label, so a missing header is one too.
    for _, label in ipairs(order) do
        if sigs[label] == nil then return result("invalid", "orphan-label") end
    end
    for _, label in ipairs(sig_order) do
        if inputs[label] == nil then return result("invalid", "orphan-label") end
    end

    local candidates = {}
    for _, label in ipairs(order) do
        local entry = inputs[label]
        if entry.kind == "inner-list" then
            local tag = sf.param(entry.params, "tag")
            if tag and tag.type == "string" and tag.value == TAG then
                candidates[#candidates + 1] = label
            end
        end
    end
    if #candidates == 0 then return result("not-signed", "no-wba-signature") end
    -- The site's own names (operator decision 2026-10-09): @authority is the
    -- client's Host, and no clause makes a verifier compare it with the hosts
    -- it serves, so a signature a bot made for another site would otherwise
    -- verify here (cross-site replay). Without names configured nothing
    -- verifies; a name outside them is a signature for someone else.
    if pol.authorities == false then return result("unverified", "no-site-names") end
    -- No usable Host (none, or several): @authority is unavailable, which the
    -- component check reports (missing-component), not a foreign name.
    if pol.authorities and req.authority and not pol.authorities[req.authority] then
        return result("invalid", "foreign-authority")
    end
    if pol.max_signatures and #candidates > pol.max_signatures then
        return result("unverified", "too-many-signatures") -- a local limit: cannot decide
    end

    -- Draft 5.2.2: every signature is validated, each on its own components
    -- and key. The outcome is the best one; `agents` lists every directory a
    -- signature verified for, in Signature-Input order.
    local agent_field = field_value(req, "signature-agent")
    local digests = {} -- body digests by algorithm, computed at most once per request
    local best, agents, listed, replay = nil, {}, {}, {}
    for _, label in ipairs(candidates) do
        local r = verify_one(label, inputs[label], sigs[label], req, agent_field,
            get_store, now, crypto_verify, pol, hash, digests)
        if best == nil or rank(r) > rank(best) then best = r end
        if r.status == "verified" and r.agent and not listed[r.agent] then
            listed[r.agent] = true
            agents[#agents + 1] = r.agent
        end
        if r.status == "verified" and pol.replay_keys then
            -- The counter is named by the signature's own expires, never by
            -- this request's policy: with the grace or max_age in the name,
            -- the same statement under another server block's settings got
            -- a fresh counter and read uses=1 (review 2026-10-12, finding
            -- 2). sweep.ts removes the file after expires, or once it has
            -- gone unused for its --max-window, whichever comes first, so the
            -- store still holds about an hour of traffic (replay.lua).
            replay[#replay + 1] = { basehash = r.basehash, noncehash = r.noncehash, expires = r.expires }
        end
    end
    if best.status == "verified" then
        best.agents = agents
        if pol.replay_keys then best.replay = replay end
    end
    return best
end

return M
