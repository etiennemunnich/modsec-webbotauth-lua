-- test_entry.lua: modsecurity_entry.lua against a mock of ModSecurity's `m`
-- API with libmodsecurity v3 semantics:
--   * m.getvar(name) raises for a name libmodsecurity cannot resolve (a
--     "collection.key" name whose collection is not TX, or an unknown bare
--     name), standing in for the uncaught C++ std::invalid_argument that
--     aborts a real nginx worker (variable.h stringMatchResolve);
--   * TX keys are case-insensitive; an unset or empty variable (REQUEST_BODY
--     when the body is empty, a TX value set to "") reads as no value at
--     all, not even nil (lua.cc pushes nil, then returns 0 results);
--   * m.setvar requires string values (luaL_checkstring in lua.cc);
--   * m.getvars("REQUEST_HEADERS") returns every header instance in order.
-- wba.crypto (lua-openssl) is replaced by the openssl CLI oracle, through the
-- same two functions (helpers.lua).
-- Run: lua lua/tests/test_entry.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local b64 = require("wba.base64")

local NOW = os.time()
local KEY = H.new_key()
local ENTRY = H.here .. "../wba/modsecurity_entry.lua"
local KEYS_PATH = H.tmp("wba-keys.tsv")

local function hex(raw) return (raw:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local JWKS = "https://agent.example/jwks.json"
H.write(KEYS_PATH, "# wba-keys v2\n" .. H.AGENT_ID .. "\t" .. KEY.keyid .. "\ted25519\t-\t" .. hex(KEY.raw) .. "\t-\t-\tvalid\t" .. (NOW + 3600) .. "\n"
    .. JWKS .. "\t" .. KEY.keyid .. "\ted25519\t-\t" .. hex(KEY.raw) .. "\t-\t-\tnone\t-\n")

local ALLOWED_GETVAR = { REQUEST_METHOD = true, REQUEST_URI_RAW = true, REQUEST_BODY = true,
                         INBOUND_DATA_ERROR = true, ["TX.wba_stage"] = true, ["TX.wba_time"] = true, ["TX.wba_reason"] = true,
                         ["TX.wba_max_window"] = true, ["TX.wba_require_components"] = true,
                         ["TX.wba_grant_agents"] = true, ["TX.wba_replay_dir"] = true,
                         ["TX.wba_require_nonce"] = true, ["TX.wba_strict_field_lines"] = true ,
                         ["TX.wba_site_names"] = true, ["TX.wba_max_age"] = true, ["TX.wba_expiry_grace"] = true,
                         ["TX.wba_malformed"] = true, ["TX.wba_grant_require_components"] = true }
local BARE = { REQUEST_METHOD = true, REQUEST_URI_RAW = true, REQUEST_BODY = true, INBOUND_DATA_ERROR = true }

local function mock(headers, o)
    local calls, tx = { getvar = {}, getvars = {}, log = {} }, o.tx or {}
    -- The site's own name, as an operator configures it; o.no_site_names leaves it unset.
    if tx["tx.wba_site_names"] == nil and not o.no_site_names then tx["tx.wba_site_names"] = "example.com" end
    local m = {}
    function m.getvar(name)
        calls.getvar[#calls.getvar + 1] = name
        local col, key = name:match("^([^.:]+)[.:](.*)$")
        if (col and col:upper() ~= "TX") or (not col and not BARE[name]) then
            error("std::invalid_argument: Variable not found (a real worker would abort here)")
        end
        if col then
            local v = tx["tx." .. key:lower()]
            if v == nil or v == "" then return end -- no value at all
            return v
        end
        if name == "REQUEST_METHOD" then return o.method or "GET" end
        if name == "REQUEST_URI_RAW" then return o.uri_raw or "/" end
        if name == "REQUEST_BODY" then
            calls.body = (calls.body or 0) + 1
            if (o.body or "") ~= "" then return o.body end
            return
        end
        if name == "INBOUND_DATA_ERROR" then return o.inbound_error or "0" end
    end
    function m.getvars(name)
        calls.getvars[#calls.getvars + 1] = name
        local out = {}
        for _, h in ipairs(headers) do out[#out + 1] = { name = "REQUEST_HEADERS:" .. h[1], value = h[2] } end
        return out
    end
    function m.setvar(k, v)
        assert(type(v) == "string", "setvar value must be a string")
        tx[k:lower()] = v
    end
    function m.log(_, msg) calls.log[#calls.log + 1] = msg end
    return m, tx, calls
end

local function run_entry(headers, o)
    o = o or {}
    local m, tx, calls = mock(headers, o)
    if o.break_getvars then m.getvars = function() error("boom") end end
    _G.m = m
    _G.WBA_CONFIG = { lua_path = H.here .. "../?.lua", keys_path = o.keys_path or KEYS_PATH,
                      scheme = "https", policy = {} }
    if o.real_crypto then
        package.loaded["wba.crypto"] = nil -- the entry loads crypto.lua over lua-openssl itself
    else
        package.loaded["wba.crypto"] = o.crypto or { verify = H.crypto_verify, sha512 = H.sha512 }
    end
    dofile(ENTRY)
    local ret = main()
    H.eq(ret, nil, "main() returns nil")
    for _, name in ipairs(calls.getvar) do
        H.eq(ALLOWED_GETVAR[name], true, "m.getvar called with a non-fixed name: " .. name)
    end
    for _, name in ipairs(calls.getvars) do H.eq(name, "REQUEST_HEADERS") end
    return tx, calls
end

--- Headers for a request signed by openssl over a hand-written base.
local function signed_headers(o)
    o = o or {}
    local member = o.member or ('"' .. H.AGENT .. '"')
    local comps = o.components or '"@authority" "signature-agent";key="agent1"'
    local lines = o.lines or { '"@authority": example.com', '"signature-agent";key="agent1": ' .. member }
    local params = (';created=%d;expires=%d;keyid="%s"'):format(o.created or NOW - 5, o.expires or NOW + 300, KEY.keyid)
        .. (o.nonce and (';nonce="%s"'):format(o.nonce) or "") .. ';tag="web-bot-auth"'
    local base = table.concat(lines, "\n") .. '\n"@signature-params": (' .. comps .. ")" .. params
    local headers = {
        { "Host", o.host or "example.com" },
        { "Signature-Agent", "agent1=" .. member },
        { "Signature-Input", "sig1=(" .. comps .. ")" .. params },
        { "Signature", "sig1=:" .. b64.encode(H.sign(KEY, base)) .. ":" },
    }
    for _, h in ipairs(o.extra or {}) do headers[#headers + 1] = h end
    return headers
end

-- 1. End to end through the entry
local tx = run_entry(signed_headers())
H.eq(tx["tx.wba_status"], "verified")
H.eq(tx["tx.wba_reason"], "")
H.eq(tx["tx.wba_agent"], H.AGENT_ID)
H.eq(tx["tx.wba_keyid"], KEY.keyid)
H.pass("signed request verifies through the entry; only fixed names reach m.getvar/m.getvars")

-- 2. The worker-crash input: a covered header whose name contains "."
tx = run_entry(signed_headers({ components = '"@authority" "x.y" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"x.y": v', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' },
    extra = { { "x.y", "v" } } }))
H.eq(tx["tx.wba_status"], "verified", "dotted name handled as data, no m.getvar call")
tx = run_entry(signed_headers({ components = '"@authority" "a.b" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"a.b": v', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } }))
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/missing-component")
H.pass("dotted component names never reach m.getvar (the live crash path is gone)")

-- 3. @path comes from the raw URI: no %3F / %2F aliasing
local path_sig = function(p) return signed_headers({ components = '"@authority" "@path" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"@path": ' .. p, '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } }) end
tx = run_entry(path_sig("/x"), { uri_raw = "/x%3Fy" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/bad-signature", "signature over /x must not verify /x%3Fy")
tx = run_entry(path_sig("/x%3Fy"), { uri_raw = "/x%3Fy?q=1" })
H.eq(tx["tx.wba_status"], "verified", "raw path, query split at the first literal '?'")
tx = run_entry(path_sig("/x"), { uri_raw = "http://example.com/x" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/missing-component", "absolute-form target: no @path")
H.pass("@path is the raw, undecoded path from REQUEST_URI_RAW")

-- 4. @authority from exactly one Host header, default port removed
tx = run_entry(signed_headers({ host = "Example.COM:443" }))
H.eq(tx["tx.wba_status"], "verified", "case folded, :443 dropped")
tx = run_entry(signed_headers({ host = "example.com:" }))
H.eq(tx["tx.wba_status"], "verified", "an empty port is no port (RFC 3986 6.2.3)")
tx = run_entry(signed_headers({ host = "example.com:8443" }))
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/foreign-authority", "non-default port is kept: not one of the site's names")
tx = run_entry(signed_headers({ host = "example.com:8443" }), { tx = { ["tx.wba_site_names"] = "example.com example.com:8443" } })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/bad-signature", "non-default port kept, so it is not what was signed")
tx = run_entry(signed_headers({ extra = { { "Host", "other.example" } } }))
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/missing-component", "two Host headers")
H.pass("@authority: one Host header, lowercased, default port removed")

-- 5. Signature-Input split across two header lines is combined (RFC 9421 2.1)
local hs = signed_headers()
local si = hs[3][2]
local extra_input = 'other=("@authority");created=1;expires=2;keyid="k";tag="x"'
hs[3] = { "Signature-Input", extra_input }
hs[#hs + 1] = { "signature-input", si }
hs[#hs + 1] = { "Signature", "other=:AAAA:" } -- RFC 9421 4: every label in both fields
tx = run_entry(hs)
H.eq(tx["tx.wba_status"], "verified")
H.pass("multiple Signature-Input instances are combined, not truncated to one")

-- 6. Failure modes are explicit and never leak identity
tx = run_entry(signed_headers(), { keys_path = H.tmp("missing.tsv") })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/keystore-unavailable")
tx = run_entry(signed_headers(), { crypto = { verify = function() error("bad signature size") end, sha512 = H.sha512 } })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/crypto-error")
local calls
tx, calls = run_entry(signed_headers(), { break_getvars = true })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/internal-error")
H.eq(#calls.log, 1, "internal error is logged")
tx = run_entry({ { "Host", "example.com" } })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "not-signed/no-signature")
tx = run_entry(signed_headers({ host = "evil.example" }))
H.eq(tx["tx.wba_agent"], nil, "no agent on invalid")
H.eq(tx["tx.wba_keyid"], nil, "no keyid on invalid")
H.pass("store missing, crypto error, engine error, unsigned: explicit outcomes, identity only on verified")

-- 7. Absolute-form request line: nginx passes "?evil=1" for "GET http://example.com?evil=1".
local q_sig = signed_headers({ components = '"@authority" "@query" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"@query": ?', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } })
tx = run_entry(q_sig, { uri_raw = "?evil=1" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/missing-component",
    "a signature over an absent query must not verify a query nginx will forward")
tx = run_entry(q_sig, { uri_raw = "/" })
H.eq(tx["tx.wba_status"], "verified", "same signature, origin-form '/', no query")
H.pass("non-origin-form target: @query unavailable, not absent")

-- 8. The key store is read only when a signature reaches key lookup.
tx, calls = run_entry({ { "Host", "example.com" }, { "Signature-Input", "x=(" }, { "Signature", "x=:AAAA:" } },
    { keys_path = H.tmp("missing.tsv") })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "not-signed/unparsable-field", "RFC 9651 4.2: ignored by default")
H.eq(#calls.log, 0, "no key-store read (and so no 'unavailable' log) for an unparsable request")
tx, calls = run_entry({ { "Host", "example.com" }, { "Signature-Input", "x=(" }, { "Signature", "x=:AAAA:" } },
    { keys_path = H.tmp("missing.tsv"), tx = { ["tx.wba_site_names"] = "example.com", ["tx.wba_malformed"] = "reject" } })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/malformed-headers", "tx.wba_malformed=reject: malformed (wba.conf answers 400)")
H.eq(#calls.log, 0)
H.pass("unparsable requests never read the key store; ignored by default, malformed by choice")

-- 8b. URL-less (draft 4.3) and every verified directory (draft 5.2.2).
local ul = signed_headers({ components = '"@authority"', lines = { '"@authority": example.com' } })
table.remove(ul, 2) -- no Signature-Agent
tx = run_entry(ul)
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "verified/url-less")
H.eq(tx["tx.wba_agent"], nil, "no directory named")
H.eq(tx["tx.wba_agents"], nil)
H.eq(tx["tx.wba_keyid"], KEY.keyid)
tx = run_entry(signed_headers())
H.eq(tx["tx.wba_agents"], H.AGENT_ID, "tx.wba_agents lists the verified directories")
H.pass("URL-less sets only tx.wba_keyid; tx.wba_agents lists every verified directory")

-- 9. RFC 9530 across the two runs wba.conf makes: phase 1 leaves
-- digest-pending and its time; phase 2 (rule 9534105 sets tx.wba_stage=body)
-- re-verifies with REQUEST_BODY at that same time.
local HELLO = '{"hello": "world"}'
local S256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
local S512 = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
local function digest_headers(v)
    return signed_headers({ components = '"@authority" "content-digest" "signature-agent";key="agent1"',
        lines = { '"@authority": example.com', '"content-digest": ' .. v, '"signature-agent";key="agent1": "' .. H.AGENT .. '"' },
        extra = { { "Content-Digest", v } } })
end
--- Both runs; returns phase 1's "status/reason", the shared tx, phase 2's calls.
local function two_phase(headers, body, o)
    o = o or {}
    local t, c1 = run_entry(headers, { method = "POST", body = body, real_crypto = o.real_crypto, tx = o.settings })
    H.eq(c1.body, nil, "phase 1 never reads REQUEST_BODY")
    local first = t["tx.wba_status"] .. "/" .. t["tx.wba_reason"]
    if t["tx.wba_reason"] ~= "digest-pending" then return first, t end
    if o.time then t["tx.wba_time"] = o.time end
    if o.drop_time then t["tx.wba_time"] = nil end
    t["tx.wba_stage"] = "body"
    local _, c2 = run_entry(headers, { method = "POST", body = body, tx = t, inbound_error = o.inbound_error,
        real_crypto = o.real_crypto })
    return first, t, c2
end
local first, t, c2 = two_phase(digest_headers(S256), HELLO)
H.eq(first, "unverified/digest-pending")
H.eq(t["tx.wba_time"] ~= nil, true, "phase 1 records its time for phase 2")
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "verified/")
H.eq(t["tx.wba_agent"], H.AGENT_ID)
H.eq(c2.body, 1, "REQUEST_BODY read once")
t = select(2, two_phase(digest_headers(S512), HELLO))
H.eq(t["tx.wba_status"], "verified", "sha-512 through wba.crypto's sha512")
t = select(2, two_phase(digest_headers(S256), HELLO .. "!"))
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "invalid/digest-mismatch")
H.eq(t["tx.wba_agent"], nil, "no agent on a swapped body")
t = select(2, two_phase(digest_headers(S256), ""))
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "invalid/digest-mismatch", "an empty body (REQUEST_BODY unset)")
t = select(2, two_phase(digest_headers(S256), HELLO, { inbound_error = "1" }))
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "unverified/body-incomplete", "INBOUND_DATA_ERROR=1")
t = select(2, two_phase(digest_headers(S256), HELLO, { time = tostring(NOW + 400) }))
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "invalid/expired", "phase 2 judges freshness at phase 1's time")
first, t = two_phase(signed_headers(), HELLO)
H.eq(first, "verified/", "no digest covered: decided in phase 1")
H.eq(t["tx.wba_time"], nil)
t = select(2, two_phase(digest_headers(S256), HELLO, { drop_time = true }))
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "verified/", "tx.wba_time unset in phase 2: decided at phase 2's clock, no internal error")
H.pass("digest-bound signatures: pending in phase 1, decided in phase 2 with the body at phase 1's time")

-- 9a. Phase 2 after phase 1 decided. Rule 9534104 normally skips phase 2
-- then, but an operator's ctl:ruleRemoveById removes only SecRule rules: rule
-- 9534105 (tx.wba_stage=body) and the script still run (libmodsecurity v3).
-- Phase 1's outcome stands: the verifier does not run again (phase 2 here
-- has no key store, so a second run would end keystore-unavailable).
local function phase2_after(headers)
    local t1 = run_entry(headers)
    local first = t1["tx.wba_status"] .. "/" .. t1["tx.wba_reason"]
    t1["tx.wba_stage"] = "body"
    local _, c = run_entry(headers, { method = "POST", body = HELLO, tx = t1, keys_path = H.tmp("missing.tsv") })
    return first, t1["tx.wba_status"] .. "/" .. t1["tx.wba_reason"], c
end
for _, h in ipairs({ signed_headers(), { { "Host", "example.com" } }, signed_headers({ host = "evil.example" }) }) do
    local p1, p2, c = phase2_after(h)
    H.eq(p2, p1, "phase 2 keeps phase 1's " .. p1)
    H.eq(c.body, nil, "REQUEST_BODY not read")
    H.eq(#c.log, 0, "nothing logged: the key store was not read again")
end
H.eq((phase2_after(signed_headers())), "verified/")
-- No m.getvar result goes straight into tonumber() or tostring(): an unset
-- variable is no value at all there, and both raise.
for _, f in ipairs({ "modsecurity_entry.lua", "wba_log.lua" }) do
    H.eq(H.read(H.here .. "../wba/" .. f):find("to%a+%(%s*m%.getvar%("), nil, f .. ": m.getvar passed straight to tonumber/tostring")
end
H.pass("phase 2 after a phase-1 decision (verified, unsigned, invalid) changes nothing and reads no body or key store")

-- 9b. Unencoded-Digest over a gzip body (draft-ietf-httpbis-unencoded-digest-05
-- 6, Figure 2): REQUEST_BODY is binary (lua.cc pushes it with
-- lua_pushlstring), NUL bytes included, and decoded in phase 2 only.
local UD_GZ = ("1f8b0800791f086400ff73cc5328cd4bad484e2d28c9cccf4bcc51282e29cacc4be702007eaf074418000000")
    :gsub("..", function(x) return string.char(tonumber(x, 16)) end)
local UD_U = "sha-256=:5Bv3NIx05BPnh0jMph6v1RJ5Q7kl9LKMtQxmvc9+Z7Y=:"
local function ud_headers(ce)
    return signed_headers({ components = '"@authority" "unencoded-digest" "signature-agent";key="agent1"',
        lines = { '"@authority": example.com', '"unencoded-digest": ' .. UD_U, '"signature-agent";key="agent1": "' .. H.AGENT .. '"' },
        extra = { { "Unencoded-Digest", UD_U }, { "Content-Encoding", ce } } })
end
H.eq(UD_GZ:find("\0", 1, true) ~= nil, true, "the body holds NUL bytes")
first, t = two_phase(ud_headers("gzip"), UD_GZ)
H.eq(first, "unverified/digest-pending")
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "verified/", "decoded and matched")
H.eq(t["tx.wba_covered"], "@authority unencoded-digest signature-agent")
t = select(2, two_phase(ud_headers("gzip"), UD_GZ:sub(1, 30)))
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "invalid/bad-content-coding", "a truncated stream")
t = select(2, two_phase(ud_headers("gzip"), UD_GZ, { inbound_error = "1" }))
H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "unverified/body-incomplete", "a cut body is never decoded")
first, t = two_phase(ud_headers("br"), UD_GZ)
H.eq(first, "unverified/digest-coding-unsupported", "br: decided in phase 1, no phase 2")
H.eq(t["tx.wba_time"], nil)
H.pass("Unencoded-Digest over a binary gzip REQUEST_BODY verifies in phase 2; truncated, cut and br bodies do not")

-- 10. Facts exported for logs, only on verified (wba.conf rule 7 logs them).
tx = run_entry(signed_headers())
H.eq(tx["tx.wba_label"], "sig1")
H.eq(tx["tx.wba_created"], tostring(NOW - 5))
H.eq(tx["tx.wba_expires"], tostring(NOW + 300))
H.eq(tx["tx.wba_covered"], "@authority signature-agent")
H.eq(#tx["tx.wba_sighash"], 64)
H.eq(tx["tx.wba_sighash"]:match("^%x+$") ~= nil, true, "sighash is hex")
H.eq(tx["tx.wba_granted"], nil, "nothing granted without tx.wba_grant_agents")
for _, bad in ipairs({ signed_headers({ host = "evil.example" }), signed_headers({ components = '"@authority"',
        lines = { '"@authority": example.com' } }) }) do
    tx = run_entry(bad)
    H.eq(tx["tx.wba_status"] == "verified", false)
    for _, v in ipairs({ "label", "created", "expires", "covered", "sighash", "granted" }) do
        H.eq(tx["tx.wba_" .. v], nil, "tx.wba_" .. v .. " set on " .. tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"])
    end
end
-- tx.wba_covered is logged as is: that is safe only because a covered name
-- that is not a lowercase RFC 9110 token never verifies.
for _, name in ipairs({ "x y", "X-A", 'x\\"y', "x;y" }) do
    local raw = name:gsub('\\"', '"')
    tx = run_entry(signed_headers({ components = '"@authority" "' .. name .. '" "signature-agent";key="agent1"',
        lines = { '"@authority": example.com', '"' .. name .. '": v', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' },
        extra = { { raw, "v" } } }))
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/unsupported-component", "covered name " .. raw)
    H.eq(tx["tx.wba_covered"], nil)
end
H.pass("label, window, covered names and sighash set on verified only; a non-token covered name never verifies")

-- 11. Operator settings (web-bot-auth-config.conf), read by fixed name.
local function with(settings, headers)
    local t, c = run_entry(headers or signed_headers(), { tx = settings })
    return t, c
end
-- A grant needs a signature that says what it was for: @method and @path by default.
local FULL = signed_headers({ components = '"@method" "@path" "@authority" "signature-agent";key="agent1"',
    lines = { '"@method": GET', '"@path": /', '"@authority": example.com', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } })
tx = with({ ["tx.wba_grant_agents"] = "https://other.example " .. H.AGENT }, FULL)
H.eq(tx["tx.wba_granted"], "1", "exact origin granted, @method and @path covered")
tx = with({ ["tx.wba_grant_agents"] = H.AGENT })
H.eq(tx["tx.wba_status"] .. "/" .. (tx["tx.wba_granted"] or "-"), "verified/-",
    "verified, but @authority alone verifies for any method and path: no grant (review F4)")
tx = with({ ["tx.wba_grant_agents"] = H.AGENT, ["tx.wba_grant_require_components"] = "none" })
H.eq(tx["tx.wba_granted"], "1", "grant_require_components=none: the operator's choice")
local TARGET = signed_headers({ components = '"@method" "@target-uri" "signature-agent";key="agent1"',
    lines = { '"@method": GET', '"@target-uri": https://example.com/', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } })
tx = with({ ["tx.wba_grant_agents"] = H.AGENT }, TARGET)
H.eq(tx["tx.wba_granted"], "1", "@target-uri includes the path, so it counts as @path")
tx = with({ ["tx.wba_grant_require_components"] = " X y" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config", "a malformed grant setting is a config error")
tx = with({ ["tx.wba_grant_agents"] = "https://agent.ex https://agent.example.evil" })
H.eq(tx["tx.wba_status"], "verified")
H.eq(tx["tx.wba_granted"], nil, "a prefix or a longer host never grants")
tx = with({ ["tx.wba_grant_agents"] = H.AGENT }, signed_headers({ host = "evil.example" }))
H.eq(tx["tx.wba_granted"], nil, "never granted unless verified")
tx = with({ ["tx.wba_require_components"] = "@path" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/insufficient-coverage")
tx = with({ ["tx.wba_require_components"] = "@authority signature-agent" })
H.eq(tx["tx.wba_status"], "verified", "covered: required names present")
tx = with({ ["tx.wba_max_window"] = "60" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/window-too-long", "305 s window over a 60 s cap")
tx = with({ ["tx.wba_max_window"] = "3600" })
H.eq(tx["tx.wba_status"], "verified")
for setting, value in pairs({ ["tx.wba_max_window"] = "soon", ["tx.wba_require_components"] = "@path,@method",
                              ["tx.wba_grant_agents"] = "https://agent.example:443" }) do
    local c
    tx, c = with({ [setting] = value })
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config", setting .. "=" .. value)
    H.eq(#c.log, 1, "bad configuration is logged")
    H.eq(c.log[1]:find(setting:sub(4), 1, true) ~= nil, true, "the log names the setting")
end
H.pass("grants exact, coverage and window settings applied, malformed settings loud (unverified/bad-config + log)")

-- 11b. The operator's own grant list replaces the default @method @path: with
-- "@method @path @query", a signature that leaves the query out could be
-- replayed with any query string, so it must not unlock the grant.
do
    local function grant_sig(components, lines) -- lines: a fresh table, completed here
        lines[#lines + 1] = '"@authority": example.com'
        lines[#lines + 1] = '"signature-agent";key="agent1": "' .. H.AGENT .. '"'
        return signed_headers({ components = components .. ' "@authority" "signature-agent";key="agent1"', lines = lines })
    end
    local MP = grant_sig('"@method" "@path"', { '"@method": GET', '"@path": /' })
    local MPQ = grant_sig('"@method" "@path" "@query"', { '"@method": GET', '"@path": /', '"@query": ?a=1' })
    local LIST = { ["tx.wba_grant_agents"] = H.AGENT, ["tx.wba_grant_require_components"] = "@method @path @query" }
    local g = run_entry(MP, { tx = { ["tx.wba_grant_agents"] = H.AGENT }, uri_raw = "/?a=1" })
    H.eq(g["tx.wba_status"] .. "/" .. (g["tx.wba_granted"] or "-"), "verified/1", "default list: @method @path is enough")
    g = run_entry(MP, { tx = LIST, uri_raw = "/?a=1" })
    H.eq(g["tx.wba_status"] .. "/" .. (g["tx.wba_granted"] or "-"), "verified/-",
        "list @method @path @query: a signature without @query verifies but is not granted")
    g = run_entry(MPQ, { tx = LIST, uri_raw = "/?a=1" })
    H.eq(g["tx.wba_status"] .. "/" .. (g["tx.wba_granted"] or "-"), "verified/1", "list @method @path @query: all three covered, granted")
end
H.pass("tx.wba_grant_require_components: the operator's list decides the grant; a component it names and the signature lacks refuses it")

-- 12. Agent types (draft 5.5) and the Appendix B proof fact, through the entry.
tx = run_entry(signed_headers())
H.eq(tx["tx.wba_agent_proof"], "valid", "the store's proof for the verifying key")
local jwks = signed_headers({ member = '"' .. JWKS .. '?v=2";type=jwks_uri' })
tx = run_entry(jwks)
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "verified/")
H.eq(tx["tx.wba_agent"], JWKS, "the jwks_uri identifier, query discarded")
H.eq(tx["tx.wba_agents"], JWKS)
H.eq(tx["tx.wba_agent_proof"], "none")
tx = run_entry(ul)
H.eq(tx["tx.wba_agent_proof"], nil, "URL-less: no agent, no proof")
tx = run_entry(signed_headers({ host = "evil.example" }))
H.eq(tx["tx.wba_agent_proof"], nil, "no proof on invalid")
tx = with({ ["tx.wba_grant_agents"] = JWKS, ["tx.wba_grant_require_components"] = "none" }, jwks)
H.eq(tx["tx.wba_granted"], "1", "a jwks_uri identifier, written in normal form, is granted exactly")
tx = with({ ["tx.wba_grant_agents"] = JWKS, ["tx.wba_grant_require_components"] = "none" }, signed_headers())
H.eq(tx["tx.wba_granted"], nil, "a jwks_uri grant never grants the origin's directory")
tx = with({ ["tx.wba_grant_agents"] = H.AGENT, ["tx.wba_grant_require_components"] = "none" }, jwks)
H.eq(tx["tx.wba_granted"], nil, "an origin grant never grants a jwks_uri on it")
for _, value in ipairs({ JWKS .. "?v=2", "https://Agent.example/jwks.json", "https://agent.example/x/../jwks.json" }) do
    local c
    tx, c = with({ ["tx.wba_grant_agents"] = value })
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config", "grant not in normal form: " .. value)
    H.eq(#c.log, 1)
end
H.pass("jwks_uri agents verify through the entry; tx.wba_agent_proof set with the agent only; grants exact on identifiers")

-- 13. ECDSA and RSA keys in a version 2 store, end to end through the entry
-- and keys.lua; and a version 1 store (Ed25519 only, no proof) still read.
local P256, P384, RSA = H.new_key("p256"), H.new_key("p384"), H.new_key("rsa", 2048)
local V2_PATH = H.tmp("wba-keys-v2.tsv")
H.write(V2_PATH, table.concat({ "# wba-keys v2", H.store_line(H.AGENT_ID, P256), H.store_line(H.AGENT_ID, P384),
    H.store_line(H.AGENT_ID, RSA, "rsa-pss-sha512") }, "\n") .. "\n")
local function headers_by(key, sign_alg, declared)
    local comps = '"@authority" "signature-agent";key="agent1"'
    local params = (';created=%d;expires=%d;keyid="%s"%s;tag="web-bot-auth"'):format(NOW - 5, NOW + 300, key.keyid,
        declared and (';alg="%s"'):format(declared) or "")
    local base = '"@authority": example.com\n"signature-agent";key="agent1": "' .. H.AGENT .. '"\n"@signature-params": ('
        .. comps .. ")" .. params
    return { { "Host", "example.com" }, { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' },
             { "Signature-Input", "sig1=(" .. comps .. ")" .. params },
             { "Signature", "sig1=:" .. b64.encode(H.sign(key, base, sign_alg)) .. ":" } }
end
for _, c in ipairs({ { P256, "ecdsa-p256-sha256", nil }, { P384, "ecdsa-p384-sha384", "ecdsa-p384-sha384" },
                     { RSA, "rsa-pss-sha512", nil }, { RSA, "rsa-pss-sha512", "rsa-pss-sha512" } }) do
    tx = run_entry(headers_by(c[1], c[2], c[3]), { keys_path = V2_PATH })
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "verified/", c[2] .. (c[3] and ", alg declared" or ", alg from the key"))
    H.eq(tx["tx.wba_keyid"], c[1].keyid)
    H.eq(tx["tx.wba_agent_proof"], "none")
end
tx = run_entry(headers_by(RSA, "rsa-v1_5-sha256", "rsa-v1_5-sha256"), { keys_path = V2_PATH })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/alg-mismatch", "the store pins the RSA key to RSA-PSS")
H.eq(tx["tx.wba_keyid"], nil)
local V1_PATH = H.tmp("wba-keys-v1.tsv")
H.write(V1_PATH, "# wba-keys v1\n" .. H.AGENT_ID .. "\t" .. KEY.keyid .. "\t" .. hex(KEY.raw) .. "\t-\t-\n")
tx = run_entry(signed_headers(), { keys_path = V1_PATH })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"] .. " " .. tx["tx.wba_agent_proof"], "verified/ none", "a version 1 store: proof none")
H.pass("a version 2 store: P-256, P-384 and RSA keys verify through the entry, the RSA key's pin holds; a version 1 store still verifies")

-- 14. Replay accounting (draft 5.3; replay.lua): a request is counted once,
-- at its final decision, only when verified; a count that cannot be kept
-- fails closed, before any verified-only variable is set.
local sha256 = require("wba.sha256")
local RDIR = H.tmp("replay-entry")
assert(H.sh(("rm -rf '%s' && mkdir -p '%s'"):format(RDIR, RDIR)))
local function files() local p = io.popen(("ls -A '%s' | wc -l"):format(RDIR)); local n = tonumber(p:read("a")); p:close(); return n end
local function rwith(headers, dir) return with({ ["tx.wba_replay_dir"] = dir or RDIR }, headers) end
local MC = '"@method" "@authority" "signature-agent";key="agent1"'
local function mc_lines(method) return { '"@method": ' .. method, '"@authority": example.com', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } end
tx = rwith(signed_headers())
H.eq(tx["tx.wba_status"] .. " " .. tx["tx.wba_uses"], "verified 1")
H.eq(tx["tx.wba_nonce_uses"], nil, "no nonce, no nonce count")
tx = rwith(signed_headers())
H.eq(tx["tx.wba_uses"], "2", "the same signature again (Ed25519 is deterministic)")
H.eq(with({}, signed_headers())["tx.wba_uses"], nil, "accounting off: nothing counted")
tx = rwith(ul)
H.eq(tx["tx.wba_reason"] .. " " .. tx["tx.wba_uses"], "url-less 1", "a URL-less signature is counted too: replay needs no directory")
H.eq(files(), 2)
tx = rwith(signed_headers({ nonce = "n-1" }))
H.eq(tx["tx.wba_uses"] .. " " .. tx["tx.wba_nonce_uses"], "1 1", "a new signature with a nonce")
tx = rwith(signed_headers({ nonce = "n-1", components = MC, lines = mc_lines("GET") }))
H.eq(tx["tx.wba_uses"] .. " " .. tx["tx.wba_nonce_uses"], "1 2", "another signature reusing the nonce")
local nfile = RDIR .. "/n." .. H.hex(sha256.digest("n-1"))
H.eq(#H.read(nfile), 2, "the nonce file is named by the nonce's SHA-256, never its bytes")
local before = files()
tx = rwith(signed_headers({ host = "evil.example", nonce = "n-2" }))
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/foreign-authority", "a Host that is not one of the site's names")
H.eq(tx["tx.wba_uses"], nil)
rwith(signed_headers({ nonce = "n-3" }))
first, t = two_phase(digest_headers(S256), HELLO, { settings = { ["tx.wba_replay_dir"] = RDIR } })
H.eq(first .. " " .. t["tx.wba_status"] .. " " .. t["tx.wba_uses"], "unverified/digest-pending verified 1",
    "a body-bound signature: not counted while pending, counted once when verified in phase 2")
H.eq(files(), before + 3, "the refused request added nothing; n-3 added two files, the body-bound signature one")
local c
tx, c = with({ ["tx.wba_replay_dir"] = RDIR .. "/missing" }, signed_headers({ nonce = "n-4" }))
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/replay-unavailable", "fail closed")
for _, k in ipairs({ "agent", "keyid", "label", "sighash", "uses", "nonce_uses" }) do
    H.eq(tx["tx.wba_" .. k], nil, k .. " is set only on verified")
end
H.eq(#c.log == 1 and c.log[1]:find("replay", 1, true) ~= nil, true, "the debug log says why")
for _, bad in ipairs({ "var/lib/wba", "/var/lib/wba/", "/var//lib", "/var/lib wba", "/var/lib/$x", "/var/lib/../etc", "/var/./lib", "/.." }) do
    tx, c = with({ ["tx.wba_replay_dir"] = bad })
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config", "tx.wba_replay_dir=" .. bad)
    H.eq(c.log[1]:find("wba_replay_dir", 1, true) ~= nil, true, "the log names the setting")
end
-- Every verified signature in a request is counted, not only the one
-- reported: the second, sent alone later, is a reuse.
local function two_sigs(only_second)
    local agent = '"signature-agent";key="agent1": "' .. H.AGENT .. '"'
    local c1, c2 = '"@authority" "signature-agent";key="agent1"', '"@method" "@authority" "signature-agent";key="agent1"'
    local function params(nonce)
        return (';created=%d;expires=%d;keyid="%s";nonce="%s";tag="web-bot-auth"'):format(NOW - 5, NOW + 300, KEY.keyid, nonce)
    end
    local p1, p2 = params("two-1"), params("two-2")
    local s1 = b64.encode(H.sign(KEY, '"@authority": example.com\n' .. agent .. '\n"@signature-params": (' .. c1 .. ")" .. p1))
    local s2 = b64.encode(H.sign(KEY, '"@method": GET\n"@authority": example.com\n' .. agent .. '\n"@signature-params": (' .. c2 .. ")" .. p2))
    local h = { { "Host", "example.com" }, { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' } }
    if only_second then
        h[3], h[4] = { "Signature-Input", "sig2=(" .. c2 .. ")" .. p2 }, { "Signature", "sig2=:" .. s2 .. ":" }
    else
        h[3] = { "Signature-Input", "sig1=(" .. c1 .. ")" .. p1 .. ", sig2=(" .. c2 .. ")" .. p2 }
        h[4] = { "Signature", "sig1=:" .. s1 .. ":, sig2=:" .. s2 .. ":" }
    end
    return h
end
before = files()
tx = rwith(two_sigs())
H.eq(tx["tx.wba_status"] .. " " .. tx["tx.wba_uses"] .. " " .. tx["tx.wba_nonce_uses"], "verified 1 1")
H.eq(files(), before + 4, "both signatures and both nonces counted")
tx = rwith(two_sigs(true))
H.eq(tx["tx.wba_uses"] .. " " .. tx["tx.wba_nonce_uses"], "2 2", "the second signature, sent alone later, is a reuse")
-- The counter keys on the signed statement (the signature base), not on
-- signature bytes: ECDSA's (r, n - s) verifies too, and a fresh ECDSA
-- signature over the same base is another set of bytes for the same thing.
local function run_ec(headers) return run_entry(headers, { keys_path = V2_PATH, tx = { ["tx.wba_replay_dir"] = RDIR } }) end
local ec = headers_by(P256, "ecdsa-p256-sha256", nil)
tx = run_ec(ec)
H.eq(tx["tx.wba_status"] .. " " .. tx["tx.wba_uses"], "verified 1")
local first_sighash = tx["tx.wba_sighash"]
local negated = H.ecdsa_negate_s(b64.decode(ec[4][2]:match("^sig1=:(.*):$")), "ecdsa-p256-sha256")
tx = run_ec({ ec[1], ec[2], ec[3], { "Signature", "sig1=:" .. b64.encode(negated) .. ":" } })
H.eq(tx["tx.wba_status"] .. " " .. tx["tx.wba_uses"], "verified 2", "(r, n - s) verifies and is the same statement")
H.eq(tx["tx.wba_sighash"] ~= first_sighash, true, "different signature bytes")
tx = run_ec(headers_by(P256, "ecdsa-p256-sha256", nil))
H.eq(tx["tx.wba_status"] .. " " .. tx["tx.wba_uses"], "verified 3", "a fresh ECDSA signature over the same base is the same statement")
-- Draft 5.3: an origin that wants a nonce on every signature can require one.
tx = with({ ["tx.wba_require_nonce"] = "1" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/missing-nonce")
H.eq(tx["tx.wba_keyid"], nil)
H.eq(with({ ["tx.wba_require_nonce"] = "1" }, signed_headers({ nonce = "n-5" }))["tx.wba_status"], "verified")
H.eq(with({ ["tx.wba_require_nonce"] = "0" })["tx.wba_status"], "verified")
tx, c = with({ ["tx.wba_require_nonce"] = "yes" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config")
H.eq(c.log[1]:find("wba_require_nonce", 1, true) ~= nil, true, "the log names the setting")
H.eq(with({ ["tx.wba_strict_field_lines"] = "1" })["tx.wba_status"], "verified", "strict field lines on: a one-line request is unaffected")
tx, c = with({ ["tx.wba_strict_field_lines"] = "on" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config")
H.eq(c.log[1]:find("wba_strict_field_lines", 1, true) ~= nil, true, "the log names the setting")
H.pass("replay accounting: every verified signature counted by its signed statement (ECDSA variants and re-signs included), nonces apart, fail closed, malformed settings loud; a nonce can be required")

-- 15. Where lua-openssl loads (the image's test stage), the same requests
-- through the entry with crypto.lua itself, as ModSecurity runs it.
if pcall(require, "openssl") then
    local cases = { { P256, "ecdsa-p256-sha256" }, { P384, "ecdsa-p384-sha384" }, { RSA, "rsa-pss-sha512" } }
    for _, c in ipairs(cases) do
        tx = run_entry(headers_by(c[1], c[2], c[2]), { keys_path = V2_PATH, real_crypto = true })
        H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "verified/", c[2] .. " with lua-openssl")
    end
    tx = run_entry(signed_headers(), { real_crypto = true })
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "verified/", "ed25519 with lua-openssl")
    -- Both names listed, so the site check passes and lua-openssl must refuse the changed @authority.
    tx = run_entry(signed_headers({ host = "evil.example" }),
        { real_crypto = true, tx = { ["tx.wba_site_names"] = "example.com evil.example" } })
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/bad-signature", "a changed @authority with lua-openssl")
    first, t = two_phase(digest_headers(S512), HELLO, { real_crypto = true })
    H.eq(first .. " " .. t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "unverified/digest-pending verified/",
        "a SHA-512 Content-Digest checked with lua-openssl's sha512")
    t = select(2, two_phase(digest_headers(S512), HELLO .. "!", { real_crypto = true }))
    H.eq(t["tx.wba_status"] .. "/" .. t["tx.wba_reason"], "invalid/digest-mismatch")
    H.pass("ECDSA, RSA-PSS and Ed25519 signatures and SHA-512 bodies verify through the entry with lua-openssl itself")
elseif os.getenv("WBA_REQUIRE_OPENSSL") == "1" then
    error("lua-openssl required here but did not load")
else
    print("SKIP: lua-openssl not installed; the entry runs with it in the image's test stage")
end

-- 13. Settings decided 2026-10-09: site names, max age, expiry grace, RFC 9651 4.2 mode.
tx = run_entry(signed_headers(), { no_site_names = true })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/no-site-names", "no site names configured: nothing verifies")
local other = signed_headers({ host = "other.example", lines = { '"@authority": other.example', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } })
tx = with({ ["tx.wba_grant_agents"] = H.AGENT, ["tx.wba_grant_require_components"] = "none" }, other)
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"] .. "/" .. (tx["tx.wba_granted"] or "-"), "invalid/foreign-authority/-",
    "a signature made for other.example, replayed here with its Host: refused, never granted (review F1)")
tx = with({ ["tx.wba_site_names"] = "Example.COM:443 www.example.com" })
H.eq(tx["tx.wba_status"], "verified", "site names normalized like the Host header")
for _, bad in ipairs({ "https://example.com", "example.com/x", "example.com:x", "*.example.com" }) do
    tx = with({ ["tx.wba_site_names"] = bad })
    H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config", "site name " .. bad)
end
for setting, values in pairs({ ["tx.wba_max_age"] = { "-1", "1h", "9999999" }, ["tx.wba_expiry_grace"] = { "61", "x" },
    ["tx.wba_malformed"] = { "drop", "IGNORE" } }) do
    for _, v in ipairs(values) do
        tx = with({ [setting] = v })
        H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config", setting .. "=" .. v)
    end
end
tx = with({ ["tx.wba_max_age"] = "0" })
H.eq(tx["tx.wba_status"], "verified", "max_age 0: no age limit")
tx = with({ ["tx.wba_expiry_grace"] = "60", ["tx.wba_max_age"] = "3600" })
H.eq(tx["tx.wba_status"], "verified")
-- Each setting reaches the verifier: requests the default decides one way
-- and the setting the other (a renamed policy key would pass the lines above).
local OLD = signed_headers({ created = NOW - 700, expires = NOW + 300 })
H.eq(with({}, OLD)["tx.wba_status"], "verified", "700 s old: within the default hour")
tx = with({ ["tx.wba_max_age"] = "600" }, OLD)
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/too-old", "tx.wba_max_age=600 reaches the verifier")
local LATE = signed_headers({ created = NOW - 200, expires = NOW - 30 })
tx = with({}, LATE)
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "invalid/expired", "strict expiry by default")
H.eq(with({ ["tx.wba_expiry_grace"] = "60" }, LATE)["tx.wba_status"], "verified", "tx.wba_expiry_grace=60 reaches the verifier")
local SPLIT = signed_headers()
SPLIT[2] = { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' }
table.insert(SPLIT, 3, { "Signature-Agent", 'agent9="https://x' })
table.insert(SPLIT, 4, { "Signature-Agent", 'y"' })
H.eq(with({}, SPLIT)["tx.wba_status"], "verified", "a Signature-Agent split inside a String: combined, it verifies")
tx = with({ ["tx.wba_strict_field_lines"] = "1" }, SPLIT)
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "not-signed/unparsable-field", "tx.wba_strict_field_lines=1 reaches the verifier")
tx = with({ ["tx.wba_max_window"] = "0" })
H.eq(tx["tx.wba_status"] .. "/" .. tx["tx.wba_reason"], "unverified/bad-config", "tx.wba_max_window=0 is not a window")
H.pass("site names required and normalized; another site's signature refused; max_age, expiry_grace and malformed validated")

H.done("test_entry")
