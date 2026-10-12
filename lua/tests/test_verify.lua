-- test_verify.lua: the verification state machine.
--
-- Ground truth comes from outside this codebase: the WBA draft's own E.2
-- vectors, and requests signed by openssl over signature bases written out
-- by hand below (never produced by sigbase.lua), so a bug shared by signer
-- and verifier cannot pass. Run: lua lua/tests/test_verify.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local verify = require("wba.verify")
local keys = require("wba.keys")
local b64 = require("wba.base64")

local NOW = 1700000000
local KEY, KEY2 = H.new_key(), H.new_key()
local STORE = { [H.AGENT_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } } }
local not_verified = {} -- every non-verified result, checked for identity leaks at the end

local function run(req, o)
    o = o or {}
    local store = STORE
    if o.store ~= nil then store = o.store or nil end
    local r = verify.verify(req, store, o.now or NOW, o.crypto or H.crypto_verify, o.policy, o.hash)
    if r.status ~= "verified" then not_verified[#not_verified + 1] = r end
    return r
end

local REJECT = { malformed = "reject" } -- RFC 9651 4.2's other branch: the message is malformed
local GRACE = { expiry_grace = 60 }     -- the graceful expiry an operator may choose

local function expect(r, status, reason, msg)
    H.eq(r.status .. "/" .. r.reason, status .. "/" .. reason, msg)
end

--- A request signed by openssl. o.lines are the covered-component lines of
--- the signature base, written by hand; the @signature-params line is
--- "(" .. o.components .. ")" .. o.params, exactly as sent in Signature-Input.
local function signed(o)
    o = o or {}
    local key = o.key or KEY
    local label = o.label or "sig1"
    local comps = o.components or '"@authority" "signature-agent";key="agent1"'
    local params = o.params or (';created=%d;expires=%d;keyid="%s";alg="ed25519";tag="web-bot-auth"')
        :format(o.created or NOW - 10, o.expires or NOW + 300, key.keyid)
    local lines = o.lines or { '"@authority": example.com', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' }
    local base = table.concat(lines, "\n") .. "\n" .. '"@signature-params": (' .. comps .. ")" .. params
    local sig = o.sig or H.sign(key, base)
    local headers = {
        { "Signature-Agent", o.agent_header or ('agent1="' .. H.AGENT .. '"') },
        { "Signature-Input", label .. "=(" .. comps .. ")" .. params },
        { "Signature", label .. "=:" .. b64.encode(sig) .. ":" },
    }
    for _, h in ipairs(o.extra_headers or {}) do headers[#headers + 1] = h end
    return H.request({ headers = headers, method = o.method, path = o.path, query = o.query,
                       authority = o.authority, scheme = o.scheme })
end

-- 1. Baseline
local r = run(signed())
expect(r, "verified", "")
H.eq(r.agent, H.AGENT_ID)
H.eq(r.keyid, KEY.keyid)
H.pass("draft-shaped request (dictionary Signature-Agent, ;key= coverage) verifies; agent is the well-known URL")

-- 2. Draft E.2 vectors, verbatim headers, RFC 9421 B.1.4 key.
local E_STORE = { ["https://signature-agent.test/.well-known/http-message-signatures-directory"] =
    { [H.RFC_KEYID] = { type = "ed25519", key = H.RFC_KEY_RAW } } }
local e22 = H.request({ headers = {
    { "Signature-Agent", '"https://signature-agent.test"' },
    { "Signature-Input", 'sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"' },
    { "Signature", "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:" },
} })
expect(run(e22, { store = E_STORE, now = 1735689700, policy = { reject_test_keys = false } }), "verified", "",
    "E.2.2 legacy form")
expect(run(e22, { store = E_STORE, now = 1735689700 }), "invalid", "test-key", "E.2.2 under default policy")
local e21 = H.request({ headers = {
    { "Signature-Agent", 'agent2="https://signature-agent.test"' },
    { "Signature-Input", 'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"' },
    { "Signature", "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:" },
} })
expect(run(e21, { store = E_STORE, now = 1735689700, policy = { reject_test_keys = false, max_window = false } }),
    "verified", "", "E.2.1 with the window check off")
expect(run(e21, { store = E_STORE, now = 1735689700, policy = { reject_test_keys = false } }),
    "verified", "", "E.2.1's 100-year window under default policy: max_age bounds it, not a window cap")
expect(run(e21, { store = E_STORE, now = 1735689600 + 3601, policy = { reject_test_keys = false } }),
    "invalid", "too-old", "E.2.1 an hour and a second after created: max_age, by default")
expect(run(e21, { store = E_STORE, now = 1735689700, policy = { reject_test_keys = false, max_age = false } }),
    "invalid", "window-too-long", "with max_age off, a window over a day is refused by default")
expect(run(e21, { store = E_STORE, now = 1735689700, policy = { reject_test_keys = false, max_window = 3600 } }),
    "invalid", "window-too-long", "an operator's own window cap applies with max_age on")
H.pass("draft E.2.1 and E.2.2 verify; by default max_age bounds a long window, and a day caps it only with max_age off")

-- 3. Tampering with a covered component
expect(run(signed({ authority = "evil.example" })), "invalid", "bad-signature")
H.pass("changed @authority fails the signature")

-- 4. Freshness and parameter types
local function p(fmt, ...) return fmt:format(...) end
local kid = KEY.keyid
expect(run(signed({ params = p(';created=%d;keyid="%s";tag="web-bot-auth"', NOW - 10, kid) })), "invalid", "missing-param")
expect(run(signed({ params = p(';expires=%d;keyid="%s";tag="web-bot-auth"', NOW + 10, kid) })), "invalid", "missing-param")
expect(run(signed({ params = p(';created="%d";expires=%d;keyid="%s";tag="web-bot-auth"', NOW, NOW + 10, kid) })), "invalid", "bad-param")
expect(run(signed({ params = p(';created=0x10;expires=%d;keyid="%s";tag="web-bot-auth"', NOW + 10, kid) }), { policy = REJECT }), "invalid", "malformed-headers")
expect(run(signed({ params = p(';created=%d;expires=1e999;keyid="%s";tag="web-bot-auth"', NOW, kid) }), { policy = REJECT }), "invalid", "malformed-headers")
expect(run(signed({ params = p(';created=0x10;expires=%d;keyid="%s";tag="web-bot-auth"', NOW + 10, kid) })), "not-signed", "unparsable-field",
    "RFC 9651 4.2: by default an unparsable Signature-Input is ignored, so the request is not signed")
expect(run(signed({ created = NOW, expires = NOW })), "invalid", "bad-param")
-- RFC 9421 4.2: each Signature member is a Byte Sequence; a String or an
-- Inner List holding one is not a signature.
for _, v in ipairs({ '"' .. b64.encode(("\1"):rep(64)) .. '"', "(:" .. b64.encode(("\1"):rep(64)) .. ":)" }) do
    local bad = signed()
    bad.fields.signature = { "sig1=" .. v }
    expect(run(bad), "invalid", "bad-signature", "Signature member " .. v:sub(1, 2) .. "...")
end
expect(run(signed({ created = NOW - 10, expires = NOW + 90000 })), "verified", "",
    "a 25-hour window is not refused by default: max_age bounds use (draft 5.2's 24 h is advice to signers)")
expect(run(signed({ created = NOW - 10, expires = NOW + 90000 }), { policy = { max_age = false } }), "invalid", "window-too-long")
expect(run(signed({ created = NOW + 30 })), "verified", "", "created 30s ahead is within skew")
expect(run(signed({ created = NOW + 120 })), "invalid", "not-yet-valid")
expect(run(signed({ created = NOW - 200, expires = NOW - 30 })), "invalid", "expired", "strict expiry by default")
expect(run(signed({ created = NOW - 200, expires = NOW - 30 }), { policy = GRACE }), "verified", "", "expired 30s ago: within a 60 s grace")
expect(run(signed({ created = NOW - 300, expires = NOW - 120 }), { policy = GRACE }), "invalid", "expired")
expect(run(signed({ created = NOW - 3600, expires = NOW + 60 })), "verified", "", "signed an hour ago exactly: max_age reached, not passed")
expect(run(signed({ created = NOW - 3601, expires = NOW + 60 })), "invalid", "too-old", "RFC 9421 3.2.1 max age, 3600 s by default")
expect(run(signed({ created = NOW - 82800, expires = NOW + 300 })), "invalid", "too-old", "a day-old signature that has not expired")
expect(run(signed({ created = NOW - 82800, expires = NOW + 300 }), { policy = { max_age = false } }), "verified", "", "max_age off")
H.pass("created/expires required Integers; hex, exponent, reversed, over-long, future, expired and too old all rejected; skew on created only")

-- 5. alg and keyid
local function with_alg(a) return p(';created=%d;expires=%d;keyid="%s";alg=%s;tag="web-bot-auth"', NOW, NOW + 10, kid, a) end
expect(run(signed({ params = with_alg('"ecdsa-p256-sha256"') })), "invalid", "alg-mismatch",
    "an allowed algorithm with the same signature length, but not for this Ed25519 key (RFC 9421 3.2 step 6.5)")
local calls_before = 0
expect(run(signed({ params = with_alg('"rsa-pss-sha512"') }), { store = function() calls_before = calls_before + 1; return STORE end }),
    "invalid", "bad-signature", "64 bytes can be no RSA signature of 2048 bits or more")
H.eq(calls_before, 0, "refused before the key-store read")
expect(run(signed({ params = with_alg('"hmac-sha256"') })), "invalid", "unsupported-alg", "draft 6.4: MUST NOT use shared HMAC")
for _, a in ipairs({ '"ED25519"', '"EdDSA"', '"RS256"', '"none"', 'ed25519', '"rsa-pss-sha256"' }) do
    expect(run(signed({ params = with_alg(a) })), "invalid", "unsupported-alg", "alg=" .. a)
end
expect(run(signed({ params = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW, NOW + 10, kid) })), "verified", "", "alg may be absent")
expect(run(signed({ params = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW, NOW + 10, "short") })), "invalid", "bad-keyid")
expect(run(signed({ params = p(';created=%d;expires=%d;keyid=%s;tag="web-bot-auth"', NOW, NOW + 10, "tok") })), "invalid", "bad-param")
H.pass("alg: a registry name of RFC 9421 3.3 other than hmac-sha256, for this key's type; keyid a 43-char base64url String")

-- 6. Coverage: what the signature must bind
expect(run(signed({ components = '"@authority"', lines = { '"@authority": example.com' } })), "invalid", "agent-not-covered")
expect(run(signed({ components = '"signature-agent";key="agent1"',
    lines = { '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } })), "invalid", "authority-not-covered")
expect(run(signed({ components = '"@authority" "signature-agent";key="agent1" "signature-agent"',
    lines = { '"@authority": example.com', '"signature-agent";key="agent1": "' .. H.AGENT .. '"',
              '"signature-agent": agent1="' .. H.AGENT .. '"' } })), "invalid", "agent-not-covered",
    "two covered, so the label decides, and no member is keyed sig1")
H.pass("must cover @authority and a Signature-Agent member it can be attributed to (draft 5.2, 5.2.1)")

-- 7. Attribution cannot be moved to someone else
local VICTIM = "https://victim.example"
local VICTIM_ID = VICTIM .. "/.well-known/http-message-signatures-directory"
local both = { [H.AGENT_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } }, [VICTIM_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } } }
expect(run(signed({ agent_header = 'agent1="' .. VICTIM .. '"' }), { store = both }), "invalid", "bad-signature",
    "swapping the covered member's URL breaks the signature")
expect(run(signed(), { store = { [VICTIM_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } } } }), "unverified", "unknown-agent",
    "the key only counts for the directory it was resolved from")
expect(run(signed(), { store = { [H.AGENT_ID] = { [KEY2.keyid] = { type = "ed25519", key = KEY2.raw } } } }), "unverified", "unknown-key")
expect(run(signed({ key = KEY2 }), { store = { [H.AGENT_ID] = { [KEY2.keyid] = { type = "ed25519", key = KEY.raw } } } }), "invalid", "bad-signature",
    "store entry under the right keyid but the wrong key")
H.pass("lookup keyed on (directory, keyid): a key never verifies for another agent (draft 5.4)")

-- 8. Signature-Agent member must be an https origin of type directory
local function agent_case(url_member)
    return signed({ agent_header = "agent1=" .. url_member,
        lines = { '"@authority": example.com', '"signature-agent";key="agent1": ' .. url_member } })
end
expect(run(agent_case('"http://agent.example"')), "invalid", "agent-not-https", "draft 5.2.1: the scheme MUST be https")
expect(run(agent_case('"http://agent.example/path"')), "unverified", "bad-agent-url",
    "draft 5.5: a directory member that is not an origin is ignored, whatever its scheme")
expect(run(agent_case('"http://agent.example/path";type=jwks_uri')), "invalid", "agent-not-https",
    "draft 5.2.1: a jwks_uri must be https")
expect(run(agent_case('"https://agent.example/keys"')), "unverified", "bad-agent-url")
expect(run(agent_case('"file:///etc/passwd"')), "unverified", "bad-agent-url", "not an origin: ignored (5.5)")
expect(run(agent_case('"file:///etc/passwd";type=cimd')), "invalid", "agent-not-https", "a cimd URL must be https (5.2.1)")
expect(run(agent_case('"HTTPS://agent.example"')), "unverified", "bad-agent-url", "https, but not the ASCII serialization of an origin: ignored (5.5)")
expect(run(agent_case('"https://Agent.example"')), "unverified", "bad-agent-url", "an origin's serialization is lowercase (RFC 6454 6.2)")
expect(run(agent_case('"agent.example"')), "unverified", "bad-agent-url", "not a URI: the field MAY be ignored (5.2.1)")
expect(run(agent_case('"https://agent.example";type=x509')), "unverified", "unsupported-agent-type")
expect(run(agent_case('"https://agent.example";type="jwks_uri"')), "unverified", "unsupported-agent-type",
    "type is a Token (5.2.1); a String is not a type this verifier supports")
expect(run(agent_case('"https://agent.example";type=jwks_uri')), "unverified", "unknown-agent",
    "a jwks_uri member is its own identifier (https://agent.example/), not the origin's directory")
expect(run(agent_case("agent")), "unverified", "bad-agent-url")
expect(run(agent_case('"https://agent.example";type=directory')), "verified", "", "explicit type=directory")
expect(run(agent_case('"https://agent.example:443"')), "unverified", "bad-agent-url",
    "an explicit default port is not the origin's ASCII serialization (5.5, RFC 6454 6.2): ignored")
expect(run(agent_case('"https://agent.example/"')), "verified", "", "an empty path / MAY be accepted (5.5)")
H.pass("non-https members fail (invalid, 5.2.1); path-carrying, non-origin and unknown-type members are ignored (unverified, 5.5)")

-- 9. Signature-Agent shapes
expect(run(signed({ agent_header = '"' .. H.AGENT .. '"', components = '"@authority" "signature-agent"',
    lines = { '"@authority": example.com', '"signature-agent": "' .. H.AGENT .. '"' } })), "verified", "", "legacy string")
expect(run(signed({ agent_header = 'sig1="' .. H.AGENT .. '"', components = '"@authority" "signature-agent"',
    lines = { '"@authority": example.com', '"signature-agent": sig1="' .. H.AGENT .. '"' } })), "verified", "",
    "dictionary covered whole: member keyed by the signature label")
expect(run(signed({ agent_header = 'other="' .. H.AGENT .. '"', components = '"@authority" "signature-agent"',
    lines = { '"@authority": example.com', '"signature-agent": other="' .. H.AGENT .. '"' } })), "invalid", "agent-not-covered")
expect(run(signed({ agent_header = 'agent9="' .. H.AGENT .. '"' })), "invalid", "missing-component",
    "covered member absent from the header")
H.pass("Signature-Agent: dictionary (;key or label), legacy string; absent member refused")

-- 10. Components
local function comp_case(components, lines, extra)
    extra = extra or {}
    local all_lines = {}
    for _, x in ipairs(lines) do all_lines[#all_lines + 1] = x end
    all_lines[#all_lines + 1] = '"signature-agent";key="agent1": "' .. H.AGENT .. '"'
    return signed({ components = components .. ' "signature-agent";key="agent1"', lines = all_lines,
        extra_headers = extra.headers, method = extra.method, path = extra.path,
        query = extra.query, scheme = extra.scheme })
end
expect(run(comp_case('"@method" "@path" "@query" "@authority"',
    { '"@method": POST', '"@path": /a%2Fb', '"@query": ?x=1&y=%3F', '"@authority": example.com' },
    { method = "POST", path = "/a%2Fb", query = "x=1&y=%3F" })), "verified", "", "method/path/query raw")
expect(run(comp_case('"@path" "@query" "@authority"', { '"@path": /', '"@query": ?', '"@authority": example.com' },
    { path = "" })), "verified", "", "empty path is '/', absent query is '?'")
expect(run(comp_case('"@target-uri"', { '"@target-uri": https://example.com/p?q=1' },
    { path = "/p", query = "q=1" })), "verified", "", "@target-uri from scheme+authority+path+query")
local no_scheme = comp_case('"@target-uri"', { '"@target-uri": https://example.com/p' }, { path = "/p" })
no_scheme.scheme = nil
expect(run(no_scheme), "invalid", "unsupported-component", "@target-uri needs a configured scheme")
expect(run(comp_case('"@authority" "x-a"', { '"@authority": example.com', '"x-a": 1, 2' },
    { headers = { { "X-A", " 1 " }, { "x-a", "2" } } })), "verified", "", "instances trimmed and joined with ', '")
expect(run(comp_case('"@authority" "x.y"', { '"@authority": example.com', '"x.y": v' },
    { headers = { { "x.y", "v" } } })), "verified", "", "dotted field names are plain data here")
expect(run(comp_case('"@authority" "x-missing"', { '"@authority": example.com', '"x-missing": ' })),
    "invalid", "missing-component")
for _, c in ipairs({ '"@foo"', '"@query-param"', '"@status"', '"@method";req', '"Host"', '"x-a";req', '"x-a";tr',
    '"x-a";sf', '"x-a";bs;sf', '"x-a";bs;key="a"', '"x-a";key=tok', '"x-a";name="q"' }) do
    expect(run(comp_case('"@authority" ' .. c, { '"@authority": example.com' },
        { headers = { { "x-a", "1" }, { "host", "h" } } })), "invalid", "unsupported-component", c)
end
H.pass("components: @method/@path/@query/@target-uri, header combining; @status, ;req, ;tr, ;sf on an untyped field, ;bs with ;sf or ;key, and unknown names refused")

-- 11. Several signatures (draft 5.2.2)
local function multi(labels_and_sigs)
    local inputs, sigs = {}, {}
    local params = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW - 10, NOW + 300, kid)
    local comps = '"@authority" "signature-agent";key="agent1"'
    local base = '"@authority": example.com\n"signature-agent";key="agent1": "' .. H.AGENT .. '"\n'
        .. '"@signature-params": (' .. comps .. ")" .. params
    for _, ls in ipairs(labels_and_sigs) do
        local sig = ls[2] == "good" and H.sign(KEY, base) or string.rep("\0", 64)
        inputs[#inputs + 1] = ls[1] .. "=(" .. comps .. ")" .. params
        sigs[#sigs + 1] = ls[1] .. "=:" .. b64.encode(sig) .. ":"
    end
    return H.request({ headers = { { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' },
        { "Signature-Input", table.concat(inputs, ", ") }, { "Signature", table.concat(sigs, ", ") } } })
end
r = run(multi({ { "a", "bad" }, { "b", "good" } }))
expect(r, "verified", "", "a bogus first signature does not mask a valid second one")
H.eq(r.label, "b")
expect(run(multi({ { "a", "bad" }, { "b", "bad" } })), "invalid", "bad-signature")
r = run(multi({ { "a", "bad" }, { "b", "bad" }, { "c", "bad" }, { "d", "good" } }))
expect(r, "verified", "", "draft 5.2.2: every signature is validated, the fourth too")
H.eq(r.label, "d")
expect(run(multi({ { "a", "bad" }, { "b", "good" }, { "c", "good" } }), { policy = { max_signatures = 2 } }),
    "unverified", "too-many-signatures", "an optional local cap is a limit of this verifier: cannot decide")
H.pass("each web-bot-auth signature validated independently, all of them; an optional cap gives unverified")

-- 11b. Signature-Agent is parsed once per request, however many signatures
-- name it (review finding: 150 labels over an 8 KiB field cost 195 ms when
-- every signature parsed it again).
do
    local sf = require("wba.structured_fields")
    local real, agent_parses = sf.parse_dictionary, 0
    sf.parse_dictionary = function(s, ...)
        if s == 'agent1="' .. H.AGENT .. '"' then agent_parses = agent_parses + 1 end
        return real(s, ...)
    end
    local labels = {}
    for n = 1, 20 do labels[n] = { "s" .. n, "bad" } end
    labels[21] = { "s21", "good" }
    local ok, res = pcall(run, multi(labels))
    sf.parse_dictionary = real
    assert(ok, res)
    expect(res, "verified", "", "the 21st signature still verifies")
    H.eq(agent_parses, 1, "21 signatures, one parse of Signature-Agent")
    H.pass("Signature-Agent parsed once per request")
end

-- 12. Header presence
expect(run(H.request({})), "not-signed", "no-signature")
expect(run(H.request({ headers = { { "Signature", "a=:AAAA:" } } })), "invalid", "orphan-label", "Signature alone (RFC 9421 4)")
expect(run(H.request({ headers = { { "Signature-Input", 'a=("@authority");created=1;expires=2;keyid="k";tag="web-bot-auth"' } } })),
    "invalid", "orphan-label", "Signature-Input alone")
expect(run(H.request({ headers = { { "Signature-Input", 'a=("@authority");created=1;expires=2;keyid="k";tag="other"' },
    { "Signature", "a=:AAAA:" } } })), "not-signed", "no-wba-signature")
local no_agent = signed()
no_agent.fields["signature-agent"] = nil
expect(run(no_agent), "invalid", "missing-component")
H.pass("no headers, half a pair, non-WBA tags, and a missing Signature-Agent")

-- 13. Key store states and the crypto seam
expect(run(signed(), { store = false }), "unverified", "keystore-unavailable")
expect(run(signed(), { store = { [H.AGENT_ID] = { [kid] = { type = "ed25519", key = KEY.raw, nbf = NOW + 100 } } } }), "unverified", "key-not-current")
expect(run(signed(), { store = { [H.AGENT_ID] = { [kid] = { type = "ed25519", key = KEY.raw, exp = NOW } } } }), "unverified", "key-not-current")
expect(run(signed(), { crypto = function() error("library missing") end }), "unverified", "crypto-error")
expect(run(signed(), { crypto = function() return 1 end }), "invalid", "bad-signature", "only boolean true verifies")
expect(run(signed({ sig = string.rep("\1", 32) })), "invalid", "bad-signature", "32-byte signature")
H.pass("store unavailable/expired keys are unverified; crypto errors never verify; wrong-length signatures refused")

-- 14a. Boundaries and cases found by the second independent review
expect(run(signed({ created = NOW + 60 })), "verified", "", "created exactly at +skew")
expect(run(signed({ created = NOW + 61 })), "invalid", "not-yet-valid")
expect(run(signed({ created = NOW - 100, expires = NOW + 1 })), "verified", "", "expires one second ahead")
expect(run(signed({ created = NOW - 100, expires = NOW })), "invalid", "expired", "expires == now")
expect(run(signed({ created = NOW - 100, expires = NOW - 59 }), { policy = GRACE }), "verified", "", "expires+grace one second ahead")
expect(run(signed({ created = NOW - 100, expires = NOW - 60 }), { policy = GRACE }), "invalid", "expired", "expires+grace == now")
expect(run(signed({ params = p(';created=%d;expires=%d;keyid="%s";nonce=5;tag="web-bot-auth"', NOW, NOW + 10, kid) })),
    "invalid", "bad-param", "non-string nonce")
expect(run(comp_case('"@authority";req', { '"@authority";req: example.com' })), "invalid", "unsupported-component")
expect(run(comp_case('"@method";x "@authority"', { '"@method";x: GET', '"@authority": example.com' })),
    "invalid", "unsupported-component", "parameters on a derived component")
expect(run(comp_case('1 "@authority"', { '"@authority": example.com' })), "invalid", "unsupported-component",
    "non-string component identifier")
local nonorigin = comp_case('"@authority" "@query"', { '"@authority": example.com', '"@query": ?' })
nonorigin.path, nonorigin.query = nil, nil
expect(run(nonorigin), "invalid", "missing-component",
    "non-origin-form target: @query is unavailable, not '?' (GET http://host?evil=1)")
expect(run(comp_case('"@authority" "x-a"', { '"@authority": example.com', '"x-a": caf\195\169' },
    { headers = { { "x-a", "caf\195\169" } } })), "invalid", "bad-component-value", "non-ASCII value (RFC 9421 2.5)")
expect(run(comp_case('"@authority" "x-a"', { '"@authority": example.com', '"x-a": a\tb' },
    { headers = { { "x-a", "a\tb" } } })), "verified", "", "HTAB inside a value is ASCII")
local calls = 0
local lazy = function() calls = calls + 1; return STORE end
expect(run(H.request({ headers = { { "Signature-Input", "x=(" }, { "Signature", "x=:AAAA:" } } }), { store = lazy }),
    "not-signed", "unparsable-field")
H.eq(calls, 0, "store not loaded for a malformed request")
expect(run(multi({ { "a", "bad" }, { "b", "good" } }), { store = lazy }), "verified", "")
H.eq(calls, 1, "store loaded once for two signatures")
H.pass("skew boundaries, nonce/identifier types, derived-component params, non-origin @query, non-ASCII, lazy key store")

-- 14b. Found by the final review: header trimming must be linear, lowercasing
-- must not depend on the process locale.
H.eq(verify.trim_ows(" \t a \t b \t "), "a \t b")
H.eq(verify.trim_ows(""), "")
H.eq(verify.trim_ows(" \t "), "")
H.eq(verify.trim_ows("x"), "x")
local pad = "a" .. (" "):rep(32000) .. "b"
local t0 = os.clock()
expect(run(H.request({ headers = { { "Signature-Input", pad }, { "Signature", pad } } })), "not-signed", "unparsable-field")
local secs = os.clock() - t0
H.eq(secs < 0.5, true, ("two 32 KB headers of inner spaces took %.2fs; the backtracking trim took seconds"):format(secs))
H.eq(verify.ascii_lower("Example.COM:443"), "example.com:443")
H.eq(verify.ascii_lower("\192\221@[`{"), "\192\221@[`{", "bytes outside A-Z, and A-Z's neighbours, unchanged")
local latin1 = false
for _, name in ipairs({ "fr_FR.ISO8859-1", "fr_FR.ISO-8859-1", "fr_FR.iso88591" }) do
    if os.setlocale(name, "ctype") then latin1 = true break end
end
if latin1 then
    H.eq(verify.ascii_lower("\192"), "\192", "unchanged under a Latin-1 locale, where string.lower gives \\224")
    os.setlocale("C", "ctype")
elseif os.getenv("WBA_REQUIRE_LATIN1") == "1" then
    error("no Latin-1 locale (fr_FR.ISO-8859-1): the locale-independence check cannot run")
else
    print("SKIP: no Latin-1 locale; ascii_lower's locale independence is checked in CI (WBA_REQUIRE_LATIN1=1)")
end
calls = 0
local nosig = signed()
nosig.fields["signature"] = { "other=:" .. b64.encode(("\0"):rep(64)) .. ":" }
expect(run(nosig, { store = lazy }), "invalid", "orphan-label", "no Signature member for the label (RFC 9421 4)")
local shortsig = signed({ sig = ("\1"):rep(32) })
expect(run(shortsig, { store = lazy }), "invalid", "bad-signature", "a 32-byte Signature member")
H.eq(calls, 0, "store not loaded when the Signature member is missing")
H.pass("OWS trim is linear (32 KB of spaces), ASCII-only lowercase, no store read without a Signature member")

-- 14c. Draft Appendix D.2: a remote browser signs its own request and also
-- covers the agent's member and signature fields. Each signature is
-- attributed to the member keyed to its own label, never to the other one.
local BROWSER = "https://browser.example"
local BROWSER_ID = BROWSER .. "/.well-known/http-message-signatures-directory"
local function d2()
    local P = ';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"'
    local a_input = '("@method" "@authority" "@path" "signature-agent";key="agent")' .. P:format(NOW - 10, NOW + 300, KEY.keyid)
    local a_sig = H.sign(KEY, table.concat({ '"@method": GET', '"@authority": example.com', '"@path": /',
        '"signature-agent";key="agent": "' .. H.AGENT .. '"', '"@signature-params": ' .. a_input }, "\n"))
    local b_input = '("@method" "@authority" "@path" "signature-agent";key="browser" "signature-agent";key="agent"'
        .. ' "signature-input";key="agent" "signature";key="agent")' .. P:format(NOW - 9, NOW + 300, KEY2.keyid)
    local b_sig = H.sign(KEY2, table.concat({ '"@method": GET', '"@authority": example.com', '"@path": /',
        '"signature-agent";key="browser": "' .. BROWSER .. '"', '"signature-agent";key="agent": "' .. H.AGENT .. '"',
        '"signature-input";key="agent": ' .. a_input, '"signature";key="agent": :' .. b64.encode(a_sig) .. ":",
        '"@signature-params": ' .. b_input }, "\n"))
    return H.request({ headers = {
        { "Signature-Agent", 'agent="' .. H.AGENT .. '", browser="' .. BROWSER .. '"' },
        { "Signature-Input", "agent=" .. a_input .. ", browser=" .. b_input },
        { "Signature", "agent=:" .. b64.encode(a_sig) .. ":, browser=:" .. b64.encode(b_sig) .. ":" } } })
end
r = run(d2(), { store = { [BROWSER_ID] = { [KEY2.keyid] = { type = "ed25519", key = KEY2.raw } } } })
expect(r, "verified", "", "outer signature verifies, covering two Signature-Agent members")
H.eq(r.agent, BROWSER_ID)
H.eq(r.label, "browser")
r = run(d2(), { store = { [H.AGENT_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } } } })
expect(r, "verified", "", "inner signature verifies on its own")
H.eq(r.label, "agent")
expect(run(d2(), { store = { [H.AGENT_ID] = { [KEY2.keyid] = { type = "ed25519", key = KEY2.raw } } } }), "unverified", "unknown-key",
    "the outer signer is never attributed to the inner signer's directory, even if that lists its key")
local OTHER = "https://other-agent.example"
local function two_members(label)
    return signed({ label = label, agent_header = 'agent1="' .. OTHER .. '", agent2="' .. H.AGENT .. '"',
        components = '"@authority" "signature-agent";key="agent1" "signature-agent";key="agent2"',
        lines = { '"@authority": example.com', '"signature-agent";key="agent1": "' .. OTHER .. '"',
                  '"signature-agent";key="agent2": "' .. H.AGENT .. '"' } })
end
expect(run(two_members("agent2")), "verified", "", "label picks among covered members")
expect(run(two_members("agent1")), "unverified", "unknown-agent", "relabelled: that directory does not list the key")
expect(run(two_members("sig1")), "invalid", "ambiguous-agent", "neither covered member is keyed to the label")
H.pass("draft D.2: two signers, each attributed to its own covered member; ambiguous coverage refused")

-- 14d. Components added for RFC 9421 compliance, end to end (openssl signs
-- hand-written bases using the RFC's own example values).
local qp_comps = '"@authority" "@query-param";name="baz" "@query-param";name="qux" "@scheme" "@request-target"'
local qp_lines = { '"@authority": example.com', '"@query-param";name="baz": batman', '"@query-param";name="qux": ',
    '"@scheme": https', '"@request-target": /path?param=value&foo=bar&baz=batman&qux=' }
expect(run(comp_case(qp_comps, qp_lines, { path = "/path", query = "param=value&foo=bar&baz=batman&qux=" })),
    "verified", "", "@query-param (incl. an empty value), @scheme, @request-target")
expect(run(comp_case(qp_comps, qp_lines, { path = "/path", query = "param=value&foo=bar&baz=robin&qux=" })),
    "invalid", "bad-signature", "a changed query parameter")
expect(run(comp_case(qp_comps, qp_lines, { path = "/path", query = "param=value&baz=batman&baz=batman&qux=" })),
    "invalid", "missing-component", "a repeated parameter name cannot be signed")
-- RFC 9421 2.2.8's second example, with spaces in names and values: signed
-- with "+" (the steps' serializer) and with "%20" (the RFC's printed lines,
-- byte for byte); both verify. One base mixing the two does not.
local sp_query = "var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"
local sp_plus = { comps = '"@authority" "@query-param";name="var" "@query-param";name="bar" "@query-param";name="fa%C3%A7ade%22%3A+"',
    lines = { '"@authority": example.com', '"@query-param";name="var": this+is+a+big%0Amultiline+value',
        '"@query-param";name="bar": with+plus+whitespace', '"@query-param";name="fa%C3%A7ade%22%3A+": something' } }
local sp_rfc = { comps = '"@authority" "@query-param";name="var" "@query-param";name="bar" "@query-param";name="fa%C3%A7ade%22%3A%20"',
    lines = { '"@authority": example.com', '"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value',
        '"@query-param";name="bar": with%20plus%20whitespace', '"@query-param";name="fa%C3%A7ade%22%3A%20": something' } }
for _, s in ipairs({ { sp_plus, "+" }, { sp_rfc, "%20 (the RFC's example lines)" } }) do
    expect(run(comp_case(s[1].comps, s[1].lines, { path = "/parameters", query = sp_query })),
        "verified", "", "@query-param with spaces spelled " .. s[2])
    expect(run(comp_case(s[1].comps, s[1].lines, { path = "/parameters", query = sp_query:gsub("something", "other") })),
        "invalid", "bad-signature", "@query-param spelled " .. s[2] .. ", a changed value")
end
expect(run(comp_case('"@authority" "@query-param";name="var" "@query-param";name="bar"',
    { '"@authority": example.com', '"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value',
      '"@query-param";name="bar": with+plus+whitespace' }, { path = "/parameters", query = sp_query })),
    "invalid", "bad-signature", "one base mixing both spellings")
-- The other spelling is tried at most once per request: three forged
-- signatures over a spaced parameter cost four checks, not six.
do
    local calls = 0
    local function counting() calls = calls + 1 return false end
    local params = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW - 10, NOW + 300, kid)
    local comps = '("@authority" "@query-param";name="a" "signature-agent";key="agent1")'
    local zero = ":" .. b64.encode(("\0"):rep(64)) .. ":"
    local req = H.request({ query = "a=x+y", headers = {
        { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' },
        { "Signature-Input", ("s1=%s%s, s2=%s%s, s3=%s%s"):format(comps, params, comps, params, comps, params) },
        { "Signature", ("s1=%s, s2=%s, s3=%s"):format(zero, zero, zero) } } })
    expect(run(req, { crypto = counting }), "invalid", "bad-signature")
    H.eq(calls, 4, "one retry for the whole request")
end
expect(run(comp_case('"@authority" "priority";sf', { '"@authority": example.com', '"priority";sf: u=3, i' },
    { headers = { { "Priority", "u=3,   i" } } })), "verified", "", ";sf strict re-serialization")
local bs_lines = { '"@authority": example.com', '"x-h";bs: :YQ==:, :Yg==:' }
expect(run(comp_case('"@authority" "x-h";bs', bs_lines, { headers = { { "X-H", "a" }, { "x-h", "b" } } })),
    "verified", "", ";bs over two instances")
expect(run(comp_case('"@authority" "x-h";bs', bs_lines, { headers = { { "X-H", "a, b" } } })),
    "invalid", "bad-signature", ";bs tells one combined instance from two")
H.pass("@query-param, @scheme, @request-target, ;sf and ;bs verify end to end; tampering and repeats are refused")

-- 14e. RFC 9530: a signature over a body digest binds the body (RFC 9421
-- 7.2.8). Digest values are the RFCs' own, cross-checked with openssl:
-- RFC 9421 7.2.8 and B.2 hash {"hello": "world"}; RFC 9530 2 and B.4 hash
-- the same object followed by LF.
local HELLO, HELLO_LF = '{"hello": "world"}', '{"hello": "world"}\n'
local S256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
local S512 = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
local S256_LF = "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:"
local RFC9530_2 = "sha-256=:d435Qo+nKZ+gLcUHn7GQtQ72hiBVAgqoLsZnZPiTGPk=:, "
    .. "sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:"
local HASH = { ["sha-256"] = require("wba.sha256").digest, ["sha-512"] = H.sha512 }
local AGENT_LINE_T = '"signature-agent";key="agent1": "' .. H.AGENT .. '"'
local body_reads = 0

--- A request signed over @authority plus `components` (base lines `lines`),
--- carrying `headers`; `body` given = phase 2, absent = phase 1.
local function dg(components, lines, headers, body, complete, method)
    local req = comp_case('"@authority" ' .. components, { '"@authority": example.com', table.unpack(lines) },
        { headers = headers, method = method or "POST" })
    if body ~= nil then
        req.body = function() body_reads = body_reads + 1; return body, complete ~= false end
    end
    return req
end
local function cd(v) return dg('"content-digest"', { '"content-digest": ' .. v }, { { "Content-Digest", v } }) end
local function cdb(v, body, complete, extra)
    local hs = { { "Content-Digest", v } }
    for _, h in ipairs(extra or {}) do hs[#hs + 1] = h end
    return dg('"content-digest"', { '"content-digest": ' .. v }, hs, body, complete)
end
local function runh(req, policy) return run(req, { hash = HASH, policy = policy }) end

for _, f in ipairs({ "content-digest", "repr-digest", "unencoded-digest" }) do
    local function req(body) return dg('"' .. f .. '"', { '"' .. f .. '": ' .. S256 }, { { f, S256 } }, body) end
    expect(runh(req()), "unverified", "digest-pending", f .. ": phase 1 cannot see the body")
    expect(runh(req(HELLO)), "verified", "", f .. ": the body matches")
    expect(runh(req(HELLO .. " ")), "invalid", "digest-mismatch", f .. ": one byte added")
    expect(runh(req("")), "invalid", "digest-mismatch", f .. ": body removed (RFC 9530 6.3)")
end
expect(runh(dg('"content-digest"', { '"content-digest": sha-256=:AAAA:' }, { { "Content-Digest", S256 } }, HELLO)),
    "invalid", "bad-signature", "a changed digest field fails the signature, body or not")
H.pass("Content-, Repr- and Unencoded-Digest: pending in phase 1, verified only when the body matches")

expect(runh(cdb(S512, HELLO)), "verified", "", "RFC 9421 B.2 sha-512")
expect(runh(cdb(S256_LF, HELLO_LF)), "verified", "", "RFC 9530 B.4 sha-256")
expect(runh(cdb(RFC9530_2, HELLO_LF)), "verified", "",
    "RFC 9530 2's two-member example: sha-512 (the strongest) matches the body; its sha-256 does not")
expect(runh(cdb(S256 .. ", " .. "sha-512=:" .. ("A"):rep(86) .. "==:", HELLO)), "invalid", "digest-mismatch",
    "the strongest covered algorithm decides: a wrong sha-512 is not rescued by a right sha-256")
H.pass("RFC vectors verify; the strongest covered Active algorithm (sha-512, then sha-256) is the one checked")

-- ;key covers one member: an uncovered member is anyone's to add.
local evil = "evil"
local forged = "sha-512=:" .. b64.encode(H.sha512(evil)) .. ":"
local keyed = function(header, body)
    return dg('"content-digest";key="sha-256"', { '"content-digest";key="sha-256": :X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:' },
        { { "Content-Digest", header } }, body)
end
expect(runh(keyed(S256, HELLO)), "verified", "", ";key coverage of one member")
expect(runh(keyed(S256 .. ", " .. forged, evil)), "invalid", "digest-mismatch",
    "an added, uncovered sha-512 over a swapped body is never read")
H.pass(";key=: only the covered member counts; an appended member cannot vouch for a swapped body")

expect(runh(cdb("md5=:XrY7u+Ae7tCTyyK7j1rNww==:", HELLO)), "unverified", "digest-algorithm-unsupported",
    "Deprecated (RFC 9530 5: MUST NOT be used where an attacker may be present)")
expect(runh(cdb("sha-3=:AAAA:, unixsum=:AAAA:", HELLO)), "unverified", "digest-algorithm-unsupported", "unknown and Deprecated")
expect(runh(cd("sha-256=1")), "invalid", "malformed-digest", "the chosen member is not a Byte Sequence")
expect(runh(cd("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:,")), "invalid", "malformed-digest",
    "not a Dictionary: decided in phase 1, no body needed")
expect(run(cdb(S512, HELLO)), "unverified", "digest-algorithm-unsupported", "no SHA-512 provider: not silently skipped")
H.pass("Deprecated and unknown algorithms are ignored (unverified); malformed fields are invalid without the body")

expect(runh(cdb(S256, HELLO, false)), "unverified", "body-incomplete", "body cut at SecRequestBodyLimit")
expect(runh(cdb(S256, HELLO:sub(1, 5), false)), "unverified", "body-incomplete",
    "a truncated body is never compared, so a prefix cannot verify")
expect(runh(cdb(S256, HELLO), { max_sha256_body = #HELLO - 1 }), "unverified", "body-too-large", "RFC 9530 6.7 limit")
expect(runh(cdb(S256, HELLO), { max_sha256_body = #HELLO }), "verified", "", "at the limit")
expect(runh(cdb(S512, HELLO), { max_sha256_body = 1 }), "verified", "", "SHA-512 (C) is not limited by the SHA-256 cap")
expect(runh(cdb(S256 .. ", sha-512=:" .. ("A"):rep(86) .. "==:", HELLO), { max_sha256_body = 1 }), "invalid", "digest-mismatch",
    "a mismatch outranks a check skipped for size")
H.eq(verify.DEFAULT_POLICY.max_sha256_body, 131072, "default: 128 KiB, ~31 ms at the CRS image's measured 4.2 MB/s")
H.pass("incomplete and oversized bodies are unverified, never compared as if whole")

-- 14e (cont.) Partial content: RFC 9530 3 and RFC 9110 14.4, 14.5.
local rd = function(range, body, method, field, value)
    field, value = field or "repr-digest", value or S256
    local hs = { { field, value } }
    if range then hs[2] = { "Content-Range", range } end
    return dg('"' .. field .. '"', { '"' .. field .. '": ' .. value }, hs, body, nil, method)
end
expect(runh(rd("bytes 0-17/40", HELLO, "PUT")), "unverified", "digest-partial", "a partial PUT: the representation is not all here")
expect(runh(rd("bytes 0-17/40", nil, "PUT")), "unverified", "digest-partial", "nothing to compare: decided in phase 1")
expect(runh(rd("bytes 0-17/40", HELLO, "POST")), "verified", "",
    "RFC 9110 14.4: Content-Range on a method that does not define it MUST be ignored")
expect(runh(rd("bytes 0-17/40", HELLO, "PATCH")), "verified", "", "PATCH defines no Content-Range either")
expect(runh(rd("bytes 0-17/18", HELLO, "PUT")), "verified", "", "a PUT range that is the whole representation")
expect(runh(rd("BYTES 0-17/18", HELLO, "PUT")), "verified", "", "range units are case-insensitive (14.1)")
expect(runh(rd("bytes 0-39/40", HELLO, "PUT")), "unverified", "digest-partial", "claims all 40 bytes, carries 18: not the whole representation")
for _, range in ipairs({ "bytes 1-17/18", "bytes 0-17/*", "bytes */18", "items 0-17/18", "bytes  0-17/18",
                         "bytes 0-17/18, bytes 0-17/18", "bytes 0-17/99999999999999999999999", "bytes 0-17" }) do
    expect(runh(rd(range, HELLO, "PUT")), "unverified", "digest-partial", "PUT with Content-Range: " .. range)
end
expect(runh(rd("bytes 0-17/40", HELLO, "PUT", "unencoded-digest")), "unverified", "digest-partial",
    "Unencoded-Digest is over the whole representation too")
expect(runh(rd("bytes 0-17/40", HELLO, "PUT", "content-digest")), "verified", "",
    "Content-Digest is over the content, partial or not (RFC 9530 2)")
H.pass("Content-Range: ignored except on PUT; a PUT is checked only when its range is the whole representation")

-- 14e (cont.) Unencoded-Digest over a content-coded body: decoded first
-- (draft-ietf-httpbis-unencoded-digest-05 3, 5). Ground truth: the draft's
-- own Figure 2 (a gzip body with its Repr-Digest over the coded bytes and its
-- Unencoded-Digest over the decoded ones), RFC 9530's Figure 2 and B.1, and
-- zlib-made streams from coding/vectors.tsv.
local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end
local coding = require("wba.coding")
local UD_GZ = unhex("1f8b0800791f086400ff73cc5328cd4bad484e2d28c9cccf4bcc51282e29cacc4be702007eaf074418000000")
local UD_REPR = "sha-256=:kwcdt3RBGcsLaj7QSz9AW8MuwJaLjOJqUU/jKixF2oU=:"
local UD_U256 = "sha-256=:5Bv3NIx05BPnh0jMph6v1RJ5Q7kl9LKMtQxmvc9+Z7Y=:"
local UD_U512 = "sha-512=:WjyMuMD9EI/v0RoJchcevbo6lF498VyE9564OgXf+98iJptoSvb1Czo9uVJu2bVU/tOv90huiMG3+YaMX1kipw==:"
local HELLO_LF_U = "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:" -- RFC 9530 B.1
local function vector(name)
    for line in io.lines(H.here .. "coding/vectors.tsv") do
        local input = line:match("^" .. name:gsub("%-", "%%-") .. "\t[^\t]+\t(%x*)\t")
        if input then return unhex(input) end
    end
    error("no vector " .. name)
end
local ZLIB_HELLO = vector("zlib-hello-lf-zlib") -- node:zlib's deflate coding of {"hello": "world"} + LF
local decodes = 0
local real_decode = coding.decode
coding.decode = function(...) decodes = decodes + 1; return real_decode(...) end
local function gzip_of(data)
    local f = H.tmp("gz.in")
    H.write(f, data)
    assert(H.sh(("gzip -n -9 -c '%s' > '%s.gz'"):format(f, f)))
    return H.read(f .. ".gz")
end
--- A signature over Unencoded-Digest (and `also`, each { component, field, value }).
local function ud(ce, body, value, also, method)
    value = value or UD_U256
    local comps, lines, hs = '"unencoded-digest"', { '"unencoded-digest": ' .. value }, { { "Unencoded-Digest", value } }
    for _, a in ipairs(also or {}) do
        comps = comps .. " " .. a[1]
        lines[#lines + 1] = a[1] .. ": " .. a[3]
        hs[#hs + 1] = { a[2], a[3] }
    end
    if ce then hs[#hs + 1] = { "Content-Encoding", ce } end
    return dg(comps, lines, hs, body, nil, method)
end

expect(runh(ud("gzip")), "unverified", "digest-pending", "phase 1: pending, as for any digest")
expect(runh(ud("gzip", UD_GZ)), "verified", "", "the draft's Figure 2: gzip body, Unencoded-Digest sha-256")
expect(runh(ud("gzip", UD_GZ, UD_U512)), "verified", "", "and its sha-512 member")
expect(runh(ud("gzip", UD_GZ, UD_REPR .. ", " .. UD_U512)), "verified", "", "the strongest covered member decides")
expect(runh(ud("gzip", UD_GZ, UD_U256 .. ";future=1;x")), "verified", "", "draft 3: unknown Parameters MUST be ignored")
expect(runh(ud("gzip", UD_GZ, nil, { { '"repr-digest"', "Repr-Digest", UD_REPR } })), "verified", "",
    "Repr-Digest over the coded bytes and Unencoded-Digest over the decoded ones, both from the draft")
expect(runh(ud(nil, UD_GZ, nil, { { '"content-encoding"', "Content-Encoding", "gzip" } })), "verified", "",
    "Content-Encoding covered too (RFC 9530 6.3 advises it)")
for _, ce in ipairs({ "x-gzip", "GZIP", "identity, gzip", "gzip, identity", " , gzip ,", "gzip,,", "Identity,X-Gzip" }) do
    expect(runh(ud(ce, UD_GZ)), "verified", "", "Content-Encoding: " .. ce)
end
expect(runh(ud(nil, "An unexceptional string\n")), "verified", "", "no coding: the body is the representation")
expect(runh(ud("identity", "An unexceptional string\n")), "verified", "", "identity is no coding (RFC 9110 8.4)")
expect(runh(ud("", "An unexceptional string\n")), "verified", "", "an empty list is no coding")
expect(runh(ud("deflate", ZLIB_HELLO, HELLO_LF_U)), "verified", "", "deflate: the zlib format (RFC 9110 8.4.1.2)")
expect(runh(ud("deflate, gzip", gzip_of(ZLIB_HELLO), HELLO_LF_U)), "verified", "",
    "stacked: deflate applied first, so gzip removed first (RFC 9110 8.4)")
expect(runh(ud("gzip, deflate", gzip_of(ZLIB_HELLO), HELLO_LF_U)), "invalid", "bad-content-coding", "the wrong order")
H.pass("Unencoded-Digest: gzip, x-gzip, deflate and stacked codings are decoded and verify against the draft's and RFC's digests")

expect(runh(ud("gzip", "An unexceptional string\n")), "invalid", "bad-content-coding", "labelled gzip, not gzip")
expect(runh(ud("deflate", UD_GZ)), "invalid", "bad-content-coding", "gzip labelled deflate")
expect(runh(ud("gzip", UD_GZ:sub(1, -2))), "invalid", "bad-content-coding", "a truncated stream")
expect(runh(ud("gzip", UD_GZ .. "\0")), "invalid", "bad-content-coding", "a trailing byte (RFC 1952 2.2)")
expect(runh(ud("gzip", "")), "invalid", "bad-content-coding", "the body removed")
local wrong = UD_U256:gsub("5Bv3", "5Bv4")
expect(runh(ud("gzip", UD_GZ, wrong)), "invalid", "digest-mismatch", "decoded fine, wrong digest")
for _, ce in ipairs({ "br", "zstd", "compress", "x-compress", "aes128gcm", "gzip, br", "br, gzip", "gzip;q=1", "gzip x", '"gzip"' }) do
    expect(runh(ud(ce)), "unverified", "digest-coding-unsupported", "decided in phase 1: Content-Encoding: " .. ce)
end
local fdict = "\120\187" .. ("\0"):rep(4) .. ZLIB_HELLO:sub(3)
expect(runh(ud("deflate", fdict, HELLO_LF_U)), "invalid", "bad-content-coding",
    "a zlib preset dictionary: RFC 1950 2.3, the compressor must not set FDICT where none is defined")
-- A br body: {"hello": "world"} + LF as brotli 1.0.9 encodes it. (RFC 9530
-- B.4's Figure 18 bytes are not valid brotli, and its d435Qo... digest
-- matches neither: RFC erratum 8890, filed by a third party on 2026-04-25,
-- status Reported, says the figure's first two bytes are wrong.)
local BR = unhex("0F09807B2268656C6C6F223A2022776F726C64227D0A03")
local BR_REPR = "sha-256=:" .. b64.encode(require("wba.sha256").digest(BR)) .. ":"
expect(runh(ud("br", BR, HELLO_LF_U, { { '"repr-digest"', "Repr-Digest", BR_REPR } })), "unverified", "digest-coding-unsupported",
    "a br body: Repr-Digest checks, Unencoded-Digest cannot")
expect(runh(dg('"repr-digest"', { '"repr-digest": ' .. BR_REPR }, { { "Repr-Digest", BR_REPR }, { "Content-Encoding", "br" } }, BR)),
    "verified", "", "Repr-Digest alone over that br body: the coded bytes, no decoder needed")
H.pass("a body that is not its declared coding is invalid; br, zstd, compress and unknown codings are unverified")

-- Bounded: min(max_decoded_body, max_decode_ratio x body length) units.
H.eq(verify.DEFAULT_POLICY.max_decoded_body, 131072, "default: 128 KiB, ~40 ms at the image's worst 3.2 MB/s")
H.eq(verify.DEFAULT_POLICY.max_decode_ratio, 200, "default: Apache httpd mod_deflate's DeflateInflateRatioLimit")
local MB2 = ("\0"):rep(2 * 1048576)
local BOMB = gzip_of(MB2)
local BOMB_U = "sha-512=:" .. b64.encode(H.sha512(MB2)) .. ":"
expect(runh(ud("gzip", BOMB, BOMB_U)), "unverified", "body-too-large", "2 MiB of zeros in ~2 KB (ratio ~1000)")
expect(runh(ud("gzip", BOMB, BOMB_U), { max_decoded_body = 3 * 1048576, max_decode_ratio = 2000 }), "verified", "",
    "the same body verifies with both limits raised: the limit decided, nothing else")
expect(runh(ud("gzip", BOMB, BOMB_U), { max_decoded_body = 3 * 1048576 }), "unverified", "body-too-large",
    "under the ratio cap alone")
expect(runh(ud("gzip", BOMB, BOMB_U), { max_decode_ratio = 2000 }), "unverified", "body-too-large", "under the size cap alone")
expect(runh(ud("gzip, gzip", gzip_of(BOMB), BOMB_U)), "unverified", "body-too-large", "a stacked bomb")
local K200 = ("web-bot-auth "):rep(16000) -- 208 KB
local K200_GZ = gzip_of(K200)
local big = { max_decoded_body = 1048576, max_decode_ratio = 2000 }
expect(runh(ud("gzip", K200_GZ, "sha-256=:" .. b64.encode(require("wba.sha256").digest(K200)) .. ":"), big),
    "unverified", "body-too-large", "the SHA-256 cap applies to the decoded body")
expect(runh(ud("gzip", K200_GZ, "sha-512=:" .. b64.encode(H.sha512(K200)) .. ":"), big), "verified", "", "SHA-512 is not capped")
H.pass("decoding stops at max_decoded_body or max_decode_ratio x body length (unverified/body-too-large); the SHA-256 cap applies after decoding")

decodes = 0
expect(runh(ud("gzip", BOMB, BOMB_U, { { '"content-digest"', "Content-Digest", S256 } })), "invalid", "digest-mismatch",
    "a covered Content-Digest that fails the received bytes")
H.eq(decodes, 0, "so the body was never decoded (unencoded-digest draft 7)")
decodes = 0
local function two_ud()
    local params = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW - 10, NOW + 300, kid)
    local cs = { '"@authority" "unencoded-digest" "signature-agent";key="agent1"',
                 '"unencoded-digest" "@authority" "signature-agent";key="agent1"' }
    local lines = { '"@authority": example.com\n"unencoded-digest": ' .. UD_U256 .. '\n' .. AGENT_LINE_T,
                    '"unencoded-digest": ' .. UD_U256 .. '\n"@authority": example.com\n' .. AGENT_LINE_T }
    local ins, sgs = {}, {}
    for n, l in ipairs({ "a", "b" }) do
        ins[n] = l .. "=(" .. cs[n] .. ")" .. params
        sgs[n] = l .. "=:" .. b64.encode(H.sign(KEY, lines[n] .. '\n"@signature-params": (' .. cs[n] .. ")" .. params)) .. ":"
    end
    local req = H.request({ method = "POST", headers = { { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' },
        { "Unencoded-Digest", UD_U256 }, { "Content-Encoding", "gzip" },
        { "Signature-Input", table.concat(ins, ", ") }, { "Signature", table.concat(sgs, ", ") } } })
    req.body = function() return UD_GZ, true end
    return req
end
local r_two = runh(two_ud())
expect(r_two, "verified", "")
H.eq(#r_two.agents, 1)
H.eq(decodes, 1, "two signatures over Unencoded-Digest: one decode")
coding.decode = real_decode
H.pass("received bytes are checked before decoding; the body is decoded once per request")

-- Want-* fields (RFC 9530 4) are hints to a sender: the algorithm checked is
-- still the strongest covered Active one, whatever a request prefers.
expect(runh(cdb(S256 .. ", sha-512=:" .. ("A"):rep(86) .. "==:", HELLO, nil,
    { { "Want-Content-Digest", "sha-256=10, sha-512=1" }, { "Want-Repr-Digest", "sha-512=0" } })), "invalid", "digest-mismatch",
    "sha-512 still decides")
H.pass("Want-Content-Digest and Want-Repr-Digest change nothing in the check")

-- digest.lua's parsers, directly.
local digest = require("wba.digest")
local function req_with(hs, method) local r = H.request({ headers = hs, method = method }); return r end
local cc = digest.content_codings(req_with({ { "Content-Encoding", "deflate" }, { "content-encoding", "x-gzip, identity" } }))
H.eq(table.concat(cc, ","), "deflate,gzip", "two field lines combine (RFC 9110 5.3), identity left out")
H.eq(#digest.content_codings(req_with({})), 0)
H.eq(digest.partial(req_with({ { "Content-Range", "bytes 0-0/1" } }, "PUT")), false, "one byte, all of it")
H.eq(digest.partial(req_with({ { "Content-Range", "bytes 00-17/018" } }, "PUT")), false, "leading zeros are digits")
H.eq(digest.partial(req_with({ { "Content-Range", "bytes 0-0/0" } }, "PUT")), true, "complete-length must exceed last-pos")
H.eq(digest.partial(req_with({ { "Content-Range", "bytes 0-17/40" } }, "put")), false, "methods are case-sensitive: put is not PUT")
H.pass("content_codings and partial parse what RFC 9110 defines")

-- Ranking: a pending signature may still verify, so it outranks invalid.
local function two(digest_sig_good)
    local params = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW - 10, NOW + 300, kid)
    local ca = '"@authority" "content-digest" "signature-agent";key="agent1"'
    local base_a = '"@authority": example.com\n"content-digest": ' .. S256 .. '\n"signature-agent";key="agent1": "'
        .. H.AGENT .. '"\n"@signature-params": (' .. ca .. ")" .. params
    local sig_a = digest_sig_good and H.sign(KEY, base_a) or ("\0"):rep(64)
    local cb = '"@authority" "signature-agent";key="agent1"'
    return H.request({ method = "POST", headers = { { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' },
        { "Content-Digest", S256 },
        { "Signature-Input", "a=(" .. ca .. ")" .. params .. ", b=(" .. cb .. ")" .. params },
        { "Signature", "a=:" .. b64.encode(sig_a) .. ":, b=:" .. b64.encode(("\0"):rep(64)) .. ":" } } })
end
expect(runh(two(true)), "unverified", "digest-pending", "pending beats a second, bad signature")
local r2 = two(true)
r2.body = function() return HELLO, true end
expect(runh(r2), "verified", "", "and verifies once the body arrives")
expect(runh(two(false)), "invalid", "bad-signature", "two bad signatures")
H.pass("a pending signature outranks an invalid one, so phase 2 still runs for it")

body_reads = 0
runh(dg('"content-digest"', { '"content-digest": sha-256=:AAAA:' }, { { "Content-Digest", S256 } }, HELLO))
local bad = cdb(S256, HELLO)
bad.fields["signature"] = { "sig1=:" .. b64.encode(("\0"):rep(64)) .. ":" }
runh(bad)
H.eq(body_reads, 0, "the body is read only after a good signature")
runh(cdb(S256, HELLO))
H.eq(body_reads, 1)
H.pass("the body is read only for a good signature that covers a digest")

-- Each algorithm runs once per request, however many signatures cover a digest.
local hashed = 0
local counting = { ["sha-256"] = function(b) hashed = hashed + 1; return HASH["sha-256"](b) end, ["sha-512"] = H.sha512 }
local function twice()
    local params = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW - 10, NOW + 300, kid)
    local cs = { '"@authority" "content-digest" "signature-agent";key="agent1"',
                 '"content-digest" "@authority" "signature-agent";key="agent1"' }
    local lines = { '"@authority": example.com\n"content-digest": ' .. S256 .. '\n' .. AGENT_LINE_T,
                    '"content-digest": ' .. S256 .. '\n"@authority": example.com\n' .. AGENT_LINE_T }
    local ins, sgs = {}, {}
    for n, l in ipairs({ "a", "b" }) do
        ins[n] = l .. "=(" .. cs[n] .. ")" .. params
        sgs[n] = l .. "=:" .. b64.encode(H.sign(KEY, lines[n] .. '\n"@signature-params": (' .. cs[n] .. ")" .. params)) .. ":"
    end
    local req = H.request({ method = "POST", headers = { { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' },
        { "Content-Digest", S256 }, { "Signature-Input", table.concat(ins, ", ") }, { "Signature", table.concat(sgs, ", ") } } })
    req.body = function() return HELLO .. "!", true end
    return req
end
expect(run(twice(), { hash = counting }), "invalid", "digest-mismatch", "two good signatures over a swapped body")
H.eq(hashed, 1, "SHA-256 ran once for two signatures")
H.pass("body digests are computed once per request, not once per signature")

-- 14f. Cost scales with the request, not components x field size (found by
-- the third review: one request with hundreds of ;sf/;key/@query-param
-- components over an 8 KiB field cost 2.65 s before memoization). Both
-- dimensions grow together here, unlike the single-header cost probe.
local CP = ';created=1700000000;expires=1700000100;keyid="' .. ("A"):rep(43) .. '";tag="web-bot-auth"'
local function costly(items, extra_fields, query)
    local fields = { ["signature-input"] = { "sig1=(" .. table.concat(items, " ") .. ")" .. CP },
                     signature = { "sig1=:" .. ("A"):rep(86) .. "==:" } }
    for k, v in pairs(extra_fields or {}) do fields[k] = v end
    local req = { fields = fields, method = "GET", authority = "example.com", path = "/", query = query, scheme = "https" }
    local t0 = os.clock()
    local res = verify.verify(req, STORE, 1700000050, function() return false end)
    return os.clock() - t0, res
end
local dict = {}
for i = 1, 1200 do dict[#dict + 1] = "k" .. i .. "=1" end
local big_dict = table.concat(dict, ", "):sub(1, 8150):gsub(",[^,]*$", "")
local keys_items, qp_items, qparts = { '"@authority"', '"priority";sf' }, { '"@authority"' }, {}
for i = 1, 800 do keys_items[#keys_items + 1] = '"priority";key="k' .. i .. '"' end
for i = 1, 900 do qparts[#qparts + 1] = "p" .. i .. "=v" end
for i = 1, 600 do qp_items[#qp_items + 1] = '"@query-param";name="p' .. i .. '"' end
local cases = {
    { "800 ;key + ;sf over an 8 KiB Dictionary", keys_items, { priority = { big_dict } } },
    { "600 @query-param over a " .. #table.concat(qparts, "&") .. " B query", qp_items, nil, table.concat(qparts, "&") },
    { ";bs over 16000 inner spaces", { '"@authority"', '"x-h";bs' }, { ["x-h"] = { "a" .. (" "):rep(16000) .. "b" } } },
}
for _, c in ipairs(cases) do
    local secs, res = costly(c[2], c[3], c[4])
    H.eq(res.status ~= "verified", true, c[1])
    -- ~40x headroom over the measured 5-7 ms; the bugs this guards took 0.7-2.7 s.
    H.eq(secs < 0.25, true, ("%s took %.0f ms; budget 250 ms"):format(c[1], secs * 1000))
end
local dup_items = { '"@authority"' }
for _ = 1, 1000 do dup_items[#dup_items + 1] = '"priority";sf' end
local dsecs, dres = costly(dup_items, { priority = { big_dict } })
expect(dres, "invalid", "duplicate-component")
H.eq(dsecs < 0.25, true, "1000 repeated components must be refused before any value is derived")
expect(run(comp_case('"@authority" "x-a" "x-a" "x-missing"', { '"@authority": example.com', '"x-a": 1' },
    { headers = { { "x-a", "1" } } })), "invalid", "duplicate-component",
    "RFC 9421 2.5, item by item: the repeat is found before the later missing value is derived")
H.pass("hundreds of components over 8-16 KiB fields stay under 250 ms; repeats are refused before any value is derived")

-- 14h. Found by the RFC 9421 requirements audit: component identity.
local pd = { { "Priority", "u=3, i" } }
expect(run(comp_case('"@authority" "priority";key="u";sf "priority";sf;key="u"',
    { '"@authority": example.com', '"priority";key="u";sf: 3', '"priority";sf;key="u": 3' }, { headers = pd })),
    "invalid", "duplicate-component", "RFC 9421 2: parameter order is not significant")
expect(run(comp_case('"@authority" "priority";key="u" "priority";key="u";sf',
    { '"@authority": example.com', '"priority";key="u": 3', '"priority";key="u";sf: 3' }, { headers = pd })),
    "invalid", "duplicate-component", "RFC 9421 2.1.2: a Dictionary key is covered once")
expect(run(comp_case('"@authority" "priority";key="u" "priority";key="i"',
    { '"@authority": example.com', '"priority";key="u": 3', '"priority";key="i": ?1' }, { headers = pd })),
    "verified", "", "two different keys of one field")
expect(run(comp_case('"@authority" "priority" "priority";sf',
    { '"@authority": example.com', '"priority": u=3, i', '"priority";sf: u=3, i' }, { headers = pd })),
    "verified", "", "a field and its ;sf form are distinct (2: the parameters differ)")
local tab_req = comp_case('"@authority"', { '"@authority": exa\tmple.com' })
tab_req.authority = "exa\tmple.com"
expect(run(tab_req), "invalid", "bad-component-value", "RFC 9421 2.5 ABNF: no HTAB in a derived component")
expect(run(comp_case('"@authority" "x-a"', { '"@authority": example.com', '"x-a": a\tb' },
    { headers = { { "X-A", "a\tb" } } })), "verified", "", "HTAB inside a field value is field-content")
H.pass("identity ignores parameter order and a redundant ;sf; HTAB refused in derived values only")

-- 14g. Draft 4.3: no Signature-Agent header at all. The identifier is the
-- keyid thumbprint: a verifier that holds the key verifies, and attributes the
-- request to nothing beyond the key. Present but uncovered stays invalid.
local function absent(key)
    local req = signed({ key = key, components = '"@authority"', lines = { '"@authority": example.com' } })
    req.fields["signature-agent"] = nil
    return req
end
r = run(absent())
expect(r, "verified", "url-less", "header absent, key held under some directory (draft 4.3)")
H.eq(r.agent, nil, "no directory is named")
H.eq(r.keyid, KEY.keyid)
H.eq(#r.agents, 0)
expect(run(absent(KEY2)), "unverified", "agent-absent", "header absent, key not held")
expect(run(absent(), { store = { [H.AGENT_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw, exp = NOW } } } }),
    "unverified", "key-not-current")
expect(run(absent(), { store = { ["https://a.example" .. "/.well-known/http-message-signatures-directory"] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw, exp = NOW } },
    [H.AGENT_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } } } }), "verified", "url-less", "any current entry for the key")
local tampered = absent()
tampered.authority = "evil.example"
expect(run(tampered), "invalid", "bad-signature", "URL-less still needs a valid signature")
expect(run(signed({ components = '"@authority"', lines = { '"@authority": example.com' } })),
    "invalid", "agent-not-covered", "header present, member not signed (5.2.1)")
H.pass("absent Signature-Agent: URL-less verification by thumbprint (draft 4.3); present but unsigned is invalid (5.2.1)")

-- 14i. RFC 9421 4: a label in one field and not the other is an error, for
-- every label; and draft 5.2.2: every signature validated, every verified
-- directory reported.
local orphan_in = signed()
orphan_in.fields["signature-input"][1] = orphan_in.fields["signature-input"][1]
    .. ', other=("@authority");created=1;expires=2;keyid="k";tag="x"'
expect(run(orphan_in), "invalid", "orphan-label", "an unrelated Signature-Input label with no Signature member")
local orphan_sig = signed()
orphan_sig.fields["signature"][1] = orphan_sig.fields["signature"][1] .. ", other=:AAAA:"
expect(run(orphan_sig), "invalid", "orphan-label", "a Signature member with no Signature-Input label")
r = run(d2(), { store = { [H.AGENT_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } }, [BROWSER_ID] = { [KEY2.keyid] = { type = "ed25519", key = KEY2.raw } } } })
expect(r, "verified", "", "both D.2 signatures verify")
H.eq(r.agent, H.AGENT_ID, "the first verified in Signature-Input order")
H.eq(table.concat(r.agents, " "), H.AGENT_ID .. " " .. BROWSER_ID, "every verified directory, in order")
H.pass("orphan labels refused; every signature validated and every verified directory listed")

-- 14j. Validating every signature has a bounded cost: as many signatures as
-- 36 KiB of headers holds (nginx refuses more by default), each reaching the
-- crypto check with a held keyid, stays under the 250 ms budget.
local many_in, many_sig = {}, {}
local mp = p(';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"', NOW - 10, NOW + 300, kid)
for i = 1, 150 do
    many_in[i] = "s" .. i .. '=("@authority" "signature-agent";key="agent1")' .. mp
    many_sig[i] = "s" .. i .. "=:" .. b64.encode(("\1"):rep(64)) .. ":"
end
local many = H.request({ headers = { { "Signature-Agent", 'agent1="' .. H.AGENT .. '"' },
    { "Signature-Input", table.concat(many_in, ", ") }, { "Signature", table.concat(many_sig, ", ") } } })
local checks = 0
local t1 = os.clock()
expect(run(many, { crypto = function() checks = checks + 1; return false end }), "invalid", "bad-signature")
local msecs = os.clock() - t1
H.eq(checks, 150, "each of the 150 signatures reached the crypto check")
H.eq(msecs < 0.25, true, ("150 signatures took %.0f ms; budget 250 ms"):format(msecs * 1000))
H.pass(("150 signatures in %d bytes of headers, all validated, in %.0f ms"):format(
    #table.concat(many_in, ", ") + #table.concat(many_sig, ", "), msecs * 1000))

-- 14k. Facts for attribution logs, from the verified signature only; and the
-- operator's minimum coverage (README, Controls).
local function sha256_hex(raw) -- openssl, independent of sha256.lua
    local f = H.tmp("sig.bin")
    H.write(f, raw)
    local pipe = io.popen(("openssl dgst -sha256 -r '%s'"):format(f))
    local out = pipe:read("a")
    pipe:close()
    return out:match("^(%x+)")
end
local fact_sig = H.sign(KEY, '"@authority": example.com\n"signature-agent";key="agent1": "' .. H.AGENT .. '"\n'
    .. '"@signature-params": ("@authority" "signature-agent";key="agent1")'
    .. (';created=%d;expires=%d;keyid="%s";alg="ed25519";tag="web-bot-auth"'):format(NOW - 10, NOW + 300, KEY.keyid))
r = run(signed({ sig = fact_sig }))
expect(r, "verified", "")
H.eq(r.label, "sig1")
H.eq(r.created, NOW - 10)
H.eq(r.expires, NOW + 300)
H.eq(table.concat(r.covered, " "), "@authority signature-agent")
H.eq(r.sighash, sha256_hex(fact_sig), "sighash is SHA-256 of the signature bytes (openssl)")
local qp = signed({ components = '"@authority" "@query-param";name="a" "@query-param";name="b" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"@query-param";name="a": 1', '"@query-param";name="b": 2',
              '"signature-agent";key="agent1": "' .. H.AGENT .. '"' }, query = "a=1&b=2" })
r = run(qp)
expect(r, "verified", "")
H.eq(table.concat(r.covered, " "), "@authority @query-param signature-agent", "each name once, in signature order")
local ul_r = run(H.request({ headers = (function()
    local base = '"@authority": example.com\n"@signature-params": ("@authority")'
        .. (';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"'):format(NOW - 10, NOW + 300, KEY.keyid)
    return { { "Signature-Input", 'sig1=("@authority")' .. (';created=%d;expires=%d;keyid="%s";tag="web-bot-auth"')
                 :format(NOW - 10, NOW + 300, KEY.keyid) },
             { "Signature", "sig1=:" .. b64.encode(H.sign(KEY, base)) .. ":" } }
end)() }))
expect(ul_r, "verified", "url-less")
H.eq(ul_r.agent, nil)
H.eq(#ul_r.sighash, 64, "URL-less still identifies its signature")

local need_path = { require_components = { "@path" } }
expect(run(signed(), { policy = need_path }), "unverified", "insufficient-coverage", "@path required, not covered")
expect(run(signed({ components = '"@authority" "@path" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"@path": /', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } }),
    { policy = need_path }), "verified", "", "@path required and covered")
expect(run(signed({ components = '"@target-uri" "signature-agent";key="agent1"',
    lines = { '"@target-uri": https://example.com/', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } }),
    { policy = need_path }), "verified", "", "@target-uri holds the path: it meets a required @path, as for a grant")
expect(run(signed({ components = '"@target-uri" "signature-agent";key="agent1"',
    lines = { '"@target-uri": https://example.com/', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } }),
    { policy = { require_components = { "@method" } } }), "unverified", "insufficient-coverage", "but not a required @method")
expect(run(signed({ sig = ("\1"):rep(64) }), { policy = need_path }), "invalid", "bad-signature",
    "a forgery is reported as one, whatever the coverage policy")
local hashed = 0
local counting = { ["sha-256"] = function(s) hashed = hashed + 1; return require("wba.sha256").digest(s) end }
local dreq = signed({ components = '"@authority" "content-digest" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
              '"signature-agent";key="agent1": "' .. H.AGENT .. '"' },
    extra_headers = { { "Content-Digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:" } } })
dreq.body = function() return '{"hello": "world"}', true end
expect(run(dreq, { policy = need_path, hash = counting }), "unverified", "insufficient-coverage")
H.eq(hashed, 0, "a signature refused for coverage never makes the WAF hash the body")
H.pass("verified results carry label, window, covered names and sighash; coverage policy refuses after crypto, before hashing")

-- 15. Every algorithm of RFC 9421 3.3 that the draft allows (all but
-- hmac-sha256, draft 6.4). openssl signs each over a hand-written base and
-- verifies it (helpers.lua): verify.lua decides which algorithm, which
-- length and which key, and must hand the oracle exactly the right ones.
local V = require("rfc_vectors")
local P256, P384, RSA = H.new_key("p256"), H.new_key("p384"), H.new_key("rsa", 2048)
local RSA3072 = H.new_key("rsa", 3072)
local function entry(key, alg) -- a key-store entry, optionally pinned to the JWK's alg
    local ke = {}
    for f, v in pairs(key.entry) do ke[f] = v end
    ke.alg = alg
    return ke
end
local function held(key, alg) return { [H.AGENT_ID] = { [key.keyid] = entry(key, alg) } } end
local BASE_LINES = '"@authority": example.com\n"signature-agent";key="agent1": "' .. H.AGENT .. '"\n'
    .. '"@signature-params": ("@authority" "signature-agent";key="agent1")'
--- A request signed by openssl with `key` as `sign_alg`, whose parameters
--- declare `declared` (nil: no alg parameter); o.sig replaces the signature.
local function by(key, sign_alg, declared, o)
    o = o or {}
    local params = (';created=%d;expires=%d;keyid="%s"%s;tag="web-bot-auth"'):format(NOW - 10, NOW + 300, key.keyid,
        declared and (';alg="%s"'):format(declared) or "")
    return signed({ key = key, params = params, sig = o.sig or H.sign(key, BASE_LINES .. params, sign_alg, o) })
end
local seen_alg
local function spy(alg, ke, sig, msg) seen_alg = alg; return H.crypto_verify(alg, ke, sig, msg) end

-- 15a. Each verifies, with alg declared and, where the key determines it, without.
for _, c in ipairs({
    { KEY, "ed25519" }, { P256, "ecdsa-p256-sha256" }, { P384, "ecdsa-p384-sha384" },
    { RSA, "rsa-pss-sha512" }, { RSA, "rsa-v1_5-sha256" }, { RSA3072, "rsa-pss-sha512" }, { RSA3072, "rsa-v1_5-sha256" },
}) do
    local key, alg = c[1], c[2]
    r = run(by(key, alg, alg), { store = held(key), crypto = spy })
    expect(r, "verified", "", alg .. " with a " .. key.type .. " key, alg declared")
    H.eq(seen_alg, alg)
    H.eq(r.keyid, key.keyid)
    if key.type ~= "rsa" then
        seen_alg = nil
        expect(run(by(key, alg, nil), { store = held(key), crypto = spy }), "verified", "",
            alg .. ": no alg parameter, the key's type allows only this one (RFC 9421 3.2 step 6.3)")
        H.eq(seen_alg, alg)
    end
    expect(run(by(key, alg, alg), { store = held(key, alg) }), "verified", "", alg .. ": the key pinned to it too (6.5: they agree)")
    local tampered_req = by(key, alg, alg)
    tampered_req.authority = "evil.example"
    expect(run(tampered_req, { store = held(key) }), "invalid", "bad-signature", alg .. ": a changed @authority")
end
H.pass("ed25519, ecdsa-p256-sha256, ecdsa-p384-sha384, rsa-pss-sha512 and rsa-v1_5-sha256 (2048 and 3072 bits) verify, openssl-signed")

-- 15b. RSA: the key type allows two algorithms, so the key's own alg or the
-- signature's decides, and a pin cannot be downgraded (RFC 9421 7.3.6).
expect(run(by(RSA, "rsa-pss-sha512", nil), { store = held(RSA) }), "invalid", "alg-undetermined",
    "an RSA key with no alg, and no alg parameter: no algorithm is determined (3.2 step 6)")
seen_alg = nil
expect(run(by(RSA, "rsa-pss-sha512", nil), { store = held(RSA, "rsa-pss-sha512"), crypto = spy }), "verified", "",
    "the JWK's alg determines it (6.3)")
H.eq(seen_alg, "rsa-pss-sha512")
expect(run(by(RSA, "rsa-v1_5-sha256", nil), { store = held(RSA, "rsa-v1_5-sha256") }), "verified", "")
expect(run(by(RSA, "rsa-v1_5-sha256", "rsa-v1_5-sha256"), { store = held(RSA, "rsa-pss-sha512") }), "invalid", "alg-mismatch",
    "a key pinned to RSA-PSS refuses PKCS #1 v1.5 (6.5; 7.3.6 downgrade)")
expect(run(by(RSA, "rsa-pss-sha512", "rsa-pss-sha512"), { store = held(RSA, "rsa-v1_5-sha256") }), "invalid", "alg-mismatch")
expect(run(by(RSA, "rsa-v1_5-sha256", "rsa-pss-sha512"), { store = held(RSA) }), "invalid", "bad-signature",
    "a PKCS #1 v1.5 signature presented as RSA-PSS")
expect(run(by(RSA, "rsa-pss-sha512", "rsa-v1_5-sha256"), { store = held(RSA) }), "invalid", "bad-signature",
    "an RSA-PSS signature presented as PKCS #1 v1.5")
H.pass("RSA: alg from the key's pin or the signature, never guessed; a pin is never downgraded; PSS and v1.5 never confused")

-- 15c. Algorithm against key type (3.2 step 6.5 and step 8: the key material
-- must be appropriate for the algorithm).
local p256_sig = H.sign(P256, BASE_LINES .. "x")
expect(run(by(P256, nil, "ecdsa-p384-sha384", { sig = ("\1"):rep(96) }), { store = held(P256) }), "invalid", "alg-mismatch",
    "P-256 key, ecdsa-p384-sha384")
expect(run(by(P256, nil, "ed25519", { sig = p256_sig }), { store = held(P256) }), "invalid", "alg-mismatch", "P-256 key, ed25519")
expect(run(by(P384, nil, "ecdsa-p256-sha256", { sig = ("\1"):rep(64) }), { store = held(P384) }), "invalid", "alg-mismatch")
expect(run(by(RSA, nil, "ed25519", { sig = ("\1"):rep(64) }), { store = held(RSA) }), "invalid", "alg-mismatch", "RSA key, ed25519")
expect(run(by(RSA, nil, "ecdsa-p256-sha256", { sig = ("\1"):rep(64) }), { store = held(RSA) }), "invalid", "alg-mismatch")
expect(run(by(KEY, nil, "rsa-v1_5-sha256", { sig = ("\1"):rep(256) }), { store = held(KEY) }), "invalid", "alg-mismatch",
    "Ed25519 key, rsa-v1_5-sha256")
H.pass("an algorithm for another key type is refused before any crypto (alg-mismatch)")

-- 15d. Signature lengths: exact for each algorithm and key (RFC 9421 3.3.4,
-- 3.3.5, 3.3.6; RFC 8017 8.1.2 and 8.2.2 step 1 for RSA).
local function len_case(key, alg, declared, n, what)
    local calls = 0
    local counting = function(...) calls = calls + 1; return H.crypto_verify(...) end
    expect(run(by(key, alg, declared, { sig = ("\1"):rep(n) }), { store = held(key), crypto = counting }),
        "invalid", "bad-signature", what)
    H.eq(calls, 0, what .. ": never reaches the crypto")
end
for _, c in ipairs({ { P256, "ecdsa-p256-sha256", 63 }, { P256, "ecdsa-p256-sha256", 65 }, { P256, "ecdsa-p256-sha256", 96 },
                     { P384, "ecdsa-p384-sha384", 95 }, { P384, "ecdsa-p384-sha384", 97 }, { P384, "ecdsa-p384-sha384", 64 },
                     { KEY, "ed25519", 63 }, { KEY, "ed25519", 65 },
                     { RSA, "rsa-pss-sha512", 255 }, { RSA, "rsa-pss-sha512", 257 }, { RSA, "rsa-v1_5-sha256", 384 },
                     { RSA3072, "rsa-pss-sha512", 256 } }) do
    len_case(c[1], c[2], c[2], c[3], ("%s, %d bytes, alg declared"):format(c[2], c[3]))
    if c[1].type ~= "rsa" then len_case(c[1], c[2], nil, c[3], ("%s, %d bytes, no alg"):format(c[2], c[3])) end
end
H.pass("signatures of any other length are bad-signature and never reach the crypto: 64/96 bytes for ECDSA, 64 for Ed25519, k for RSA")

-- 15e. ECDSA signatures are r || s (3.3.4, 3.3.5). The DER encoding OpenSSL
-- produces is refused, whatever its length happens to be.
for _, key in ipairs({ P256, P384 }) do
    local alg = H.DEFAULT_ALG[key.type]
    for _, declared in ipairs({ alg, false }) do
        local params = (';created=%d;expires=%d;keyid="%s"%s;tag="web-bot-auth"'):format(NOW - 10, NOW + 300, key.keyid,
            declared and (';alg="%s"'):format(declared) or "")
        local der = H.sign(key, BASE_LINES .. params, alg, { der = true })
        local calls = 0
        local counting = function(...) calls = calls + 1; return H.crypto_verify(...) end
        expect(run(signed({ key = key, params = params, sig = der }), { store = held(key), crypto = counting }),
            "invalid", "bad-signature", alg .. ": DER-encoded (" .. #der .. " bytes)")
        H.eq(calls, 0)
        -- The same signature as r || s verifies: only the encoding was wrong.
        local raw = H.sign(key, BASE_LINES .. params, alg)
        expect(run(signed({ key = key, params = params, sig = raw }), { store = held(key) }), "verified", "")
    end
end
H.pass("a DER-encoded ECDSA signature is refused; the same key's r || s verifies")

-- 15f. RSA-PSS parameters: SHA-512, MGF1 with SHA-512, salt length exactly 64 (3.3.1).
for _, salt in ipairs({ 32, 0, 63 }) do
    expect(run(by(RSA, "rsa-pss-sha512", "rsa-pss-sha512", { saltlen = salt }), { store = held(RSA) }), "invalid", "bad-signature",
        "RSA-PSS signed with a " .. salt .. "-byte salt")
end
H.pass("RSA-PSS with a salt of 0, 32 or 63 bytes is refused (sLen is 64)")

-- 15g. RSA keys under 2048 bits never verify: the store holding one is refused
-- whole (keys.lua; RFC 7518 3.3, 3.5), so the request cannot reach crypto.
local small = H.new_key("rsa", 2047)
local small_store = keys.parse(keys.HEADER .. "\n" .. H.store_line(H.AGENT_ID, small) .. "\n")
H.eq(small_store, nil)
expect(run(by(small, "rsa-pss-sha512", "rsa-pss-sha512"), { store = function() return small_store end }),
    "unverified", "keystore-unavailable", "a 2047-bit key, openssl-signed")
local ok_store = assert(keys.parse(keys.HEADER .. "\n" .. H.store_line(H.AGENT_ID, RSA, "rsa-pss-sha512") .. "\n"
    .. H.store_line(H.AGENT_ID, P256) .. "\n" .. H.store_line(H.AGENT_ID, P384) .. "\n"))
expect(run(by(RSA, "rsa-pss-sha512", nil), { store = ok_store }), "verified", "", "an RSA key through keys.lua, pinned")
expect(run(by(P256, "ecdsa-p256-sha256", nil), { store = ok_store }), "verified", "", "P-256 through keys.lua")
expect(run(by(P384, "ecdsa-p384-sha384", "ecdsa-p384-sha384"), { store = ok_store }), "verified", "", "P-384 through keys.lua")
H.pass("a 2047-bit RSA key never verifies; RSA, P-256 and P-384 keys verify through keys.lua's store")

-- 15h. URL-less (draft 4.3) with a key listed under two directories: every
-- current entry must allow the algorithm, so a pin is never bypassed.
local function url_less(key, sign_alg, declared)
    local params = (';created=%d;expires=%d;keyid="%s"%s;tag="web-bot-auth"'):format(NOW - 10, NOW + 300, key.keyid,
        declared and (';alg="%s"'):format(declared) or "")
    local req = signed({ key = key, params = params, components = '"@authority"', lines = { '"@authority": example.com' },
        sig = H.sign(key, '"@authority": example.com\n"@signature-params": ("@authority")' .. params, sign_alg) })
    req.fields["signature-agent"] = nil
    return req
end
local two = { [H.AGENT_ID] = { [RSA.keyid] = entry(RSA) }, [VICTIM_ID] = { [RSA.keyid] = entry(RSA, "rsa-pss-sha512") } }
expect(run(url_less(RSA, "rsa-pss-sha512", "rsa-pss-sha512"), { store = two }), "verified", "url-less")
expect(run(url_less(RSA, "rsa-v1_5-sha256", "rsa-v1_5-sha256"), { store = two }), "invalid", "alg-mismatch",
    "one directory pins the key to RSA-PSS")
expect(run(url_less(RSA, "rsa-pss-sha512", nil), { store = two }), "invalid", "alg-undetermined",
    "one directory leaves the algorithm open")
local split = { [H.AGENT_ID] = { [RSA.keyid] = entry(RSA, "rsa-v1_5-sha256") }, [VICTIM_ID] = { [RSA.keyid] = entry(RSA, "rsa-pss-sha512") } }
for _, a in ipairs({ "rsa-v1_5-sha256", "rsa-pss-sha512" }) do
    expect(run(url_less(RSA, a, nil), { store = split }), "invalid", "alg-mismatch",
        "two directories pin the key to different algorithms; signed " .. a)
end
expect(run(url_less(P256, "ecdsa-p256-sha256", nil), { store = held(P256) }), "verified", "url-less")
H.pass("URL-less: the algorithm must be the same under every directory that lists the key")

-- 15i. The draft's own rsa-pss-sha512 vectors (E.1), and the RFC 9421 test
-- keys refused by default (draft 6.8).
local E1_STORE = { [V.E1_DIRECTORY] = { [V.RSA_PSS_KEYID] = V.RSA_PSS_KEY } }
for n, v in ipairs(V.E1) do
    local req = H.request({ headers = { { "Signature-Agent", v.agent }, { "Signature-Input", v.input }, { "Signature", v.sig } } })
    local pol = { reject_test_keys = false }
    if n == 1 then pol.max_window = false end -- E.1.1's expires is 100 years out, like E.2.1's
    expect(run(req, { store = E1_STORE, now = 1735689700, policy = pol }), "verified", "", v.name)
    expect(run(req, { store = E1_STORE, now = 1735689700, policy = { max_window = false } }), "invalid", "test-key",
        v.name .. " under the default policy: RFC 9421 B.1.2 is a test key")
end
for _, t in ipairs({ "BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo", "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA",
                     "ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI", "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" }) do
    H.eq(verify.TEST_KEY_THUMBPRINTS[t], true, t)
end
H.pass("draft E.1.1 and E.1.2 (rsa-pss-sha512) verify; RFC 9421 B.1.1-B.1.3 and the JOSE example keys are test keys")
-- 14l. Draft 5.5: jwks_uri and cimd members. Each is its own identifier,
-- the member value in normal form with query and fragment discarded, looked
-- up in the store key-sync filled from the operator's list (5.4: keyed on
-- the (URL, key) pair).
local WK = "/.well-known/http-message-signatures-directory"
local JWKS, CIMD = "https://agent.example/keys/jwks.json", "https://agent.example/card"
local typed = { [JWKS] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } }, [CIMD] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } } }
r = run(agent_case('"' .. JWKS .. '";type=jwks_uri'), { store = typed })
expect(r, "verified", "", "type=jwks_uri")
H.eq(r.agent, JWKS)
r = run(agent_case('"' .. CIMD .. '";type=cimd'), { store = typed })
expect(r, "verified", "", "type=cimd")
H.eq(r.agent, CIMD)
for _, spelled in ipairs({ JWKS .. "?v=7", JWKS .. "#k", "HTTPS://Agent.Example:443/keys/./x/../jwks.json",
    "https://agent.example/%6Beys/jwks.json", "https://agent.example:/keys/jwks.json" }) do
    r = run(agent_case('"' .. spelled .. '";type=jwks_uri'), { store = typed })
    expect(r, "verified", "", spelled)
    H.eq(r.agent, JWKS, "one identifier for every spelling (5.5: query and fragment dropped; RFC 3986 6.2.2, 6.2.3)")
end
expect(run(agent_case('"' .. JWKS .. '";type=jwks_uri'), { store = { [CIMD] = typed[CIMD] } }), "unverified", "unknown-agent",
    "a key held for another URL never counts (5.4)")
expect(run(agent_case('"https://agent.example"'), { store = typed }), "unverified", "unknown-agent",
    "a directory member is the well-known URI, not a listed jwks_uri on the same origin")
r = run(agent_case('"' .. H.AGENT_ID .. '";type=jwks_uri'))
expect(r, "verified", "", "a jwks_uri naming a directory's well-known URI is that same identifier")
H.eq(r.agent, H.AGENT_ID)
for _, bad in ipairs({ '"https://user@agent.example/k";type=jwks_uri', '"https://agent.example/a b";type=cimd',
    '"https://agent.example/a%zz";type=jwks_uri', '"https://agent.example:08443/k";type=jwks_uri' }) do
    expect(run(agent_case(bad), { store = typed }), "unverified", "bad-agent-url", bad)
end
expect(run(agent_case('"http://agent.example/k";type=jwks_uri'), { store = typed }), "invalid", "agent-not-https")
-- Normalizing runs on the client's value before any key is looked up, so it
-- must be linear: 8 KiB of dot segments and percent-encodings.
for _, path in ipairs({ ("/./.."):rep(1600), ("/a%41"):rep(1600), ("/a"):rep(4000) .. ("/.."):rep(2600) }) do
    local req = agent_case('"https://agent.example' .. path .. '";type=jwks_uri')
    local t2 = os.clock()
    expect(run(req, { store = typed }), "unverified", "unknown-agent")
    local s2 = os.clock() - t2
    H.eq(s2 < 0.25, true, ("an %d-byte jwks_uri path took %.0f ms; budget 250 ms"):format(#path, s2 * 1000))
end
H.pass("jwks_uri and cimd members verify against their own identifiers, in every spelling of them; others ignored")

-- 14m. IPv6 literal agent hosts: RFC 5952 canonical text in the identifier.
local V6 = "https://[2001:db8::1]:8443"
local v6_store = { [V6 .. WK] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } }, [V6 .. "/k"] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw } } }
for _, member in ipairs({ V6, "https://[2001:db8:0:0:0:0:0:1]:8443", "https://[2001:0db8::0001]:8443/" }) do
    r = run(agent_case('"' .. member .. '"'), { store = v6_store })
    expect(r, "verified", "", member)
    H.eq(r.agent, V6 .. WK)
end
expect(run(agent_case('"https://[2001:DB8::1]:8443"'), { store = v6_store }), "unverified", "bad-agent-url",
    "an origin's serialization is lowercase (RFC 6454 6.2)")
expect(run(agent_case('"https://[2001:db8::1]:443"'), { store = v6_store }), "unverified", "bad-agent-url",
    "an explicit default port is not an origin's serialization")
expect(run(agent_case('"https://[fe80::1%25en0]:8443"'), { store = v6_store }), "unverified", "bad-agent-url", "zone id")
r = run(agent_case('"https://[2001:DB8:0::1]:8443/k";type=jwks_uri'), { store = v6_store })
expect(r, "verified", "", "jwks_uri on an IPv6 literal: case-normalized")
H.eq(r.agent, V6 .. "/k")
H.pass("IPv6 literal hosts verify under one canonical identifier; uppercase, :443 and zone ids in an origin are ignored")

-- 14n. Draft Appendix B: the proof fact comes from the store, for the key
-- that verified, and only while the proof's own expires has not passed.
local function proof_run(entry)
    entry.type, entry.key = "ed25519", KEY.raw
    return run(signed(), { store = { [H.AGENT_ID] = { [KEY.keyid] = entry } } })
end
H.eq(proof_run({ proof = "valid", proof_exp = NOW + 1 }).proof, "valid")
H.eq(proof_run({ proof = "valid", proof_exp = NOW }).proof, "expired", "5.5.3: valid only until expires")
H.eq(proof_run({ proof = "invalid" }).proof, "invalid")
H.eq(proof_run({ proof = "none" }).proof, "none")
H.eq(proof_run({}).proof, "none", "an entry without proof fields")
r = run(absent(), { store = { [H.AGENT_ID] = { [KEY.keyid] = { type = "ed25519", key = KEY.raw, proof = "valid", proof_exp = NOW + 1 } } } })
expect(r, "verified", "url-less")
H.eq(r.proof, nil, "URL-less: no directory, so no directory proof")
H.pass("proof fact: valid, expired, invalid or none for the verifying key; absent when URL-less")

-- 14. Identity is only ever returned with "verified" (draft 4.1: no policy on unresolved URLs)
for _, nv in ipairs(not_verified) do
    local what = " leaked on " .. nv.status .. "/" .. nv.reason
    H.eq(nv.agent, nil, "agent" .. what)
    H.eq(nv.keyid, nil, "keyid" .. what)
    for _, f in ipairs({ "label", "created", "expires", "covered", "sighash", "proof" }) do H.eq(nv[f], nil, f .. what) end
end
H.pass(#not_verified .. " non-verified results carry no agent, proof, keyid, label, window, covered names or sighash")

-- 16. RFC 9651 4.2's MAY, taken with policy.strict_field_lines: a field
-- whose combined value parses, sent as lines one of which does not parse
-- alone, fails; split cleanly, it still verifies. Default: lines combined.
local STRICT = { strict_field_lines = true }
local function split_at(full, at) -- two lines that join with ", " into full
    local i = assert(full:find(at, 1, true))
    return { full:sub(1, i - 1), full:sub(i + 2) }
end
local nparams = (';created=%d;expires=%d;keyid="%s";alg="ed25519";nonce="a, b";tag="web-bot-auth"'):format(NOW - 10, NOW + 300, KEY.keyid)
local req16 = signed({ params = nparams })
req16.fields["signature-input"] = split_at(req16.fields["signature-input"][1], ', b"')
expect(run(req16), "verified", "", "Signature-Input split inside a String: combined, it verifies")
expect(run(req16, { policy = STRICT }), "not-signed", "unparsable-field", "strict: a line alone does not parse, so the field is ignored")
local agent_split = signed()
agent_split.fields["signature-agent"] = { 'agent1="' .. H.AGENT .. '"', 'agent9="https://x', 'y"' }
expect(run(agent_split), "verified", "")
expect(run(agent_split, { policy = STRICT }), "not-signed", "unparsable-field", "strict: Signature-Agent too")
local agent_clean = signed()
agent_clean.fields["signature-agent"] = { 'agent1="' .. H.AGENT .. '"', 'agent9="https://other.example"' }
expect(run(agent_clean, { policy = STRICT }), "verified", "", "strict: lines that each parse are fine")
local CD = 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:;x="a, b"'
local cd_req = signed({ components = '"@authority" "content-digest" "signature-agent";key="agent1"',
    lines = { '"@authority": example.com', '"content-digest": ' .. CD, '"signature-agent";key="agent1": "' .. H.AGENT .. '"' },
    extra_headers = { { "Content-Digest", 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:;x="a' }, { "Content-Digest", 'b"' } } })
expect(run(cd_req), "unverified", "digest-pending", "a covered Content-Digest split inside a String: combined, it is checked")
expect(run(cd_req, { policy = STRICT }), "invalid", "malformed-digest", "strict: a covered digest's line alone does not parse")
H.pass("RFC 9651 4.2 MAY as policy.strict_field_lines: Signature-Input, Signature-Agent and covered digests fail per line; clean splits still verify")

-- 17. Decided 2026-10-09 (independent review F1-F3): the site's own
-- names, RFC 9651 4.2's ignore branch by default, max age, strict expiry.
local SITE = { authorities = { ["example.com"] = true } }
expect(run(signed(), { policy = SITE }), "verified", "", "a signature for this site's name")
local foreign = signed({ authority = "other.example", -- a signature made for another site, replayed here with its Host
    lines = { '"@authority": other.example', '"signature-agent";key="agent1": "' .. H.AGENT .. '"' } })
expect(run(foreign), "verified", "", "library default (authorities nil): not checked")
expect(run(foreign, { policy = SITE }), "invalid", "foreign-authority", "cross-site replay refused")
expect(run(signed(), { policy = { authorities = false } }), "unverified", "no-site-names", "no names configured: nothing verifies")
expect(run(H.request({ headers = { { "Signature-Input", "x=(" }, { "Signature", "x=:AAAA:" } } }), { policy = SITE }),
    "not-signed", "unparsable-field", "the site check never turns an ignored field into a refusal")
local cavage = H.request({ method = "POST", path = "/inbox", headers = { { "Signature",
    'keyId="https://social.example/users/a#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="AAAA"' } } })
expect(run(cavage), "not-signed", "unparsable-field", "a draft-cavage Signature header (ActivityPub) is not an RFC 9421 signature")
expect(run(cavage, { policy = REJECT }), "invalid", "malformed-headers", "reject: the operator chose RFC 9651 4.2's malformed branch")
local bad_agent = signed()
bad_agent.fields["signature-agent"] = { 'agent1="https://x' }
expect(run(bad_agent), "invalid", "missing-component", "a ;key member of an unparsable Signature-Agent cannot be derived (RFC 9421 2.1.2)")
local whole = signed({ components = '"@authority" "signature-agent"', agent_header = 'agent1="https://x',
    lines = { '"@authority": example.com', '"signature-agent": agent1="https://x' } })
expect(run(whole), "invalid", "unparsable-agent", "an unparsable Signature-Agent covered whole: invalid, never a 400 by default")
expect(run(whole, { policy = REJECT }), "invalid", "malformed-headers", "reject: malformed, so 400")
H.pass("site names: own name verified, another site's refused, none configured unverified; draft-cavage and unparsable fields ignored by default, 400 only by choice")

-- 18. A replay counter lives until the last second its signature can verify,
-- so the store holds at most max_age of traffic (review finding: inodes).
local function last_of(o, policy)
    local pol = { replay_keys = true }
    for k, v in pairs(policy or {}) do pol[k] = v end
    local res = run(signed(o), { policy = pol })
    expect(res, "verified", "")
    return res.replay[1].last
end
local long = { expires = NOW + 7200 }
H.eq(last_of(long), NOW - 10 + 3600, "created + max_age, when sooner than expires")
H.eq(last_of({}), NOW + 300, "expires, when sooner")
H.eq(last_of({}, GRACE), NOW + 360, "expires plus the grace the operator chose")
H.eq(last_of(long, { max_age = false }), NOW + 7200, "max_age off: expires")
H.pass("replay counters named by the last second a signature over the base can verify")

H.done("test_verify")
