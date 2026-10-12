-- test_negative_vectors.lua: verify.lua against the 17 draft-00 negative
-- vectors (negative-vectors/, pinned and hashed; see its README).
--
-- Hard requirement: no vector verifies. Each outcome must equal the vector's
-- expected.outcome (draft Appendix C.1), except where DISPOSITIONS records a
-- different outcome together with the draft or RFC text behind it. A
-- disposition pins our exact outcome, so any change fails the suite too.
-- Run: lua lua/tests/test_negative_vectors.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local json = require("json")
local b64 = require("wba.base64")
local keys = require("wba.keys")
local components = require("wba.components")
local verify = require("wba.verify")
local sf = require("wba.structured_fields")
local sha256 = require("wba.sha256")

local FILE = H.here .. "negative-vectors/web-bot-auth-negative-vectors.json"
local SHA256 = "175b26a13309f90ed654ae1e80c862ddd6e74f1bf992bdf2cdd58bdeaf4f4be4"

local DISPOSITIONS = {
    -- RFC 9651 4.2 allows two answers to an unparsable field: ignore it, or
    -- treat the message as malformed. The vector proposes the second; this
    -- verifier takes the first by default (operator decision 2026-10-09, so a
    -- draft-cavage Signature header from ActivityPub is not refused), and the
    -- second with tx.wba_malformed=reject, checked below.
    ["NV-10"] = { outcome = "not-signed/unparsable-field",
        why = "RFC 9651 4.2 ignore branch by default; malformed=reject gives the vector's invalid/malformed-headers" },
}

-- The vectors' proposed reasons, in this verifier's vocabulary. A vector that
-- reaches the right outcome for a different reason fails: rejecting
-- everything is not conformance.
local REASONS = {
    ["target-not-covered"] = "authority-not-covered",
    ["missing-fields"] = "missing-param",
    ["expired"] = "expired",
    ["clock-ahead"] = "not-yet-valid",
    ["bad-signature"] = "bad-signature",
    ["canonicalization-mismatch"] = "bad-signature",  -- the base differs; only the signature can tell
    ["missing-component"] = "missing-component",
    ["signature-input-unreadable"] = "malformed-headers",
    ["signature-value-unreadable"] = "orphan-label",  -- no Signature member for the label (RFC 9421 4)
    ["duplicate-component"] = "duplicate-component",
    ["content-digest-mismatch"] = "digest-mismatch",  -- RFC 9530, checked in phase 2 (digest.lua)
    ["signature-agent-absent"] = "agent-absent",  -- draft 4.3: URL-less attribution, not implemented
    ["signature-agent-ambiguous-member"] = "agent-not-covered",
    ["signature-agent-member-missing"] = "missing-component",  -- RFC 9421 2.5: the covered member cannot be resolved
    ["signature-agent-not-https"] = "agent-not-https",
    ["signature-agent-not-origin"] = "bad-agent-url",
    ["signature-agent-unparsable"] = "missing-component",  -- the covered ;key member cannot be resolved
}

local p = io.popen("openssl dgst -sha256 -r '" .. FILE .. "'")
H.eq(p:read("a"):match("^([0-9a-f]+)"), SHA256, "negative vectors differ from the pinned file")
p:close()
local doc = json.decode(H.read(FILE))
H.eq(doc.document, "draft-ietf-webbotauth-httpsig-protocol-00")
H.pass("vector file is the pinned one (SHA-256), for draft-00")

local function b64url(s)
    s = s:gsub("-", "+"):gsub("_", "/")
    return assert(b64.decode(s .. string.rep("=", (4 - #s % 4) % 4)))
end

--- The request as modsecurity_entry.lua builds it for this URL in phase 2,
--- when the body is available too (the final outcome).
local function build(vec)
    local scheme, rest = vec.request.url:match("^([A-Za-z]+)://(.*)$")
    local authority = rest:match("^[^/?#]*")
    local tail = rest:sub(#authority + 1):match("^[^#]*")
    local path, query = tail, nil
    local q = tail:find("?", 1, true)
    if q then path, query = tail:sub(1, q - 1), tail:sub(q + 1) end
    authority = components.ascii_lower(authority):gsub(":443$", "")
    local fields = {}
    for name, value in pairs(vec.request.headers) do
        fields[components.ascii_lower(name)] = { value }
    end
    local body = vec.request.body or ""
    return { fields = fields, method = vec.request.method, authority = authority,
             path = path == "" and "/" or path, query = query, scheme = scheme,
             body = function() return body, true end }
end

--- The verifier holds the vector's key for every https agent the request names.
local function store_for(vec, req)
    local raw = b64url(vec.key.jwk.x)
    local store = {}
    local agents = req.fields["signature-agent"] and req.fields["signature-agent"][1]
    if agents then
        local ok, dict, order = pcall(sf.parse_dictionary, agents)
        local urls = {}
        if ok then
            for _, k in ipairs(order) do
                if dict[k].kind == "item" and dict[k].value.type == "string" then urls[#urls + 1] = dict[k].value.value end
            end
        else
            local iok, item = pcall(sf.parse_item, agents)
            if iok and item.value.type == "string" then urls[1] = item.value.value end
        end
        for _, u in ipairs(urls) do
            local id = keys.identifier(u)
            if id then store[id] = { [vec.key.keyid] = { type = "ed25519", key = raw } } end
        end
    end
    return store
end

local rows, failures = {}, {}
for _, group in ipairs(doc.testGroups) do
    for _, vec in ipairs(group.tests) do
        local req = build(vec)
        local r = verify.verify(req, store_for(vec, req), vec.now, H.crypto_verify,
            { reject_test_keys = false, max_window = false }, -- the draft's E.2 parameters: test key, 100-year window
            { ["sha-256"] = sha256.digest, ["sha-512"] = H.sha512 })
        local ours = r.status .. "/" .. r.reason
        local want = vec.expected.outcome
        local disp = DISPOSITIONS[vec.id]
        local verdict
        if r.status == "verified" or r.agent or r.keyid then
            verdict = "FAIL: verified"
        elseif disp then
            verdict = (ours == disp.outcome) and "dispositioned" or ("FAIL: disposition expects " .. disp.outcome)
        else
            local want_reason = REASONS[vec.expected.reason]
            if r.status ~= want then
                verdict = "FAIL: want " .. want
            elseif r.reason ~= want_reason then
                verdict = "FAIL: right outcome, wrong reason (want " .. tostring(want_reason) .. ")"
            else
                verdict = "match"
            end
        end
        rows[#rows + 1] = ("%-6s %-10s %-32s %-40s %s"):format(vec.id, want, vec.expected.reason, ours, verdict)
        if verdict:sub(1, 4) == "FAIL" then failures[#failures + 1] = vec.id end
        if disp then rows[#rows + 1] = "       " .. disp.why end
    end
end

print(("%-6s %-10s %-32s %-40s %s"):format("vector", "expected", "proposed reason", "ours", "result"))
for _, row in ipairs(rows) do print(row) end
H.eq(#failures, 0, "negative vectors failed: " .. table.concat(failures, ", "))
for _, group in ipairs(doc.testGroups) do
    for _, vec in ipairs(group.tests) do
        if vec.id == "NV-10" then
            local req = build(vec)
            local r = verify.verify(req, store_for(vec, req), vec.now, H.crypto_verify,
                { reject_test_keys = false, max_window = false, malformed = "reject" },
                { ["sha-256"] = sha256.digest, ["sha-512"] = H.sha512 })
            H.eq(r.status .. "/" .. r.reason, "invalid/malformed-headers", "NV-10 with malformed=reject: the vector's own outcome")
        end
    end
end
local dispositioned = 0
for _ in pairs(DISPOSITIONS) do dispositioned = dispositioned + 1 end
H.pass(("17 negative vectors: none verifies; %d match the draft's outcome for the intended reason, %d dispositioned")
    :format(17 - dispositioned, dispositioned))
H.done("test_negative_vectors")
