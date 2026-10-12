--[[
digest.lua: RFC 9530 integrity fields, checked against the request body.

RFC 9421 7.2.8: a signature over Content-Digest says nothing about the body
until the verifier also checks that digest against the content received.
This module makes that check for every digest field a signature covers:

  content-digest    RFC 9530 2: the content as received.
  repr-digest       RFC 9530 3: the whole selected representation data, in
                    its content coding (RFC 9110 8.4: "the representation is
                    defined in terms of the coded form"). A request's content
                    is all of it unless the request is a partial PUT (below),
                    so: the same bytes, never decoded.
  unencoded-digest  draft-ietf-httpbis-unencoded-digest-05 3 (IANA:
                    permanent): the representation with no content coding.
                    The body is decoded per Content-Encoding, last coding
                    applied first (draft 5), by coding.lua: gzip (x-gzip)
                    and deflate. Any other coding is digest-coding-unsupported.

Partial content (RFC 9530 3; RFC 9110 14.4, 14.5). Content-Range in a
request means something only for a method that defines it, and only PUT
does (partial PUT); on any other method "a server MUST ignore" it, so the
content is the whole representation. On a PUT the content is the whole
representation only when the range is "bytes 0-(n-1)/n"; any other range,
an unknown length (*), another unit or an unparsable value leaves
Repr-Digest and Unencoded-Digest uncheckable: digest-partial.

Which members count: only those the signature covers. A bare, ;sf or ;bs
component covers the whole field; ;key="..." covers one member. An uncovered
member can be added by anyone on the path, so it is never read.

Which algorithm: RFC 9530 5 allows only "Active" algorithms where an attacker
may be present (IANA, 2026: sha-256 and sha-512). Deprecated ones (md5, sha,
unixsum, unixcksum, adler, crc32c) and unknown keys are ignored. Of the
covered Active members, the strongest one is checked. Skipping a weaker one
cannot be exploited (RFC 9530 6.6, 6.7): a forger would need a SHA-512
collision. Want-Content-Digest, Want-Repr-Digest and Want-Unencoded-Digest
are hints to a sender (RFC 9530 4) and change nothing here.

Order: the received bytes are checked (Content-Digest, Repr-Digest) before
anything is decoded, so a body that fails them never reaches the decoder
(unencoded-digest draft 7: "validation of the received bytes before further
processing").

Cost: SHA-512 runs in C (OpenSSL via lua-openssl, ~1.4 GB/s in the CRS image), so it is
bounded only by SecRequestBodyLimit. SHA-256 runs in Lua (sha256.lua, ~4 MB/s
on the same image's Lua 5.3), so a body larger than policy.max_sha256_body is
not hashed with it (RFC 9530 6.7); for Unencoded-Digest that is the decoded
body. Decoding runs in Lua (~3.2 MB/s at worst) within a budget of
min(max_decoded_body, max_decode_ratio x body length) units (coding.lua:
each decoded byte, plus a charge per deflate block); past it, body-too-large.
Each algorithm runs at most once per request on each of the two inputs, and
decoding at most once, however many signatures cover a digest.

Outcomes (C.1 of the Web Bot Auth draft):
  invalid     malformed-digest, digest-mismatch, bad-content-coding (the body
              is not valid data in its declared coding): a check failed
  unverified  digest-algorithm-unsupported, digest-coding-unsupported,
              digest-partial, body-incomplete, body-too-large: the check
              cannot be made
--]]

local sf = require("wba.structured_fields")
local components = require("wba.components")
local coding = require("wba.coding")

local M = {}

M.FIELDS = { ["content-digest"] = true, ["repr-digest"] = true, ["unencoded-digest"] = true }
local ORDER = { "content-digest", "repr-digest", "unencoded-digest" }
M.PREFERENCE = { "sha-512", "sha-256" } -- IANA "Active", strongest first

local TOKEN = "^[!#$%%&'*+%-.^_`|~0-9A-Za-z]+$" -- RFC 9110 5.6.2

--- The digest fields a signature covers, or nil:
--- { [field] = true (whole field) | { [member key] = true } }.
function M.covered(covered)
    local fields
    for _, c in ipairs(covered) do
        local name = c.item.value.value
        if M.FIELDS[name] then
            fields = fields or {}
            local k = sf.param(c.item.params, "key") -- a String: components.value() checked
            if k == nil then
                fields[name] = true
            elseif fields[name] ~= true then
                fields[name] = fields[name] or {}
                fields[name][k.value] = true
            end
        end
    end
    return fields
end

--- RFC 9110 8.4: the content codings applied, in the order applied, with
--- identity (no transformation) left out; or nil, reason when one cannot be
--- decoded here.
function M.content_codings(req)
    local value = components.field_value(req, "content-encoding")
    local list = {}
    if value == nil then return list end
    for raw in (value .. ","):gmatch("([^,]*),") do
        local c = components.trim_ows(raw)
        if c ~= "" then -- RFC 9110 5.6.1.2: empty list elements are ignored
            if not c:match(TOKEN) then return nil, "digest-coding-unsupported" end
            c = components.ascii_lower(c)           -- 8.4.1: case-insensitive
            if c == "x-gzip" then c = "gzip" end     -- 8.4.1.3
            if c ~= "identity" then
                if not coding.DECODERS[c] then return nil, "digest-coding-unsupported" end
                list[#list + 1] = c
            end
        end
    end
    return list
end

--- Whether the request's content may be less than the whole representation
--- (RFC 9110 14.4, 14.5; see the header comment).
--- @return true; or false and, for a PUT whose range claims the whole
---   representation, its length, which the content must then have
function M.partial(req)
    local range = components.field_value(req, "content-range")
    if range == nil or req.method ~= "PUT" then return false end
    local unit, first, last, length = range:match("^([^ ]+) (%d+)%-(%d+)/(%d+)$")
    if not unit or not unit:match(TOKEN) or components.ascii_lower(unit) ~= "bytes" then return true end
    first, last, length = math.tointeger(tonumber(first)), math.tointeger(tonumber(last)), math.tointeger(tonumber(length))
    if first == 0 and last and length and length == last + 1 then return false, length end
    return true
end

--- Everything decidable without the body.
--- @return checks { { alg, want, decode? } ... } still to compare with the
---   body (decode: the codings to remove first), and the reason a covered
---   digest cannot be checked at all (or nil);
---   or false, reason when a covered digest is malformed (invalid)
function M.plan(req, fields, hash, strict_lines)
    local checks, unsure = {}, nil
    for _, name in ipairs(ORDER) do
        local members = fields[name]
        if members then
            -- Present: components.value() derived it for the signature base.
            local ok, dict = pcall(sf.parse_dictionary, components.field_value(req, name))
            if not ok then return false, "malformed-digest" end
            -- RFC 9651 4.2's MAY (policy.strict_field_lines): each line alone too.
            if strict_lines and not sf.every_line(req.fields[name], sf.parse_dictionary) then
                return false, "malformed-digest"
            end
            local alg
            for _, a in ipairs(M.PREFERENCE) do
                if dict[a] ~= nil and (members == true or members[a]) and hash[a] then
                    alg = a
                    break
                end
            end
            local m = alg and dict[alg]
            if m and (m.kind ~= "item" or m.value.type ~= "binary") then
                return false, "malformed-digest"
            end
            local why, codings, length
            if not alg then
                why = "digest-algorithm-unsupported"
            elseif name ~= "content-digest" then
                local part
                part, length = M.partial(req)
                if part then
                    why = "digest-partial"
                elseif name == "unencoded-digest" then
                    codings, why = M.content_codings(req)
                    if codings and #codings == 0 then codings = nil end
                end
            end
            if why then
                unsure = unsure or why
            else
                checks[#checks + 1] = { alg = alg, want = m.value.value, decode = codings, length = length }
            end
        end
    end
    return checks, unsure
end

--- The body with its content codings removed, once per request.
--- @return the decoded body; or nil, status, reason
local function decoded(body, codings, policy, cache)
    local d = cache.decoded
    if not d then
        local budget = policy.max_decoded_body or math.maxinteger
        if policy.max_decode_ratio and policy.max_decode_ratio * #body < budget then
            budget = policy.max_decode_ratio * #body
        end
        local data, kind = coding.decode(body, codings, budget)
        d = { data = data, kind = kind }
        cache.decoded = d
    end
    if d.data then return d.data end
    if d.kind == "corrupt" then return nil, "invalid", "bad-content-coding" end
    if d.kind == "limit" then return nil, "unverified", "body-too-large" end
    return nil, "unverified", "digest-coding-unsupported"
end

--- Compares planned checks with the body.
--- @param body string, complete boolean (false: truncated or over a limit)
--- @param policy { max_sha256_body?, max_decoded_body?, max_decode_ratio? }
---   (verify.DEFAULT_POLICY; an absent field is no limit)
--- @param cache table shared by the request's signatures: digests by
---   algorithm and input, and the decoded body
--- @return nil when every check matches, else status, reason
function M.compare(checks, body, complete, hash, policy, cache)
    if not complete then return "unverified", "body-incomplete" end
    local unsure
    for pass = 1, 2 do -- 1: the received bytes; 2: the decoded representation
        for _, c in ipairs(checks) do
            if (c.decode == nil) == (pass == 1) then
                local data, key, st, why = body, c.alg
                if c.length and #body ~= c.length then
                    -- The range says this is the whole representation; the content disagrees.
                    data, why = nil, "digest-partial"
                elseif c.decode then
                    data, st, why = decoded(body, c.decode, policy, cache)
                    if st == "invalid" then return st, why end
                    key = c.alg .. " decoded"
                end
                if not data then
                    unsure = unsure or why
                elseif c.alg == "sha-256" and policy.max_sha256_body and #data > policy.max_sha256_body then
                    unsure = unsure or "body-too-large"
                else
                    cache[key] = cache[key] or hash[c.alg](data)
                    if cache[key] ~= c.want then return "invalid", "digest-mismatch" end
                end
            end
        end
    end
    if unsure then return "unverified", unsure end
    return nil
end

return M
