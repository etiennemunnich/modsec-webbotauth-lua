-- test_sf_corpus.lua: structured_fields.lua against the HTTP Working Group's
-- RFC 9651 corpus (sf-corpus/, pinned and hashed; see its README). Every
-- record runs, none is skipped, and every mismatch is listed before the
-- suite fails.
--
--   parse records      raw lines joined by ", " must parse to `expected`
--                      (or fail when must_fail; may fail when can_fail), and
--                      `expected` must serialize to `canonical` (or raw)
--   serialize records  `expected` must serialize to `canonical`, or fail to
--                      serialize when must_fail
-- Run: lua lua/tests/test_sf_corpus.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local json = require("json")
local sf = require("wba.structured_fields")

local DIR = H.here .. "sf-corpus/"

-- 1. The corpus is the pinned one, byte for byte.
local files = {}
for line in H.read(DIR .. "MANIFEST"):gmatch("[^\n]+") do
    local want, path = line:match("^([0-9a-f]+)  (.+)$")
    local p = io.popen("openssl dgst -sha256 -r '" .. DIR .. path .. "'")
    local got = p:read("a"):match("^([0-9a-f]+)")
    p:close()
    H.eq(got, want, "sf-corpus/" .. path .. " differs from MANIFEST")
    files[#files + 1] = path
end
H.pass(#files .. " corpus files match their pinned SHA-256")

-- RFC 4648 section 6 base32, for the corpus's binary values.
local B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
local function base32_decode(s)
    local bits, n, out = 0, 0, {}
    for c in s:gsub("=", ""):gmatch(".") do
        bits = (bits << 5) | (B32:find(c, 1, true) - 1)
        n = n + 5
        if n >= 8 then
            n = n - 8
            out[#out + 1] = string.char((bits >> n) & 0xFF)
        end
    end
    return table.concat(out)
end

-- The corpus's JSON form of a value, and conversions both ways.
local function bare_from_json(v)
    local mt = math.type(v)
    if mt == "integer" then return { type = "integer", value = v } end
    if mt == "float" then return { type = "decimal", value = v } end
    if type(v) == "string" then return { type = "string", value = v } end
    if type(v) == "boolean" then return { type = "boolean", value = v } end
    if v.__type == "binary" then return { type = "binary", value = base32_decode(v.value) } end
    return { type = v.__type, value = v.value } -- token, date, displaystring
end

local function params_from_json(ps)
    local out = {}
    for n, kv in ipairs(ps) do out[n] = { kv[1], bare_from_json(kv[2]) } end
    return out
end

local function member_from_json(m)
    if json.is_array(m[1]) then
        local items = {}
        for n, it in ipairs(m[1]) do
            items[n] = { kind = "item", value = bare_from_json(it[1]), params = params_from_json(it[2]) }
        end
        return { kind = "inner-list", items = items, params = params_from_json(m[2]) }
    end
    return { kind = "item", value = bare_from_json(m[1]), params = params_from_json(m[2]) }
end

local function value_from_json(header_type, e)
    if header_type == "item" then return member_from_json(e) end
    if header_type == "list" then
        local members = {}
        for n, m in ipairs(e) do members[n] = member_from_json(m) end
        return { kind = "list", members = members }
    end
    local map, order = {}, {}
    for n, kv in ipairs(e) do
        order[n] = kv[1]
        map[kv[1]] = member_from_json(kv[2])
    end
    return { kind = "dictionary", map = map, order = order }
end

-- Structural equality; numbers must also agree on integer vs float.
local function same(a, b)
    if type(a) ~= type(b) then return false end
    if type(a) == "number" then return math.type(a) == math.type(b) and a == b end
    if type(a) ~= "table" then return a == b end
    for k, v in pairs(a) do
        if not same(v, b[k]) then return false end
    end
    for k in pairs(b) do
        if a[k] == nil then return false end
    end
    return true
end

-- The parsed value in the same shape as value_from_json's output.
local function normalize(v)
    if v.kind == "list" then
        local m = {}
        for n, x in ipairs(v.members) do m[n] = normalize(x) end
        return { kind = "list", members = m }
    elseif v.kind == "dictionary" then
        local map = {}
        for k, x in pairs(v.map) do map[k] = normalize(x) end
        return { kind = "dictionary", map = map, order = v.order }
    elseif v.kind == "inner-list" then
        local items = {}
        for n, x in ipairs(v.items) do items[n] = normalize(x) end
        return { kind = "inner-list", items = items, params = v.params }
    end
    return { kind = "item", value = v.value, params = v.params }
end

-- 2. Every record.
local total, failures, allowed = 0, {}, {}
local function bad(file, rec, why)
    failures[#failures + 1] = ("%s: %s: %s"):format(file, rec.name, why)
end

for _, file in ipairs(files) do
    local records = json.decode(H.read(DIR .. file))
    for _, rec in ipairs(records) do
        total = total + 1
        local canonical = rec.canonical or rec.raw
        local want = canonical and (canonical[1] or "") -- [] means "field omitted"
        if rec.raw then
            local ok, parsed = pcall(sf.parse, table.concat(rec.raw, ", "), rec.header_type)
            if rec.must_fail then
                if ok then bad(file, rec, "parsed, but must fail") end
            elseif not ok then
                if rec.can_fail then
                    allowed[#allowed + 1] = file .. ": " .. rec.name
                else
                    bad(file, rec, "failed to parse: " .. parsed)
                end
            else
                local expected = value_from_json(rec.header_type, rec.expected)
                if not same(normalize(parsed), expected) then
                    bad(file, rec, "parsed value differs from expected")
                else
                    local sok, out = pcall(sf.serialize, expected)
                    if not sok then
                        bad(file, rec, "expected value failed to serialize: " .. out)
                    elseif out ~= want then
                        bad(file, rec, ("serialized %q, want %q"):format(out, want))
                    end
                end
            end
        else
            local sok, out = pcall(sf.serialize, value_from_json(rec.header_type, rec.expected))
            if rec.must_fail then
                if sok then bad(file, rec, ("serialized %q, but must fail"):format(out)) end
            elseif not sok then
                bad(file, rec, "failed to serialize: " .. out)
            elseif out ~= want then
                bad(file, rec, ("serialized %q, want %q"):format(out, want))
            end
        end
    end
end

if #failures > 0 then
    for _, f in ipairs(failures) do print("FAIL: " .. f) end
    error(("%d of %d corpus records failed"):format(#failures, total), 0)
end
for _, a in ipairs(allowed) do print("can_fail (a SHOULD the RFC lets parsers decline): " .. a) end
H.pass(("all %d corpus records: parse, fail and serialize as the RFC 9651 corpus requires"):format(total))
H.done("test_sf_corpus")
