--[[
components.lua: RFC 9421 component values (sections 2.1 and 2.2) for a
request. Pure Lua 5.3+, no I/O.

  value(req, item)  -> component value string, or nil + reason

`req` is { fields = { [lowercase name] = { value, ... } }, method, authority,
path, query, scheme } as built by modsecurity_entry.lua. `item` is the parsed
component identifier (a String item with parameters).

Supported, each against the RFC's own examples (lua/tests/test_components.lua):
  @method @authority @scheme @path @query @target-uri @request-target
  @query-param;name="..."
  fields, alone or with ;key="..." (2.1.2), ;sf (2.1.1) or ;bs (2.1.3)

Errors, as RFC 9421 2.5 requires when a component cannot be resolved:
  @status                responses only (2.2.9)
  ;req                   responses only (2.4); a request has no related request
  ;tr                    trailers never reach ModSecurity's request phase
  ;bs with ;sf or ;key   incompatible (2.1)
  ;sf on a field whose Structured Field type is unknown (2.1.1)
--]]

local sf = require("wba.structured_fields")

local M = {}

--- Strips leading and trailing SP/HTAB in one pass each way. Never use the
--- pattern "^[ \t]*(.-)[ \t]*$" on request input: it backtracks, so a value
--- with a long run of inner whitespace costs time quadratic in its length.
function M.trim_ows(s)
    local i = s:find("[^ \t]")
    if not i then return "" end
    local j = #s
    while j > i do
        local b = s:byte(j)
        if b ~= 32 and b ~= 9 then break end
        j = j - 1
    end
    return s:sub(i, j)
end

--- Lowercases A-Z and nothing else. string.lower is C tolower(), which
--- follows the process locale; a range like [A-Z] compares bytes.
function M.ascii_lower(s)
    return (s:gsub("[A-Z]", function(c) return string.char(c:byte() + 32) end))
end

--- RFC 9421 2.1 step 3, HTTP/1.1 only: an obs-fold (OWS CRLF RWS) becomes
--- one SP. A linear scan; a pattern like "[ \t]*\r\n[ \t]+" backtracks on a
--- long run of whitespace. A CRLF without following whitespace is not an
--- obs-fold and stays (sigbase then refuses the value). nginx rejects obs-fold,
--- so in ModSecurity this returns its input unchanged.
local function unfold(v)
    if not v:find("\n", 1, true) then return v end
    local out, pos = {}, 1
    while true do
        local i = v:find("\r\n", pos, true)
        if not i then
            out[#out + 1] = v:sub(pos)
            return table.concat(out)
        end
        local after = v:byte(i + 2)
        if after == 32 or after == 9 then
            local j = i - 1
            while j >= pos and (v:byte(j) == 32 or v:byte(j) == 9) do j = j - 1 end
            local k = i + 2
            while v:byte(k) == 32 or v:byte(k) == 9 do k = k + 1 end
            out[#out + 1] = v:sub(pos, j) .. " "
            pos = k
        else
            out[#out + 1] = v:sub(pos, i + 1)
            pos = i + 2
        end
    end
end

-- Per-request memo. Each field value, parsed field and the query's parameters
-- are worked out at most once per request, however many covered components
-- name them. Without it the cost is components x field size: hundreds of
-- ;sf, ;key or @query-param components over one 8 KiB field cost seconds of
-- CPU before any key or signature check (measured: 2.65 s for one request).
local MEMO = setmetatable({}, { __mode = "k" })
local function memo(req)
    local m = MEMO[req]
    if not m then
        m = { field = {}, dict = {}, item = {}, sf = {}, bs = {} }
        MEMO[req] = m
    end
    return m
end

--- RFC 9421 2.1: each instance trimmed and unfolded, all joined with ", ".
function M.field_value(req, name)
    local m = memo(req)
    local cached = m.field[name]
    if cached ~= nil then return cached or nil end
    local values = req.fields[name]
    local out = false
    if values and #values > 0 then
        local parts = {}
        for n, v in ipairs(values) do
            parts[n] = unfold(M.trim_ows(v))
        end
        out = table.concat(parts, ", ")
    end
    m.field[name] = out
    return out or nil
end
M.unfold = unfold

-- Structured Field types (RFC 9421 2.1.1 needs the type to re-serialize).
-- IANA HTTP Field Name registry, "Structured Type" column, snapshot of
-- 2026-10-01 (field-names.csv, sha256 f052054a8f53585e...). The registry lists
-- sec-fetch-storage-access as "Token"; a Token is an Item. Plus the
-- Dictionaries RFC 9421 (Accept-Signature, 5.1) and the Web Bot Auth draft
-- (Signature-Agent) define without registering a type.
M.FIELD_TYPES = {
    ["accept-ch"] = "list", ["accept-query"] = "list",
    ["activate-storage-access"] = "item", ["available-dictionary"] = "item",
    ["cache-group-invalidation"] = "list", ["cache-groups"] = "list",
    ["cache-status"] = "list", ["capsule-protocol"] = "item",
    ["cdn-cache-control"] = "dictionary", ["client-cert"] = "item",
    ["client-cert-chain"] = "list", ["concealed-auth-export"] = "item",
    ["connect-udp-bind"] = "item", ["content-digest"] = "dictionary",
    ["cross-origin-embedder-policy"] = "item",
    ["cross-origin-embedder-policy-report-only"] = "item",
    ["cross-origin-opener-policy"] = "item",
    ["cross-origin-opener-policy-report-only"] = "item",
    ["deprecation"] = "item", ["dictionary-id"] = "item", ["incremental"] = "item",
    ["origin-agent-cluster"] = "item", ["priority"] = "dictionary",
    ["proxy-public-address"] = "list", ["proxy-status"] = "list",
    ["repr-digest"] = "dictionary", ["sec-fetch-dest"] = "item",
    ["sec-fetch-mode"] = "item", ["sec-fetch-site"] = "item",
    ["sec-fetch-storage-access"] = "item", ["sec-fetch-user"] = "item",
    ["signature"] = "dictionary", ["signature-input"] = "dictionary",
    ["unencoded-digest"] = "dictionary", ["use-as-dictionary"] = "dictionary",
    ["want-content-digest"] = "dictionary", ["want-repr-digest"] = "dictionary",
    ["want-unencoded-digest"] = "dictionary",
    ["accept-signature"] = "dictionary", ["signature-agent"] = "dictionary",
}

-- @query-param (2.2.8) ------------------------------------------------------

-- WHATWG URL Standard, percent-decode a byte sequence: "%" and two hex digits
-- become one byte; any other "%" stays as it is.
local function percent_decode(s)
    return (s:gsub("%%([0-9A-Fa-f][0-9A-Fa-f])", function(h) return string.char(tonumber(h, 16)) end))
end

-- WHATWG Encoding Standard, UTF-8 decode without BOM, replacement error mode,
-- returned as UTF-8 bytes: each maximal invalid subpart becomes U+FFFD.
local REPLACEMENT = "\239\191\189"
local function utf8_decode_replace(s)
    local out, i, n = {}, 1, #s
    while i <= n do
        local c = s:byte(i)
        local need, lo, hi = -1, 0x80, 0xBF -- need -1: not a lead byte
        if c <= 0x7F then
            need = 0
        elseif c >= 0xC2 and c <= 0xDF then
            need = 1
        elseif c >= 0xE0 and c <= 0xEF then
            need = 2
            if c == 0xE0 then lo = 0xA0 elseif c == 0xED then hi = 0x9F end
        elseif c >= 0xF0 and c <= 0xF4 then
            need = 3
            if c == 0xF0 then lo = 0x90 elseif c == 0xF4 then hi = 0x8F end
        end
        local seen = 0
        while seen < need do
            local b = s:byte(i + 1 + seen)
            if b == nil or b < lo or b > hi then break end
            lo, hi = 0x80, 0xBF
            seen = seen + 1
        end
        if seen == need then
            out[#out + 1] = s:sub(i, i + need)
        else
            out[#out + 1] = REPLACEMENT -- an unexpected byte is not consumed: it is decoded next
        end
        i = i + 1 + seen
    end
    return table.concat(out)
end

-- WHATWG URL Standard, application/x-www-form-urlencoded parser, 5.1.
local function form_parse(query)
    local out = {}
    for bytes in (query .. "&"):gmatch("([^&]*)&") do
        if bytes ~= "" then
            local eq = bytes:find("=", 1, true)
            local name = eq and bytes:sub(1, eq - 1) or bytes
            local value = eq and bytes:sub(eq + 1) or ""
            name, value = (name:gsub("%+", " ")), (value:gsub("%+", " "))
            out[#out + 1] = { utf8_decode_replace(percent_decode(name)), utf8_decode_replace(percent_decode(value)) }
        end
    end
    return out
end

-- RFC 9421 2.2.8 step 2: the URL Standard's "percent-encode after encoding"
-- (UTF-8) with the application/x-www-form-urlencoded percent-encode set:
-- everything but ASCII alphanumerics and "*-._" is encoded, as uppercase hex.
-- A space is "+" here, as section 5.2's serializer calls it (spaceAsPlus);
-- the RFC's own example prints "%20" (the algorithm's default), so
-- verify.lua also accepts that spelling (CONFORMANCE.md, choice 9). A
-- literal "+" in the data is "%2B", so a "+" here only ever means a space.
local function form_encode(s)
    return (s:gsub("[^A-Za-z0-9*%-._]", function(c)
        if c == " " then return "+" end
        return string.format("%%%02X", c:byte())
    end))
end
M.form_parse, M.form_encode = form_parse, form_encode
M.memo = memo -- verify.lua and sigbase.lua keep per-request facts here too

local function query_param(req, item)
    local name, other
    for _, kv in ipairs(item.params) do
        if kv[1] == "name" and kv[2].type == "string" and name == nil then
            name = kv[2].value
        else
            other = true
        end
    end
    if other or not name then return nil, "unsupported-component" end
    if req.path == nil then return nil, "missing-component" end -- query unavailable, as for @query
    local m = memo(req)
    if not m.query then -- encoded name -> { count, encoded value }, built once
        m.query = {}
        for _, pair in ipairs(form_parse(req.query or "")) do
            local key = form_encode(pair[1])
            local e = m.query[key]
            if e then
                e.count = e.count + 1
            else
                m.query[key] = { count = 1, value = form_encode(pair[2]) }
            end
        end
    end
    -- A name spelled with "%20" for a space (the RFC's example) is the same
    -- name; its value is then spelled the same way.
    local spaced = name:find("%20", 1, true) ~= nil
    local e = m.query[spaced and (name:gsub("%%20", "+")) or name]
    -- 2.2.8: a name that occurs more than once "MUST NOT be included".
    if not e or e.count ~= 1 then return nil, "missing-component" end
    return spaced and (e.value:gsub("%+", "%%20")) or e.value
end

-- Derived components (2.2) ---------------------------------------------------

local function derived(req, item)
    local name = item.value.value
    if name == "@query-param" then return query_param(req, item) end
    if #item.params > 0 then return nil, "unsupported-component" end -- incl. ;req (2.4)
    local path = req.path
    if path == "" then path = "/" end -- 2.2.6
    local v
    if name == "@method" then
        v = req.method
    elseif name == "@authority" then
        v = req.authority
    elseif name == "@scheme" then
        v = req.scheme and M.ascii_lower(req.scheme)
    elseif name == "@path" then
        v = path
    elseif name == "@query" then
        -- Only when the target starts with "/" (path known: origin-form, or
        -- what nginx hands over after an absolute-form host). Otherwise the
        -- query is unavailable, not absent: nginx hands ModSecurity "?evil=1"
        -- for "GET http://host?evil=1", and "?" must not match that.
        if path ~= nil then v = "?" .. (req.query or "") end
    elseif name == "@request-target" then
        -- 2.2.5, built in origin-form from the raw path and query. For an
        -- absolute-form line nginx hands over only what follows the host, so
        -- "GET http://example.com/x" gives "/x", which a signature over the
        -- full URL does not match; with no "/" after the host it is unavailable.
        if req.path then v = req.path .. (req.query and ("?" .. req.query) or "") end
    elseif name == "@target-uri" then
        if not req.scheme then return nil, "unsupported-component" end
        if req.authority and path then
            v = M.ascii_lower(req.scheme) .. "://" .. req.authority .. path
                .. (req.query and ("?" .. req.query) or "")
        end
    else
        return nil, "unsupported-component" -- @status (responses only) and unregistered names
    end
    if v == nil then return nil, "missing-component" end
    return v
end

-- HTTP fields (2.1) ---------------------------------------------------------

local FIELD_NAME = "^[a-z0-9!#$%%&'*+%-%.^_`|~]+$"
M.FIELD_NAME = FIELD_NAME -- RFC 9110 token, lowercase (also checks operator settings)

local function field(req, item, field_types)
    local name = item.value.value
    if not name:match(FIELD_NAME) then return nil, "unsupported-component" end
    local key, strict, binary
    for _, kv in ipairs(item.params) do
        local k, v = kv[1], kv[2]
        if k == "key" and v.type == "string" then
            key = v.value
        elseif k == "sf" and v.type == "boolean" and v.value == true then
            strict = true
        elseif k == "bs" and v.type == "boolean" and v.value == true then
            binary = true
        else
            return nil, "unsupported-component" -- req, tr, name, unregistered, or a mistyped value
        end
    end
    local combined = M.field_value(req, name) -- memoized
    if combined == nil then return nil, "missing-component" end
    local m = memo(req)

    if binary then -- 2.1.3
        if key or strict then return nil, "unsupported-component" end
        if m.bs[name] == nil then
            local members = {}
            for n, v in ipairs(req.fields[name]) do
                members[n] = { kind = "item", value = { type = "binary", value = unfold(M.trim_ows(v)) }, params = {} }
            end
            m.bs[name] = sf.serialize({ kind = "list", members = members })
        end
        return m.bs[name]
    end

    if key then -- 2.1.2 (already strict, so ;sf adds nothing)
        local known = field_types[name]
        if known and known ~= "dictionary" then return nil, "unsupported-component" end -- a known List or Item
        if m.dict[name] == nil then
            local ok, dict = pcall(sf.parse_dictionary, combined)
            m.dict[name] = ok and dict or false
        end
        local dict = m.dict[name]
        if not dict or dict[key] == nil then return nil, "missing-component" end
        return sf.serialize_member(dict[key])
    end

    if strict then -- 2.1.1
        local ftype = field_types[name]
        if not ftype then return nil, "unsupported-component" end
        local slot = name .. "\0" .. ftype
        if m.sf[slot] == nil then
            local ok, parsed = pcall(sf.parse, combined, ftype)
            local sok, out = false, nil
            if ok then sok, out = pcall(sf.serialize, parsed) end
            m.sf[slot] = sok and out or false
        end
        if not m.sf[slot] then return nil, "missing-component" end
        return m.sf[slot]
    end
    return combined
end

--- The field parsed as a Dictionary (RFC 9651 3.2), or as an Item when
--- as_item, at most once per request; nil when absent or unparsable.
function M.parsed(req, name, as_item)
    local combined = M.field_value(req, name)
    if combined == nil then return nil end
    local slot = memo(req)[as_item and "item" or "dict"]
    if slot[name] == nil then
        local ok, v = pcall(as_item and sf.parse_item or sf.parse_dictionary, combined)
        slot[name] = ok and v or false
    end
    return slot[name] or nil
end

--- Value of one covered component for this request, or nil + reason.
--- field_types defaults to M.FIELD_TYPES; tests pass their own.
function M.value(req, item, field_types)
    if item.value.type ~= "string" then return nil, "unsupported-component" end
    if item.value.value:sub(1, 1) == "@" then return derived(req, item) end
    return field(req, item, field_types or M.FIELD_TYPES)
end

return M
