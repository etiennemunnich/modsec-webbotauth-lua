--[[
structured_fields.lua: Structured Field Values for HTTP, RFC 9651 (which
obsoletes RFC 8941). Parsing follows section 4.2 and serialization section
4.1, step for step; each function names the section it implements. Pure Lua
5.3+. Checked against the HTTP Working Group's corpus
(httpwg/structured-field-tests, vendored in lua/tests/sf-corpus) with no
exceptions.

Values carry their type, so they re-serialize exactly (RFC 9421 signs
serializations: a String keeps its quotes, a Token does not):

  bare item   { type = t, value = v }
                integer        Lua integer
                decimal        Lua float
                string         Lua string, ASCII
                token          Lua string
                binary         Lua string of raw bytes
                boolean        true | false
                date           Lua integer, seconds since the Unix epoch
                displaystring  Lua string of UTF-8 bytes
  parameters  ordered list of { key, bare_item }
  item        { kind = "item", value = bare_item, params = parameters }
  inner list  { kind = "inner-list", items = { item, ... }, params = parameters }
  list        { kind = "list", members = { item | inner list, ... } }
  dictionary  { kind = "dictionary", map = { [key] = member }, order = { key, ... } }

A duplicate dictionary or parameter key keeps the position of its first
occurrence and the value of its last (4.2.2 step 4, 4.2.3.2 step 7).

Errors raise error("sf: ...", 0); callers use pcall. Character classes are
spelled out in ASCII: Lua's %a, %d and %w follow the C locale.
--]]

local base64 = require("wba.base64")

local M = {}

local function fail(msg, i)
    error("sf: " .. msg .. (i and (" at " .. i) or ""), 0)
end

local function skip_sp(s, i)
    while s:byte(i) == 32 do i = i + 1 end
    return i
end

local function skip_ows(s, i)
    local b = s:byte(i)
    while b == 32 or b == 9 do
        i = i + 1
        b = s:byte(i)
    end
    return i
end

local KEY = "^[a-z*][a-z0-9_%-%.%*]*"
local TOKEN = "^[A-Za-z*][A-Za-z0-9!#$%%&'*+%-%.^_`|~:/]*"

--- True when s is well-formed UTF-8 (RFC 3629 section 4): no overlong forms,
--- no surrogates, nothing above U+10FFFF.
function M.valid_utf8(s)
    local i, n = 1, #s
    while i <= n do
        local c = s:byte(i)
        local need; local lo, hi = 0x80, 0xBF
        if c < 0x80 then
            need = 0
        elseif c >= 0xC2 and c <= 0xDF then
            need = 1
        elseif c == 0xE0 then
            need, lo = 2, 0xA0
        elseif (c >= 0xE1 and c <= 0xEC) or c == 0xEE or c == 0xEF then
            need = 2
        elseif c == 0xED then
            need, hi = 2, 0x9F
        elseif c == 0xF0 then
            need, lo = 3, 0x90
        elseif c >= 0xF1 and c <= 0xF3 then
            need = 3
        elseif c == 0xF4 then
            need, hi = 3, 0x8F
        else
            return false
        end
        for k = 1, need do
            local b = s:byte(i + k)
            if b == nil then return false end
            if k == 1 then
                if b < lo or b > hi then return false end
            elseif b < 0x80 or b > 0xBF then
                return false
            end
        end
        i = i + need + 1
    end
    return true
end

-- Parsing ------------------------------------------------------------------

local parse_bare_item

-- 4.2.3.3 Parsing a Key
local function parse_key(s, i)
    local k = s:match(KEY, i)
    if not k then fail("expected key", i) end
    return k, i + #k
end

-- 4.2.4 Parsing an Integer or Decimal
local function parse_number(s, i)
    local j, sign = i, 1
    if s:byte(j) == 45 then -- "-"
        sign, j = -1, j + 1
    end
    local int = s:match("^[0-9]+", j)
    if not int then fail("expected digit", j) end
    j = j + #int
    if s:byte(j) ~= 46 then -- not "."
        if #int > 15 then fail("integer longer than 15 digits", i) end
        return { type = "integer", value = sign * math.tointeger(tonumber(int)) }, j
    end
    if #int > 12 then fail("decimal with more than 12 integer digits", i) end
    local frac = s:match("^[0-9]*", j + 1)
    if #frac == 0 then fail("decimal ends in '.'", i) end
    if #frac > 3 then fail("decimal with more than 3 fraction digits", i) end
    local n = math.tointeger(tonumber(int .. frac)) -- at most 15 digits: exact
    return { type = "decimal", value = sign * (n / 10.0 ^ #frac) }, j + 1 + #frac
end

-- 4.2.5 Parsing a String
local function parse_string(s, i)
    local out, j = {}, i + 1
    while true do
        local b = s:byte(j)
        if b == nil then
            fail("unterminated string", i)
        elseif b == 92 then -- backslash
            local nb = s:byte(j + 1)
            if nb ~= 34 and nb ~= 92 then fail("invalid escape", j) end
            out[#out + 1] = string.char(nb)
            j = j + 2
        elseif b == 34 then
            return { type = "string", value = table.concat(out) }, j + 1
        elseif b < 32 or b > 126 then
            fail("invalid character in string", j)
        else
            out[#out + 1] = string.char(b)
            j = j + 1
        end
    end
end

-- 4.2.6 Parsing a Token
local function parse_token(s, i)
    local t = s:match(TOKEN, i)
    if not t then fail("expected token", i) end
    return { type = "token", value = t }, i + #t
end

-- 4.2.7 Parsing a Byte Sequence
local function parse_binary(s, i)
    local j = s:find(":", i + 1, true)
    if not j then fail("unterminated byte sequence", i) end
    local raw = base64.decode(s:sub(i + 1, j - 1)) -- rejects anything outside A-Z a-z 0-9 + / =
    if not raw then fail("invalid byte sequence", i) end
    return { type = "binary", value = raw }, j + 1
end

-- 4.2.8 Parsing a Boolean
local function parse_boolean(s, i)
    local b = s:byte(i + 1)
    if b ~= 48 and b ~= 49 then fail("invalid boolean", i) end
    return { type = "boolean", value = b == 49 }, i + 2
end

-- 4.2.9 Parsing a Date
local function parse_date(s, i)
    local v, j = parse_number(s, i + 1)
    if v.type ~= "integer" then fail("date must be an integer", i) end
    return { type = "date", value = v.value }, j
end

-- 4.2.10 Parsing a Display String
local function parse_display_string(s, i)
    if s:byte(i + 1) ~= 34 then fail("expected '\"' after '%'", i) end
    local out, j = {}, i + 2
    while true do
        local b = s:byte(j)
        if b == nil then
            fail("unterminated display string", i)
        elseif b < 32 or b > 126 then
            fail("invalid character in display string", j)
        elseif b == 37 then -- "%"
            local hex = s:sub(j + 1, j + 2)
            if not hex:match("^[0-9a-f][0-9a-f]$") then fail("invalid percent-encoding", j) end
            out[#out + 1] = string.char(tonumber(hex, 16))
            j = j + 3
        elseif b == 34 then
            local bytes = table.concat(out)
            if not M.valid_utf8(bytes) then fail("display string is not UTF-8", i) end
            return { type = "displaystring", value = bytes }, j + 1
        else
            out[#out + 1] = string.char(b)
            j = j + 1
        end
    end
end

-- 4.2.3.1 Parsing a Bare Item
function parse_bare_item(s, i)
    local b = s:byte(i)
    if b == 45 or (b and b >= 48 and b <= 57) then return parse_number(s, i) end
    if b == 34 then return parse_string(s, i) end
    if b and ((b >= 65 and b <= 90) or (b >= 97 and b <= 122) or b == 42) then return parse_token(s, i) end
    if b == 58 then return parse_binary(s, i) end
    if b == 63 then return parse_boolean(s, i) end
    if b == 64 then return parse_date(s, i) end
    if b == 37 then return parse_display_string(s, i) end
    fail("expected bare item", i)
end

-- 4.2.3.2 Parsing Parameters
local function parse_parameters(s, i)
    local params, at = {}, {}
    while s:byte(i) == 59 do -- ";"
        i = skip_sp(s, i + 1)
        local key
        key, i = parse_key(s, i)
        local value = { type = "boolean", value = true }
        if s:byte(i) == 61 then -- "="
            value, i = parse_bare_item(s, i + 1)
        end
        if at[key] then
            params[at[key]][2] = value
        else
            params[#params + 1] = { key, value }
            at[key] = #params
        end
    end
    return params, i
end

-- 4.2.3 Parsing an Item
local function parse_item(s, i)
    local value
    value, i = parse_bare_item(s, i)
    local params
    params, i = parse_parameters(s, i)
    return { kind = "item", value = value, params = params }, i
end

-- 4.2.1.2 Parsing an Inner List
local function parse_inner_list(s, i)
    i = i + 1
    local items = {}
    while true do
        i = skip_sp(s, i)
        local b = s:byte(i)
        if b == nil then fail("unterminated inner list", i) end
        if b == 41 then -- ")"
            local params
            params, i = parse_parameters(s, i + 1)
            return { kind = "inner-list", items = items, params = params }, i
        end
        local item
        item, i = parse_item(s, i)
        items[#items + 1] = item
        local nb = s:byte(i)
        if nb ~= 32 and nb ~= 41 then fail("expected SP or ')' in inner list", i) end
    end
end

-- 4.2.1.1 Parsing an Item or Inner List
local function parse_member(s, i)
    if s:byte(i) == 40 then return parse_inner_list(s, i) end -- "("
    return parse_item(s, i)
end

-- Steps shared by 4.2.1 and 4.2.2 after each member: OWS, then end or ",".
local function next_member(s, i)
    i = skip_ows(s, i)
    if i > #s then return nil end
    if s:byte(i) ~= 44 then fail("expected ','", i) end
    i = skip_ows(s, i + 1)
    if i > #s then fail("trailing comma", i) end
    return i
end

-- 4.2.1 Parsing a List
local function parse_list(s, i)
    local members = {}
    while i and i <= #s do
        local member
        member, i = parse_member(s, i)
        members[#members + 1] = member
        i = next_member(s, i)
    end
    return { kind = "list", members = members }, #s + 1
end

-- 4.2.2 Parsing a Dictionary
local function parse_dictionary(s, i)
    local map, order = {}, {}
    while i and i <= #s do
        local key, member
        key, i = parse_key(s, i)
        if s:byte(i) == 61 then -- "="
            member, i = parse_member(s, i + 1)
        else
            local params
            params, i = parse_parameters(s, i)
            member = { kind = "item", value = { type = "boolean", value = true }, params = params }
        end
        if map[key] == nil then order[#order + 1] = key end
        map[key] = member
        i = next_member(s, i)
    end
    return { kind = "dictionary", map = map, order = order }, #s + 1
end

local PARSERS = { list = parse_list, dictionary = parse_dictionary, item = parse_item }

--- 4.2 Parsing Structured Fields. `s` is the field value, with multiple
--- field lines already combined by ", "; field_type is "list",
--- "dictionary" or "item".
function M.parse(s, field_type)
    local parser = PARSERS[field_type]
    if not parser then fail("unknown field type " .. tostring(field_type)) end
    local bad = s:find("[\128-\255]")
    if bad then fail("non-ASCII byte", bad) end
    local i = skip_sp(s, 1)
    local value
    value, i = parser(s, i)
    i = skip_sp(s, i)
    if i <= #s then fail("unexpected trailing characters", i) end
    return value
end

--- Dictionary field value -> map key -> member, ordered keys.
function M.parse_dictionary(s)
    local d = M.parse(s, "dictionary")
    return d.map, d.order
end

--- Item field value (e.g. the legacy bare-string Signature-Agent).
function M.parse_item(s)
    return M.parse(s, "item")
end

--- Value for `key` in a parameter list, or nil.
function M.param(params, key)
    for _, kv in ipairs(params) do
        if kv[1] == key then return kv[2] end
    end
    return nil
end

-- Serialization --------------------------------------------------------------

-- 4.1.4 Serializing an Integer
local function serialize_integer(v)
    if math.type(v) ~= "integer" or v < -999999999999999 or v > 999999999999999 then
        fail("integer out of range")
    end
    return string.format("%d", v)
end

-- The shortest decimal numeral that converts back to x, as sign, digits and
-- the exponent of the first digit. Rounding (4.1.5 step 2) applies to the
-- decimal number, so 0.0025 rounds to 0.002 even though the nearest binary
-- double is slightly above it.
local function shortest_decimal(x)
    for p = 0, 16 do
        local s = string.format("%." .. p .. "e", x)
        if tonumber(s) == x then
            local sign, d1, rest, exp = s:match("^(%-?)([0-9])[^0-9e]?([0-9]*)e([-+][0-9]+)$")
            return sign, d1 .. rest, tonumber(exp)
        end
    end
    fail("decimal has no finite representation")
end

-- 4.1.5 Serializing a Decimal
local function serialize_decimal(x)
    if type(x) ~= "number" or x ~= x or x == math.huge or x == -math.huge then
        fail("not a decimal number")
    end
    local sign, digits, exp = shortest_decimal(x + 0.0)
    local point = exp + 1 -- digits before the decimal point
    local int, frac
    if point <= 0 then
        int, frac = "0", string.rep("0", -point) .. digits
    elseif point >= #digits then
        int, frac = digits .. string.rep("0", point - #digits), ""
    else
        int, frac = digits:sub(1, point), digits:sub(point + 1)
    end
    int = int:gsub("^0+", "")
    if #int > 13 then fail("decimal integer component longer than 12 digits") end
    local keep = (frac .. "000"):sub(1, 3)
    local n = math.tointeger(tonumber((int == "" and "0" or int) .. keep)) -- thousandths
    local rest = frac:sub(4)
    if rest ~= "" then
        local first = rest:byte(1) - 48
        if first > 5 or (first == 5 and (rest:find("[1-9]", 2) or n % 2 == 1)) then
            n = n + 1 -- round half to even
        end
    end
    local whole, thousandths = n // 1000, n % 1000
    if whole > 999999999999 then fail("decimal integer component longer than 12 digits") end
    local fraction = "0"
    if thousandths ~= 0 then fraction = (string.format("%03d", thousandths):gsub("0+$", "")) end
    return (sign == "-" and n ~= 0 and "-" or "") .. string.format("%d", whole) .. "." .. fraction
end

-- 4.1.6 Serializing a String
local function serialize_string(v)
    if type(v) ~= "string" or v:find("[^\32-\126]") then fail("string with characters outside VCHAR or SP") end
    return '"' .. (v:gsub('[\\"]', "\\%0")) .. '"'
end

-- 4.1.7 Serializing a Token
local function serialize_token(v)
    if type(v) ~= "string" or not v:match(TOKEN .. "$") then fail("invalid token") end
    return v
end

-- 4.1.11 Serializing a Display String
local function serialize_display_string(v)
    if type(v) ~= "string" or not M.valid_utf8(v) then fail("display string is not UTF-8") end
    local escaped = v:gsub("[%%\"\0-\31\127-\255]", function(c) return string.format("%%%02x", c:byte()) end)
    return '%"' .. escaped .. '"'
end

-- 4.1.3.1 Serializing a Bare Item
local function serialize_bare_item(v)
    local t = v.type
    if t == "integer" then
        return serialize_integer(v.value)
    elseif t == "decimal" then
        return serialize_decimal(v.value)
    elseif t == "string" then
        return serialize_string(v.value)
    elseif t == "token" then
        return serialize_token(v.value)
    elseif t == "binary" then -- 4.1.8
        if type(v.value) ~= "string" then fail("byte sequence must be a string") end
        return ":" .. base64.encode(v.value) .. ":"
    elseif t == "boolean" then -- 4.1.9
        if type(v.value) ~= "boolean" then fail("not a boolean") end
        return v.value and "?1" or "?0"
    elseif t == "date" then -- 4.1.10
        return "@" .. serialize_integer(v.value)
    elseif t == "displaystring" then
        return serialize_display_string(v.value)
    end
    fail("cannot serialize type " .. tostring(t))
end

-- 4.1.1.3 Serializing a Key
local function serialize_key(k)
    if type(k) ~= "string" or not k:match(KEY .. "$") then fail("invalid key") end
    return k
end

-- 4.1.1.2 Serializing Parameters
function M.serialize_params(params)
    local out = {}
    for n, kv in ipairs(params) do
        local value = kv[2]
        if value.type == "boolean" and value.value == true then
            out[n] = ";" .. serialize_key(kv[1])
        else
            out[n] = ";" .. serialize_key(kv[1]) .. "=" .. serialize_bare_item(value)
        end
    end
    return table.concat(out)
end

-- 4.1.3 Serializing an Item
function M.serialize_item(item)
    return serialize_bare_item(item.value) .. M.serialize_params(item.params)
end

-- 4.1.1.1 Serializing an Inner List
function M.serialize_inner_list(list)
    local parts = {}
    for n, item in ipairs(list.items) do
        parts[n] = M.serialize_item(item)
    end
    return "(" .. table.concat(parts, " ") .. ")" .. M.serialize_params(list.params)
end

--- An Item or Inner List (a List member, or a Dictionary member's value).
function M.serialize_member(member)
    if member.kind == "inner-list" then
        return M.serialize_inner_list(member)
    end
    return M.serialize_item(member)
end

--- 4.1 Serializing Structured Fields: a list, dictionary or item as built by
--- M.parse. An empty List or Dictionary serializes to "" (4.1 step 1: the
--- field is omitted).
function M.serialize(value)
    local parts = {}
    if value.kind == "list" then -- 4.1.1
        for n, member in ipairs(value.members) do
            parts[n] = M.serialize_member(member)
        end
    elseif value.kind == "dictionary" then -- 4.1.2
        for n, key in ipairs(value.order) do
            local member = value.map[key]
            if member.kind == "item" and member.value.type == "boolean" and member.value.value == true then
                parts[n] = serialize_key(key) .. M.serialize_params(member.params)
            else
                parts[n] = serialize_key(key) .. "=" .. M.serialize_member(member)
            end
        end
    elseif value.kind == "item" then
        return M.serialize_item(value)
    else
        fail("cannot serialize " .. tostring(value.kind))
    end
    return table.concat(parts, ", ")
end

--- RFC 9651 4.2: "Parsers MAY fail when processing a field value spread
--- across multiple field lines, when one of those lines does not parse as
--- that field." True when there is at most one line, or each parses alone
--- with parse (a function raising on bad input).
function M.every_line(lines, parse)
    if not lines or #lines < 2 then return true end
    for _, line in ipairs(lines) do
        if not pcall(parse, line) then return false end
    end
    return true
end

return M
