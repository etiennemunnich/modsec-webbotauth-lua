-- json.lua: a small, strict JSON reader (RFC 8259) for test corpora. Never
-- loaded by the verifier. Numbers keep their written type: "1" becomes a Lua
-- integer and "1.0" a float, which the structured-field corpus relies on to
-- tell Integers from Decimals. Arrays carry a marker metatable so an empty
-- array and an empty object stay distinguishable.
local M = {}

M.null = setmetatable({}, { __tostring = function() return "null" end })
local ARRAY = {}

function M.is_array(t)
    return type(t) == "table" and getmetatable(t) == ARRAY
end

local function fail(msg, i)
    error(("json: %s at %d"):format(msg, i), 0)
end

local function skip_ws(s, i)
    return s:find("[^ \t\r\n]", i) or #s + 1
end

local ESCAPES = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }

local function hex4(s, i)
    local h = s:sub(i, i + 3)
    if not h:match("^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$") then fail("bad \\u escape", i) end
    return tonumber(h, 16)
end

local function read_string(s, i)
    local out, j = {}, i + 1
    while true do
        local k = s:find('["\\]', j)
        if not k then fail("unterminated string", i) end
        out[#out + 1] = s:sub(j, k - 1)
        if s:sub(k, k) == '"' then return table.concat(out), k + 1 end
        local e = s:sub(k + 1, k + 1)
        if e == "u" then
            local cp = hex4(s, k + 2)
            j = k + 6
            if cp >= 0xD800 and cp <= 0xDBFF and s:sub(j, j + 1) == "\\u" then
                local lo = hex4(s, j + 2)
                if lo >= 0xDC00 and lo <= 0xDFFF then
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                    j = j + 6
                end
            end
            out[#out + 1] = utf8.char(cp)
        elseif ESCAPES[e] then
            out[#out + 1] = ESCAPES[e]
            j = k + 2
        else
            fail("bad escape", k)
        end
    end
end

local read_value

local function read_number(s, i)
    local text = s:match("^%-?[0-9]+", i)
    if not text then fail("bad number", i) end
    local frac = s:match("^%.[0-9]+", i + #text)
    if frac then text = text .. frac end
    local exp = s:match("^[eE][-+]?[0-9]+", i + #text)
    if exp then text = text .. exp end
    return tonumber(text), i + #text -- "1" -> integer, "1.0" / "1e3" -> float
end

function read_value(s, i)
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == '"' then return read_string(s, i) end
    if c == "{" then
        local obj = {}
        i = skip_ws(s, i + 1)
        if s:sub(i, i) == "}" then return obj, i + 1 end
        while true do
            if s:sub(i, i) ~= '"' then fail("expected key", i) end
            local key
            key, i = read_string(s, i)
            i = skip_ws(s, i)
            if s:sub(i, i) ~= ":" then fail("expected ':'", i) end
            obj[key], i = read_value(s, i + 1)
            i = skip_ws(s, i)
            local d = s:sub(i, i)
            if d == "}" then return obj, i + 1 end
            if d ~= "," then fail("expected ',' or '}'", i) end
            i = skip_ws(s, i + 1)
        end
    end
    if c == "[" then
        local arr = setmetatable({}, ARRAY)
        i = skip_ws(s, i + 1)
        if s:sub(i, i) == "]" then return arr, i + 1 end
        while true do
            arr[#arr + 1], i = read_value(s, i)
            i = skip_ws(s, i)
            local d = s:sub(i, i)
            if d == "]" then return arr, i + 1 end
            if d ~= "," then fail("expected ',' or ']'", i) end
            i = i + 1
        end
    end
    if s:sub(i, i + 3) == "true" then return true, i + 4 end
    if s:sub(i, i + 4) == "false" then return false, i + 5 end
    if s:sub(i, i + 3) == "null" then return M.null, i + 4 end
    return read_number(s, i)
end

function M.decode(s)
    local v, i = read_value(s, 1)
    if skip_ws(s, i) <= #s then fail("trailing data", i) end
    return v
end

return M
