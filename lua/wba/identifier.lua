--[[
identifier.lua: Signature-Agent identifiers (draft 5.5). wba-keysync's
identifier.ts implements the same rules, and both suites run every row of
lua/tests/fixtures/identifiers.tsv, so the two cannot drift apart.

"All three types produce an identifier: the URL the verifier resolved, with
any query and fragment discarded." (5.5)

  directory(origin, strict)  type=directory (the default): the well-known URI
                             at the origin, https://<host>[:<port>]/.well-known/
                             http-message-signatures-directory
  url(value)                 type=jwks_uri and type=cimd: the member value,
                             query and fragment discarded
  valid(id)                  true when id is an identifier: the normal form of
                             itself (every directory identifier is one too)

Identifiers are compared after RFC 3986 6.2.2 and 6.2.3 normalization (5.5):
scheme and host lowercased, percent-encoding hex uppercased and unreserved
characters decoded, dot segments removed, an empty path made "/", an empty
or default (443) port removed. An IPv6 literal is written in RFC 5952's
canonical text (5952 4 binds any system that generates IPv6 text, as this
one does in the store, the logs and tx.wba_agent); two spellings of one
address are one identifier, two addresses never are.

Refused (nil), so the member is ignored and nothing is resolved:
  * anything that is not an https URI (RFC 3986 5.2.1 / 3 ABNF);
  * userinfo (RFC 9110 4.2.4: a recipient SHOULD treat it as an error);
  * a host that is not a DNS name, an IPv4 address or an IPv6 literal
    (IPvFuture, zone identifiers, percent-encoded names);
  * a port with a leading zero, 0, or above 65535: RFC 3986 leaves "08443"
    as is, while fetch() connects to 8443, so the identifier would name a
    port other than the one fetched.

directory() is stricter (5.5: the member value MUST be the ASCII
serialization of an origin, RFC 6454 6.2, and a verifier MUST ignore anything
else; "/" MAY be accepted): lowercase only, no path, query or fragment, no
empty port, and in strict mode (a request's member) no explicit ":443". Not
strict (an operator's allowlist): ":443" is normalized away.

Pure Lua 5.3, no I/O. Lowercasing touches A-Z only, whatever the locale.
--]]

local M = {}

M.WELL_KNOWN = "/.well-known/http-message-signatures-directory"

local function lower(s) return (s:gsub("[A-Z]", function(c) return string.char(c:byte() + 32) end)) end

-- RFC 3986 dec-octet: 0-255, no leading zero.
local function dec_octet(s)
    if not s:match("^%d%d?%d?$") or (#s > 1 and s:sub(1, 1) == "0") then return nil end
    local n = math.tointeger(tonumber(s))
    if n > 255 then return nil end
    return n
end

local function ipv4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = dec_octet(a), dec_octet(b), dec_octet(c), dec_octet(d)
    if not (a and b and c and d) then return nil end
    return { a, b, c, d }
end

-- "a:b:c" -> { a, b, c } as integers, "" -> {}, anything else nil.
local function h16_list(s)
    local out = {}
    if s == "" then return out end
    for part in (s .. ":"):gmatch("([^:]*):") do
        if not part:match("^%x%x?%x?%x?$") then return nil end
        out[#out + 1] = math.tointeger(tonumber(part, 16))
    end
    return out
end

--- The eight 16-bit groups of an RFC 3986 IPv6address in lowercase, or nil.
local function ipv6_groups(s)
    if s == "" or s:find("[^0-9a-f:.]") then return nil end
    local tail = {}
    if s:find(".", 1, true) then
        local dotted = s:match(":([0-9.]+)$") -- ls32: an IPv4address ends it
        local o = dotted and ipv4(dotted)
        if not o then return nil end
        tail = { o[1] * 256 + o[2], o[3] * 256 + o[4] }
        s = s:sub(1, #s - #dotted)
        if s:sub(-2) ~= "::" then s = s:sub(1, -2) end
    end
    local groups
    local a, b = s:find("::", 1, true)
    if a then
        if s:find("::", b + 1, true) then return nil end
        local left, right = h16_list(s:sub(1, a - 1)), h16_list(s:sub(b + 1))
        if not left or not right then return nil end
        local n = #left + #right + #tail
        if n > 7 then return nil end -- "::" stands for at least one group
        groups = left
        for _ = 1, 8 - n do groups[#groups + 1] = 0 end
        for _, g in ipairs(right) do groups[#groups + 1] = g end
    else
        groups = h16_list(s)
        if not groups or #groups + #tail ~= 8 then return nil end
    end
    for _, g in ipairs(tail) do groups[#groups + 1] = g end
    return groups
end

local function dotted(hi, lo) return ("%d.%d.%d.%d"):format(hi >> 8, hi & 255, lo >> 8, lo & 255) end

--- RFC 5952 text: 4.1 no leading zeros, 4.2 "::" for the longest run of two
--- or more zero groups (the first when tied), 4.3 lowercase; 5: the IPv4
--- part of an IPv4-mapped (RFC 4291) or IPv4-translated (RFC 2765) address
--- in dotted decimal.
local function ipv6_text(g)
    if g[1] == 0 and g[2] == 0 and g[3] == 0 and g[4] == 0 then
        if g[5] == 0 and g[6] == 0xffff then return "::ffff:" .. dotted(g[7], g[8]) end
        if g[5] == 0xffff and g[6] == 0 then return "::ffff:0:" .. dotted(g[7], g[8]) end
    end
    local best, len, i = 0, 0, 1
    while i <= 8 do
        if g[i] == 0 then
            local j = i
            while j <= 8 and g[j] == 0 do j = j + 1 end
            if j - i > len then best, len = i, j - i end
            i = j
        else
            i = i + 1
        end
    end
    local function hex(from, to)
        local parts = {}
        for k = from, to do parts[#parts + 1] = ("%x"):format(g[k]) end
        return table.concat(parts, ":")
    end
    if len < 2 then return hex(1, 8) end
    return hex(1, best - 1) .. "::" .. hex(best + len, 8)
end

--- Canonical host[:port], or nil. mode: "origin" (a request's directory
--- member: lowercase only, no empty or explicit default port), "lenient" (an
--- operator's directory origin: ":443" dropped), "url" (lowercased; an
--- empty or default port dropped, RFC 3986 6.2.3).
--- The host grammars below admit neither "@" (so userinfo, RFC 9110 4.2.4,
--- never parses) nor A-Z (an origin's serialization is lowercase, RFC 6454
--- 6.2); only "url" mode lowercases first.
local function authority(a, mode)
    if mode == "url" then a = lower(a) end
    local host, port
    if a:sub(1, 1) == "[" then
        local inner, rest = a:match("^%[([^%]]*)%](.*)$")
        local g = inner and ipv6_groups(inner) -- "v..." (IPvFuture) and "%25" (zone) refused here
        if not g then return nil end
        host = "[" .. ipv6_text(g) .. "]"
        if rest ~= "" then
            port = rest:match("^:(%d*)$")
            if not port then return nil end
        end
    else
        host, port = a:match("^([^:]*):(%d*)$")
        host = host or a
        if not host:match("^[a-z0-9][a-z0-9.-]*$") or host:find("[.-]$") then return nil end
    end
    if port == "" then
        if mode ~= "url" then return nil end
        port = nil
    end
    if port then
        if not port:match("^[1-9]%d?%d?%d?%d?$") or math.tointeger(tonumber(port)) > 65535 then return nil end
        if port == "443" then
            if mode == "origin" then return nil end
            port = nil
        end
    end
    return port and (host .. ":" .. port) or host
end

--- The directory identifier for an https origin, or nil (see the header).
function M.directory(origin, strict)
    local auth, rest = origin:match("^https://([^/?#]+)(.*)$")
    if not auth or (rest ~= "" and rest ~= "/") then return nil end
    local hostport = authority(auth, strict and "origin" or "lenient")
    if not hostport then return nil end
    return "https://" .. hostport .. M.WELL_KNOWN
end

local PCHAR = "A-Za-z0-9%-%._~!$&'()*+,;=:@%%"

local function pct_ok(s) return not s:gsub("%%%x%x", ""):find("%%") end

-- RFC 3986 6.2.2.1 and 6.2.2.2: hex digits uppercase, unreserved decoded.
local function pct_normal(s)
    return (s:gsub("%%(%x%x)", function(h)
        local c = string.char(tonumber(h, 16))
        if c:match("^[A-Za-z0-9%-%._~]$") then return c end
        return "%" .. h:upper()
    end))
end

-- RFC 3986 5.2.4 for a path that begins with "/", in linear time: a stack
-- of segments; a final "." or ".." leaves a trailing "/".
local function remove_dot_segments(path)
    local out, last = {}, nil
    for seg in (path:sub(2) .. "/"):gmatch("([^/]*)/") do
        last = seg
        if seg == ".." then
            out[#out] = nil
        elseif seg ~= "." then
            out[#out + 1] = seg
        end
    end
    if last == "." or last == ".." then out[#out + 1] = "" end
    return "/" .. table.concat(out, "/")
end

--- The identifier of a jwks_uri or cimd member value: the normalized https
--- URL with its query and fragment discarded, or nil (see the header).
function M.url(value)
    if value:find("[^A-Za-z0-9%-%._~:/?#%[%]@!$&'()*+,;=%%]") then return nil end
    local scheme, rest = value:match("^([A-Za-z][A-Za-z0-9+.%-]*):(.*)$")
    if not scheme or lower(scheme) ~= "https" then return nil end
    local auth, tail = rest:match("^//([^/?#]*)(.*)$")
    local hostport = auth and authority(auth, "url")
    if not hostport then return nil end
    local path = tail:match("^[^?#]*")
    local suffix = tail:sub(#path + 1)
    if path:find("[^" .. PCHAR .. "/]") or not pct_ok(path) then return nil end
    if suffix ~= "" then -- validated, then discarded (5.5)
        local query, fragment = suffix:match("^%?([^#]*)"), suffix:match("#(.*)$")
        for _, part in ipairs({ query or "", fragment or "" }) do
            if part:find("[^" .. PCHAR .. "/?]") or not pct_ok(part) then return nil end
        end
    end
    path = pct_normal(path)
    return "https://" .. hostport .. (path == "" and "/" or remove_dot_segments(path))
end

--- True when id is an identifier: its own normal form, with no query or
--- fragment. Every identifier directory() returns is one.
function M.valid(id)
    return type(id) == "string" and M.url(id) == id
end

return M
