--[[
base64.lua: standard base64 (RFC 4648 section 4), the encoding RFC 9651 Byte
Sequences use. Pure Lua 5.3+ (integer bit operators), no dependencies.

decode() follows RFC 9651 section 4.2.7: it tolerates missing or partial "="
padding and non-zero pad bits, because the spec says parsers SHOULD NOT fail
on either. Callers that need a fixed length (a 64-byte Ed25519 signature)
check it themselves. Any character outside the alphabet, "=" anywhere but the
end, more "=" than the length needs (RFC 4648 3.2), or an impossible length
returns nil.
--]]

local M = {}

local ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local DECODE = {}
for n = 1, 64 do
    DECODE[ALPHABET:byte(n)] = n - 1
end

--- @param s string base64 text
--- @return string|nil raw bytes, or nil if s is not base64
function M.decode(s)
    local body, pad = s:match("^([A-Za-z0-9+/]*)(=*)$")
    if not body or #pad > 2 or #body % 4 == 1 then
        return nil
    end
    if #pad > (4 - #body % 4) % 4 then -- more padding than the length calls for
        return nil
    end
    local out, n = {}, 0
    for i = 1, #body, 4 do
        local chunk = body:sub(i, i + 3)
        local v = 0
        for j = 1, #chunk do
            v = (v << 6) | DECODE[chunk:byte(j)]
        end
        local bits = #chunk * 6          -- 24, 18 or 12
        local bytes = bits // 8          -- 3, 2 or 1
        v = v >> (bits - bytes * 8)      -- drop pad bits
        for k = bytes - 1, 0, -1 do
            n = n + 1
            out[n] = string.char((v >> (8 * k)) & 0xFF)
        end
    end
    return table.concat(out)
end

--- @param raw string bytes
--- @return string canonical padded base64
function M.encode(raw)
    local out, n = {}, 0
    for i = 1, #raw, 3 do
        local a, b, c = raw:byte(i, i + 2)
        local v = (a << 16) | ((b or 0) << 8) | (c or 0)
        local chars = (b == nil) and 2 or ((c == nil) and 3 or 4)
        for k = 0, 3 do
            n = n + 1
            if k < chars then
                local idx = (v >> (18 - 6 * k)) & 63
                out[n] = ALPHABET:sub(idx + 1, idx + 1)
            else
                out[n] = "="
            end
        end
    end
    return table.concat(out)
end

return M
