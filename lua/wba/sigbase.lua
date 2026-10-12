--[[
sigbase.lua: RFC 9421 section 2.5, "Creating the Signature Base". Pure Lua.

    signature-base = *( signature-base-line LF ) signature-params-line

Each covered component is a typed Structured Fields item (its name as a
String plus any parameters, e.g. "signature-agent";key="agent2"), serialized
exactly the way the signer serialized it. The final @signature-params line has
no trailing LF.

Proven byte-for-byte against RFC 9421 Appendix B.2.6 and the Web Bot Auth
draft's Appendix E.2.1 / E.2.2 vectors (lua/tests/test_sigbase.lua).
--]]

local sf = require("wba.structured_fields")

local M = {}

--- What makes two covered components the same one. RFC 9421 2: parameter
--- order is not significant ("foo";bar;baz equals "foo";baz;bar). RFC 9421
--- 2.1.2: a Dictionary key is covered at most once, and ;sf adds nothing to
--- ;key, so "d";key="a" and "d";key="a";sf are the same component too.
--- Raises on an unserializable item (callers pcall).
function M.identity(item)
    local name = sf.serialize_item({ value = item.value, params = {} })
    local keyed = sf.param(item.params, "key") ~= nil
    local ps = {}
    for _, kv in ipairs(item.params) do
        if not (keyed and kv[1] == "sf") then ps[#ps + 1] = sf.serialize_params({ kv }) end
    end
    table.sort(ps)
    return name .. table.concat(ps)
end

--- @param covered ordered list of { item = <sf item>, value = <component value string> }
--- @param params ordered sf parameter list of the signature (created, keyid, ...)
--- @param memo optional per-request table (components.memo): a value already
---   checked for this request is not scanned again for the next signature
--- @return string|nil signature base, or nil + reason code
function M.build(covered, params, memo)
    if memo and not memo.ascii_d then memo.ascii_d, memo.ascii_f = {}, {} end
    if #covered == 0 then
        return nil, "no-covered-components"
    end
    local seen, lines, items = {}, {}, {}
    for n, c in ipairs(covered) do
        local id = M.identity(c.item)
        if seen[id] then
            return nil, "duplicate-component"
        end
        seen[id] = true
        if c.value == nil then
            return nil, "missing-component"
        end
        -- RFC 9421 2.5 step 4: the base must be ASCII. Also refuse control
        -- bytes other than HTAB, which no valid HTTP field value contains,
        -- and HTAB too in a derived component (2.5 ABNF: *( VCHAR / SP )).
        local derived = c.item.value.value:sub(1, 1) == "@"
        local ok = memo and (derived and memo.ascii_d or memo.ascii_f)
        if not (ok and ok[c.value]) then
            if c.value:find(derived and "[^\32-\126]" or "[^\9\32-\126]") then
                return nil, "bad-component-value"
            end
            if ok then ok[c.value] = true end
        end
        lines[n] = sf.serialize_item(c.item) .. ": " .. c.value
        items[n] = c.item
    end
    lines[#lines + 1] = '"@signature-params": '
        .. sf.serialize_inner_list({ items = items, params = params })
    return table.concat(lines, "\n")
end

return M
