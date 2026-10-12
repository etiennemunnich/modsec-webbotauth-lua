--[[
wba_log.lua: the SecRuleScript of wba.conf rule 7 (phase 5). Appends
one JSON line per signed request to CONFIG.path:

  {"event":"web-bot-auth","time":1790922501,"unique_id":"...","client_ip":"...",
   "method":"GET","uri":"/x","status":"verified","reason":"","agent":"https://...",
   "agent_proof":"valid","keyid":"...","label":"sig1","created":1790922496,
   "expires":1790923101,"granted":false,"sighash":"<64 hex>","uses":1,
   "nonce_uses":null,"covered":"@authority signature-agent"}

Why a script and not a rule's `log` action: ModSecurity-nginx (v1.0.4,
src/ngx_http_modsecurity_log.c) writes the message of a rule that only logs
(pass,log) at nginx's info level, and the CRS image runs nginx at warn, so
those never appear. A rule that refuses is different: the connector
(src/ngx_http_modsecurity_module.c) writes the refusal at error level, with
the rule's id, msg and unique_id, so refusals by the recipes and by rule
9534107 do appear. The audit log records only "relevant" transactions, with
every header and body. This line is written for every signed request,
whatever those settings.

What it holds: the plugin's own outcome, values from a verified signature
(null unless verified; uses and nonce_uses also null without replay
accounting, or without a nonce), and the request's time, unique_id, client address,
method and raw URI (as the access log has them). Never the signature: sighash
identifies it. Values are read by fixed name only (m.getvar never sees a
name built from the request) and JSON-escaped; bytes outside printable ASCII
are written as \u00XX, so a line is always valid JSON and always one line.
Each field is capped after escaping (the URI at 1024 bytes, the agent at
512), so a line stays under 4096 bytes: one write() of that size to a pipe
is never interleaved with another worker's.

Configuration: CONFIG below. "/dev/stdout" is the container's log in the
official image (nginx workers inherit it); for nginx run as a daemon, set a
file the worker user can append to. Tests (and only tests) may predefine the
global WBA_LOG_CONFIG instead. A line that cannot be written (the file
cannot be opened, or the disk is full) changes no outcome; the debug log, at
level 2, says why: "[wba] log line not written: ...".
--]]

local CONFIG = WBA_LOG_CONFIG or {
    path = "/dev/stdout",
}

--- A JSON string of at most `limit` escaped bytes (256 by default), cut
--- between escapes, never inside one. Every field is capped, so a line stays
--- under 4096 bytes however its values are made up.
local function str(v, limit)
    limit = limit or 256
    local out, n = {}, 0
    for c in v:gmatch(".") do
        local e = c
        if c == '"' or c == "\\" then
            e = "\\" .. c
        elseif c:match("[%c\127-\255]") then
            e = ("\\u%04x"):format(c:byte())
        end
        if n + #e > limit then break end
        out[#out + 1], n = e, n + #e
    end
    return '"' .. table.concat(out) .. '"'
end

-- Set only on verified; wba.conf rule 1 leaves "n/a" otherwise.
local function verified_str(v, limit)
    if v == nil or v == "n/a" then return "null" end
    return str(v, limit)
end

local function verified_int(v)
    if v == nil or not v:match("^%d+$") or #v > 15 then return "null" end -- RFC 9651 Integers: 15 digits
    return v
end

function main()
    local ok, err = pcall(function()
        -- Rule 9534120 skips unsigned requests; this also covers a request
        -- whose phase 1 ended before wba.conf rule 1 ran (status unset). An
        -- unparsable signature header, ignored (not-signed/unparsable-field),
        -- is logged: the operator should see it.
        local status = m.getvar("TX.wba_status")
        if status == nil then return end
        if status == "not-signed" and m.getvar("TX.wba_reason") ~= "unparsable-field" then return end
        local function get(name) return m.getvar(name) or "" end
        local line = table.concat({
            '{"event":"web-bot-auth","time":', tostring(os.time()),
            ',"unique_id":', str(get("UNIQUE_ID")),
            ',"client_ip":', str(get("REMOTE_ADDR")),
            ',"method":', str(get("REQUEST_METHOD"), 32),
            ',"uri":', str(get("REQUEST_URI_RAW"), 1024),
            ',"status":', str(status),
            ',"reason":', str(get("TX.wba_reason")),
            ',"agent":', verified_str(m.getvar("TX.wba_agent"), 512), -- a jwks_uri / cimd identifier has a path
            ',"agent_proof":', verified_str(m.getvar("TX.wba_agent_proof"), 16),
            ',"keyid":', verified_str(m.getvar("TX.wba_keyid")),
            ',"label":', verified_str(m.getvar("TX.wba_label"), 64),
            ',"created":', verified_int(m.getvar("TX.wba_created")),
            ',"expires":', verified_int(m.getvar("TX.wba_expires")),
            ',"granted":', m.getvar("TX.wba_granted") == "1" and "true" or "false",
            ',"sighash":', verified_str(m.getvar("TX.wba_sighash")),
            ',"uses":', verified_int(m.getvar("TX.wba_uses")),
            ',"nonce_uses":', verified_int(m.getvar("TX.wba_nonce_uses")),
            ',"covered":', verified_str(m.getvar("TX.wba_covered"), 512),
            "}\n",
        })
        local f, open_err = io.open(CONFIG.path, "a")
        if not f then error("cannot open " .. CONFIG.path .. ": " .. tostring(open_err)) end
        f:setvbuf("full", 8192) -- the whole line in one write()
        local wrote, write_err = f:write(line)
        -- The buffered line reaches the file inside close(), so a full disk
        -- shows here: close() returns nil and the reason.
        local closed, close_err = f:close()
        if not wrote then error("cannot write " .. CONFIG.path .. ": " .. tostring(write_err)) end
        if not closed then error("cannot write " .. CONFIG.path .. ": " .. tostring(close_err)) end
    end)
    if not ok then m.log(2, "[wba] log line not written: " .. tostring(err)) end
    return nil -- no match: this rule only writes the line
end
