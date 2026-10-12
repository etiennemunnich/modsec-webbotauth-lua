-- test_log.lua: wba_log.lua (wba.conf rule 7) against a mock of ModSecurity's
-- `m`, with the libmodsecurity v3 rule that m.getvar raises for a name it
-- cannot resolve. Every line must be one valid JSON object (json.lua, a
-- strict RFC 8259 reader) holding exactly what the README says.
-- Run: lua lua/tests/test_log.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local json = require("json")

local SCRIPT = H.here .. "../wba/wba_log.lua"
local LOG = H.tmp("wba.log")
local FIXED = { UNIQUE_ID = true, REMOTE_ADDR = true, REQUEST_METHOD = true, REQUEST_URI_RAW = true }
for _, k in ipairs({ "status", "reason", "agent", "agent_proof", "keyid", "label", "created", "expires", "granted", "sighash", "uses", "nonce_uses", "covered" }) do
    FIXED["TX.wba_" .. k] = true
end

-- `open`, when given, stands in for io.open while the script runs (a file
-- that fails the way a full disk does).
local function run(vars, path, open)
    local logged, names = {}, {}
    _G.m = {
        getvar = function(name)
            names[#names + 1] = name
            if not FIXED[name] then error("std::invalid_argument: Variable not found") end
            -- Unset (nil or false here) or empty: no value at all, not even
            -- nil, as libmodsecurity's lua.cc returns.
            local v = vars[name]
            if v == nil or v == false or v == "" then return end
            return v
        end,
        log = function(_, msg) logged[#logged + 1] = msg end,
    }
    _G.WBA_LOG_CONFIG = { path = path or LOG }
    H.write(LOG, "")
    local real_open = io.open
    if open then io.open = open end -- luacheck: ignore 122 (a fake file for one run; put back below)
    dofile(SCRIPT)
    local result = main()
    io.open = real_open -- luacheck: ignore 122 (puts the real io.open back)
    H.eq(result, nil)
    for _, n in ipairs(names) do H.eq(FIXED[n], true, "m.getvar called with a non-fixed name: " .. n) end
    return H.read(LOG), logged
end

local SIGHASH = ("ab"):rep(32)
local VERIFIED = {
    UNIQUE_ID = "179092250669.094052", REMOTE_ADDR = "192.0.2.7", REQUEST_METHOD = "GET", REQUEST_URI_RAW = "/x?y=1",
    ["TX.wba_status"] = "verified", ["TX.wba_reason"] = "",
    ["TX.wba_agent"] = H.AGENT_ID, ["TX.wba_agent_proof"] = "valid", ["TX.wba_keyid"] = ("k"):rep(43), ["TX.wba_label"] = "sig1",
    ["TX.wba_created"] = "1790922496", ["TX.wba_expires"] = "1790923101", ["TX.wba_granted"] = "1",
    ["TX.wba_sighash"] = SIGHASH, ["TX.wba_uses"] = "2", ["TX.wba_nonce_uses"] = "n/a",
    ["TX.wba_covered"] = "@authority signature-agent",
}
local function with(over)
    local v = {}
    for k, x in pairs(VERIFIED) do v[k] = x end
    for k, x in pairs(over) do v[k] = x end
    return v
end
local function one_line(text)
    H.eq(select(2, text:gsub("\n", "")), 1, "exactly one line")
    H.eq(text:sub(-1), "\n")
    return json.decode(text:sub(1, -2))
end

-- 1. A verified request: every field, typed.
local first, first_logged = run(VERIFIED)
H.eq(#first_logged, 0, "a line written: nothing for the debug log")
local line = one_line(first)
H.eq(line.event, "web-bot-auth")
H.eq(math.type(line.time), "integer")
H.eq(line.unique_id, "179092250669.094052")
H.eq(line.client_ip, "192.0.2.7")
H.eq(line.method, "GET")
H.eq(line.uri, "/x?y=1")
H.eq(line.status, "verified")
H.eq(line.reason, "")
H.eq(line.agent, H.AGENT_ID)
H.eq(line.agent_proof, "valid")
H.eq(line.keyid, ("k"):rep(43))
H.eq(line.label, "sig1")
H.eq(line.created, 1790922496)
H.eq(line.expires, 1790923101)
H.eq(line.granted, true)
H.eq(line.sighash, SIGHASH)
H.eq(line.uses, 2)
H.eq(line.nonce_uses, json.null, "no nonce: null")
H.eq(line.covered, "@authority signature-agent")
H.eq(one_line((run(with({ ["TX.wba_nonce_uses"] = "3" })))).nonce_uses, 3)
H.pass("verified: one JSON line with outcome, identity, proof, window, grant, sighash, use counts and covered names")

-- 2. URL-less, and a failure: "n/a" (wba.conf rule 1) becomes null.
line = one_line((run(with({ ["TX.wba_agent"] = "n/a", ["TX.wba_agent_proof"] = "n/a", ["TX.wba_reason"] = "url-less", ["TX.wba_granted"] = "0" }))))
H.eq(line.agent, json.null)
H.eq(line.agent_proof, json.null)
H.eq(line.reason, "url-less")
H.eq(line.granted, false)
local failed = with({ ["TX.wba_status"] = "invalid", ["TX.wba_reason"] = "bad-signature", ["TX.wba_granted"] = "0" })
for _, k in ipairs({ "agent", "agent_proof", "keyid", "label", "created", "expires", "sighash", "uses", "nonce_uses", "covered" }) do failed["TX.wba_" .. k] = "n/a" end
line = one_line((run(failed)))
H.eq(line.status .. "/" .. line.reason, "invalid/bad-signature")
for _, k in ipairs({ "agent", "agent_proof", "keyid", "label", "created", "expires", "sighash", "uses", "nonce_uses", "covered" }) do
    H.eq(line[k], json.null, k .. " must be null when not verified")
end
H.eq(line.granted, false)
H.pass("URL-less and failed requests: unverified fields are null, never 'n/a' or a client value")

-- 3. Unsigned, or phase 1 ended before rule 1 ran: no line.
H.eq((run(with({ ["TX.wba_status"] = "not-signed" }))), "")
H.eq((run(with({ ["TX.wba_status"] = false }))), "", "status unset")
local ign = run(with({ ["TX.wba_status"] = "not-signed", ["TX.wba_reason"] = "unparsable-field" }))
H.eq(ign:find('"status":"not-signed","reason":"unparsable-field"', 1, true) ~= nil, true,
    "an unparsable signature header, ignored, is still logged")
H.pass("no line for unsigned requests or an unset status; one for an ignored, unparsable signature header")

-- 4. Client-controlled text cannot break the line or the JSON.
local nasty = '/a"b\\c\nd\re\1f\127g\128h\255i%22'
local text = run(with({ REQUEST_URI_RAW = nasty, REQUEST_METHOD = 'GET"\n' }))
line = one_line(text)
H.eq(text:find("[\128-\255]") == nil, true, "no raw byte above 127 in the line")
H.eq(text:find("\\u0080", 1, true) ~= nil and text:find("\\u00ff", 1, true) ~= nil, true, "high bytes as \\u00XX")
H.eq(line.uri:sub(1, 14), nasty:sub(1, 14), "quote, backslash, LF, CR, controls and DEL round-trip")
H.eq(line.method, 'GET"\n')
local long = run(with({ REQUEST_URI_RAW = "/" .. ("x"):rep(9000) }))
H.eq(#one_line(long).uri, 1024, "URI cut to 1024 bytes")
H.eq(#one_line((run(with({ REQUEST_URI_RAW = ("\1"):rep(5000) })))).uri, 1024 // 6,
    "URI capped at 1024 escaped bytes, cut between escapes (\\u0001 is 6 bytes)")
H.eq(one_line((run(with({ ["TX.wba_created"] = ("9"):rep(16) })))).created, json.null,
    "an integer longer than RFC 9651 allows (15 digits) is not written")
-- The longest line a request can make: 1-byte characters that fill every
-- field to its cap exactly, 15-digit integers (the most RFC 9651 allows) and
-- "granted":false. A filler that escapes to several bytes stops short of a
-- cap, and an integer too long is written as null, so either would measure
-- a shorter line than a real request can cause.
local CAPS = {
    UNIQUE_ID = 256, REMOTE_ADDR = 256, REQUEST_METHOD = 32, REQUEST_URI_RAW = 1024,
    ["TX.wba_status"] = 256, ["TX.wba_reason"] = 256, ["TX.wba_agent"] = 512, ["TX.wba_agent_proof"] = 16,
    ["TX.wba_keyid"] = 256, ["TX.wba_label"] = 64, ["TX.wba_sighash"] = 256, ["TX.wba_covered"] = 512,
}
local FIELD = { UNIQUE_ID = "unique_id", REMOTE_ADDR = "client_ip", REQUEST_METHOD = "method", REQUEST_URI_RAW = "uri" }
local INTS = { "created", "expires", "uses", "nonce_uses" }
local worst = { ["TX.wba_granted"] = "0" }
for k in pairs(CAPS) do worst[k] = ("x"):rep(5000) end
for _, k in ipairs(INTS) do worst["TX.wba_" .. k] = ("9"):rep(15) end
local wtext = run(worst)
local wline = one_line(wtext)
for k, cap in pairs(CAPS) do
    local name = FIELD[k] or k:sub(#"TX.wba_" + 1)
    H.eq(#wline[name], cap, name .. " filled to its cap exactly")
end
for _, k in ipairs(INTS) do H.eq(wline[k], 999999999999999, k .. ": a 15-digit integer is written") end
H.eq(wline.granted, false)
H.eq(#wtext <= 4096, true, ("worst-case line is %d bytes; one pipe write (4096 bytes on Linux) must hold it"):format(#wtext))
H.pass(("every field filled to its cap: worst case %d bytes, within one 4096-byte pipe write"):format(#wtext))
H.pass("quotes, backslashes, newlines, controls and high bytes escaped; URI capped")

-- 5. A line that cannot be written changes nothing else and says why in the debug log.
local _, logged = run(VERIFIED, H.tmp("no-such-dir/wba.log"))
H.eq(#logged, 1)
H.eq(logged[1]:find("log line not written", 1, true) ~= nil, true)
H.pass("unwritable log path: no error escapes, the debug log names the cause")

-- 6. A write that fails is noticed. The line is buffered whole, so it reaches
-- the file only when the file is closed: on a full disk, io.open succeeds and
-- close() returns nil and the reason. The debug log must say so.
local function failing_open(write_err, close_err)
    return function()
        return {
            setvbuf = function() return true end,
            write = function(self) if write_err then return nil, write_err end return self end,
            close = function() if close_err then return nil, close_err end return true end,
        }
    end
end
for _, case in ipairs({
    { when = "at close", open = failing_open(nil, "No space left on device"), cause = "No space left on device" },
    { when = "at write", open = failing_open("Input/output error", nil), cause = "Input/output error" },
}) do
    local _, msgs = run(VERIFIED, nil, case.open)
    H.eq(#msgs, 1, "a write that fails " .. case.when .. " is reported once")
    H.eq(msgs[1]:find("log line not written", 1, true) ~= nil and msgs[1]:find(case.cause, 1, true) ~= nil, true,
        "the debug log names the cause (" .. case.cause .. "): " .. msgs[1])
end
H.pass("a line lost at write or at close (a full disk) is reported in the debug log with its cause")

H.done("test_log")
