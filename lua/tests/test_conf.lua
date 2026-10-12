-- test_conf.lua: the rule files as shipped (wba.conf, web-bot-auth-config.conf,
-- recipes.conf). The Lua is loaded only with SecRuleScript, which stops
-- startup when a script it names does not compile; @inspectFile would quietly run the
-- file as a program instead (live/run.sh checks the first). Every rule id, commented
-- examples included (operators uncomment them), sits in the plugin's block
-- 9534000-9534999 and appears once.
-- Run: lua lua/tests/test_conf.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")

local FILES = { "wba.conf", "web-bot-auth-config.conf", "recipes.conf" }
local text = {}
for _, f in ipairs(FILES) do text[f] = H.read(H.here .. "../wba/" .. f) end

-- 1. Lua only through SecRuleScript, and every script the entry needs is loaded.
local scripts = {}
for line in text["wba.conf"]:gmatch("[^\n]+") do
    if not line:match("^%s*#") then
        H.eq(line:find("@inspectFile", 1, true), nil, "no rule loads Lua with @inspectFile: " .. line)
        local path = line:match("^SecRuleScript%s+(%S+%.lua)%s")
        if path then scripts[#scripts + 1] = path:match("[^/]+$") end
    end
end
H.eq(table.concat(scripts, " "), "modsecurity_entry.lua modsecurity_entry.lua wba_log.lua",
    "phase 1 verify, phase 2 body, phase 5 log")
H.pass("wba.conf loads its Lua with SecRuleScript only: verify (phase 1), body (phase 2), log (phase 5)")

-- 2. Every id inside 9534000-9534999, once across the three files.
local seen, n = {}, 0
for _, f in ipairs(FILES) do
    for id in text[f]:gmatch("id:(%d+)") do
        local v = tonumber(id)
        H.eq(v >= 9534000 and v <= 9534999, true, f .. ": id " .. id .. " is outside 9534000-9534999")
        H.eq(seen[v], nil, f .. ": id " .. id .. " also in " .. tostring(seen[v]))
        seen[v], n = f, n + 1
    end
end
H.eq(n >= 25, true, "the files were read (" .. n .. " ids)")
H.pass(n .. " rule ids, each once, all in the plugin's block 9534000-9534999")

--- The directives of a rule file, in order: continuation lines joined the
--- way ModSecurity joins them, comments dropped. Each rule gets its kind, its
--- actions (a list of "name" or "name:value"), phase, id, and whether it is
--- the child of a chain (metadata actions belong on the chain's first rule).
local function directives(src)
    local out, cur = {}, nil
    for line in (src .. "\n"):gmatch("([^\n]*)\n") do
        if cur then cur = cur .. line:gsub("^%s+", "") elseif not line:match("^%s*#") and line:match("%S") then cur = line end
        if cur and cur:sub(-1) == "\\" then cur = cur:sub(1, -2) elseif cur then out[#out + 1] = cur; cur = nil end
    end
    local rules, chained = {}, false
    for _, d in ipairs(out) do
        local kind = d:match("^%s*(%a+)")
        local r = { kind = kind, text = d, child = false }
        if kind == "SecMarker" then
            r.marker = d:match('^%s*SecMarker%s+"?([%w-]+)')
        elseif kind == "SecRule" or kind == "SecAction" or kind == "SecRuleScript" then
            r.child, r.actions, r.has = chained, {}, {}
            local list = d:match('"([^"]*)"%s*$')
            local word, quoted = {}, false
            for c in (list .. ","):gmatch(".") do
                if c == "'" then quoted = not quoted end
                if c == "," and not quoted then
                    local a = table.concat(word)
                    r.actions[#r.actions + 1] = a
                    local name, value = a:match("^([%w]+):?(.*)$")
                    r.has[name] = r.has[name] or {}
                    table.insert(r.has[name], value)
                    word = {}
                else
                    word[#word + 1] = c
                end
            end
            r.id = r.has.id and tonumber(r.has.id[1])
            r.phase = r.has.phase and tonumber(r.has.phase[1])
            chained = r.has.chain ~= nil
        end
        rules[#rules + 1] = r
    end
    return rules
end
local parsed = { ["wba.conf"] = directives(text["wba.conf"]), ["recipes.conf"] = directives(text["recipes.conf"]) }

-- 3. Every rule the plugin ships (wba.conf, recipes.conf) carries the plugin's
-- tag, so ctl:ruleRemoveByTag=web-bot-auth reaches all of them (in
-- ModSecurity v3, ctl:ruleRemoveById skips SecAction and SecRuleScript), and
-- the same version string. A deliberate severity on every rule that logs:
-- without one, v3 logs severity 0 (EMERGENCY), above any CRS attack rule.
local VER = "'web-bot-auth-plugin/0.1.0'"
local SEVERITY = { [9534107] = "'WARNING'", [9534135] = "'WARNING'", -- a broken or forged signature
                   [9534130] = "'NOTICE'", [9534131] = "'NOTICE'",    -- site policy: unsigned or unverified bots
                   [9534133] = "'NOTICE'", [9534134] = "'NOTICE'" }   -- site policy: a signature or nonce used again
local starters, kinds = 0, {}
for _, f in ipairs({ "wba.conf", "recipes.conf" }) do
    for _, r in ipairs(parsed[f]) do
        if r.actions and not r.child then
            starters, kinds[r.kind] = starters + 1, true
            local where = f .. " rule " .. tostring(r.id)
            H.eq(table.concat(r.has.tag or {}, " "), "'web-bot-auth'", where .. ": tag")
            H.eq(table.concat(r.has.ver or {}, " "), VER, where .. ": ver")
            local logs = r.has.log ~= nil
            H.eq(logs or r.has.nolog ~= nil, true, where .. ": says log or nolog")
            H.eq(table.concat(r.has.severity or {}, " "), logs and (SEVERITY[r.id] or "a severity") or "", where .. ": severity")
        elseif r.actions then
            for _, meta in ipairs({ "id", "tag", "ver", "severity", "msg" }) do
                H.eq(r.has[meta], nil, f .. ": a chained rule carries " .. meta)
            end
        end
    end
end
H.eq(kinds.SecRule and kinds.SecAction and kinds.SecRuleScript and starters >= 19, true, "the rules were parsed (" .. starters .. ")")
local logging = 0
for _ in pairs(SEVERITY) do logging = logging + 1 end
H.pass(("%d rules, SecRule, SecAction and SecRuleScript alike: tag 'web-bot-auth', ver %s; the %d that log have their severity"):format(starters, VER, logging))

-- 4. The on/off switch: tx.web-bot-auth-plugin_enabled=0 skips the plugin in
-- phases 1, 2 and 5 with skipAfter to the phase's marker (skipAfter acts
-- within its own phase, and skips SecAction and SecRuleScript too). Every
-- SecAction and SecRuleScript of the phase sits between the switch and the
-- marker, except phase 1's rule 9534100: the switch comes after it, so every
-- variable still exists (not-signed, n/a) when the plugin is off.
local wba = parsed["wba.conf"]
local function at(pred) for i, r in ipairs(wba) do if pred(r) then return i end end end
for phase, marker in pairs({ [1] = "END-WBA-VERIFY", [2] = "END-WBA-BODY", [5] = "END-WBA-LOG" }) do
    local switches = {}
    for i, r in ipairs(wba) do
        if r.actions and r.text:match('^SecRule%s+TX:web%-bot%-auth%-plugin_enabled%s+"@eq 0"') then
            if r.phase == phase then switches[#switches + 1] = i end
        end
    end
    H.eq(#switches, 1, "phase " .. phase .. ": one switch rule")
    local s = wba[switches[1]]
    H.eq(table.concat(s.has.skipAfter or {}, " "), marker, "phase " .. phase .. ": the switch skips to " .. marker)
    local m = at(function(r) return r.marker == marker end)
    H.eq(m ~= nil and m > switches[1], true, "phase " .. phase .. ": " .. marker .. " comes after the switch")
    for i, r in ipairs(wba) do
        if r.phase == phase and (r.kind == "SecAction" or r.kind == "SecRuleScript") and r.id ~= 9534100 then
            H.eq(i > switches[1] and i < m, true, "phase " .. phase .. ": rule " .. r.id .. " is not skipped by the switch")
        end
    end
end
H.eq(at(function(r) return r.id == 9534100 end) < at(function(r) return r.phase == 1 and r.has and r.has.skipAfter
    and r.text:find("plugin_enabled", 1, true) end), true, "the phase 1 switch comes after rule 9534100")
local setting = text["web-bot-auth-config.conf"]:match("\n(# SecRule &TX:web%-bot%-auth%-plugin_enabled \"@eq 0\" \\\n#[^\n]*)")
H.eq(setting ~= nil and setting:find("setvar:tx.web-bot-auth-plugin_enabled=0", 1, true) ~= nil, true,
    "web-bot-auth-config.conf offers the switch, commented out, set only when unset")
H.pass("tx.web-bot-auth-plugin_enabled=0 skips every SecAction and SecRuleScript in phases 1, 2 and 5, after rule 9534100")

-- 5. The image build stops when the base image's libmodsecurity is not
-- linked against the Lua the Dockerfile builds for (lua-openssl, the module
-- path). The check is the build stage's first RUN, and it is run here as
-- written, against a stand-in ldd that prints what an image would.
local docker = H.read(H.here .. "../wba/Dockerfile"):gsub("\\\n", " ")
local build_stage = docker:match("\nFROM %${CRS_IMAGE} AS build\n(.-)\nFROM ")
local check = build_stage and build_stage:match("^[^\n]*\n?.-RUN%s+([^\n]*)")
H.eq(check ~= nil and check:find("ldd /usr/local/modsecurity/lib/libmodsecurity.so.3", 1, true) ~= nil, true,
    "the build stage's first RUN checks libmodsecurity's Lua")
local want = check:match("liblua(%d+)\\%.(%d+)")
want = want and (want .. "." .. check:match("liblua%d+\\%.(%d+)"))
for what, got in pairs({ ["liblua-dev"] = docker:match("liblua(%d+%.%d+)%-dev"), ["include path"] = docker:match("%-I/usr/include/lua(%d+%.%d+)"),
                         ["test Lua"] = docker:match("LUA=lua(%d+%.%d+)"), ["module path"] = docker:match("/usr/local/lib/lua/(%d+%.%d+)/openssl%.so") }) do
    H.eq(got, want, "the Dockerfile's " .. what .. " is the Lua the check requires")
end
local bin = H.tmp("fake-bin")
assert(H.sh("mkdir -p '" .. bin .. "'"))
H.write(bin .. "/ldd", '#!/bin/sh\n[ "$1" = /usr/local/modsecurity/lib/libmodsecurity.so.3 ] && [ -n "$FAKE_LDD" ] '
    .. '|| { echo "ldd: $1: No such file or directory" >&2; exit 1; }\nprintf "%s\\n" "$FAKE_LDD"\n')
assert(H.sh("chmod +x '" .. bin .. "/ldd'"))
H.write(H.tmp("check.sh"), check .. "\n")
local function build_check(ldd_out)
    local ok = H.sh(("FAKE_LDD='%s' PATH='%s':\"$PATH\" sh '%s' > '%s' 2>&1"):format(ldd_out, bin, H.tmp("check.sh"), H.tmp("check.out")))
    return ok, H.read(H.tmp("check.out"))
end
local function linked(lua) return "\tlibstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f0000000000)\n\tlib" .. lua
    .. ".so.0 => /lib/x86_64-linux-gnu/lib" .. lua .. ".so.0 (0x00007f0000100000)" end
H.eq((build_check(linked("lua" .. want))), true, "linked against Lua " .. want .. ": the build goes on")
for _, other in ipairs({ linked("lua5.4"), linked("lua5.5"), linked("luajit-5.1"), "" }) do
    local ok, out = build_check(other)
    H.eq(ok, false, "the build must stop for: " .. (other ~= "" and other:match("lib(lua[^.]*%.?%d*)") or "no library"))
    H.eq(out:find("not linked against Lua " .. want, 1, true) ~= nil, true, "the build says why: " .. out)
end
H.pass("Dockerfile: the build stops, saying why, unless libmodsecurity links Lua " .. want .. ", the Lua it builds for")

H.done("test_conf")
