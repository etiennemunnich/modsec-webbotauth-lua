--[[
modsecurity_entry.lua: the SecRuleScript ModSecurity runs (see wba.conf).
Adapts ModSecurity's `m` API to verify.lua and writes the outcome:

  tx.wba_status  verified | invalid | unverified | not-signed
  tx.wba_reason  machine-readable reason (README.md)
  and ONLY when verified (wba.conf rule 1 sets each to "n/a" first, and
  tx.wba_granted to 0):
  tx.wba_agent, tx.wba_agents  identifier URL(s) (draft 5.5); "n/a" when URL-less
  tx.wba_agent_proof  the directory's Appendix B possession proof for the key:
                 valid, invalid, expired or none; "n/a" when URL-less
  tx.wba_keyid   JWK thumbprint
  tx.wba_label, tx.wba_created, tx.wba_expires  the signature's label and window
  tx.wba_covered component names it covered, space-separated
  tx.wba_sighash hex SHA-256 of the signature bytes (never the signature)
  tx.wba_granted 1 when the agent is in tx.wba_grant_agents and the signature
                 covered every component in tx.wba_grant_require_components
                 (@method @path by default; @target-uri counts as @path)
  tx.wba_uses, tx.wba_nonce_uses  with replay accounting on (tx.wba_replay_dir):
                 this host's count of the signed statement, and of its nonce
                 if it has one, this request included (replay.lua); with
                 several verified signatures, every one is counted and the
                 highest count is reported

Operator settings come from web-bot-auth-config.conf through TX variables,
read by fixed name: tx.wba_site_names, tx.wba_grant_agents,
tx.wba_grant_require_components, tx.wba_require_components,
tx.wba_max_window, tx.wba_max_age, tx.wba_expiry_grace, tx.wba_malformed,
tx.wba_require_nonce, tx.wba_strict_field_lines, tx.wba_replay_dir.
tx.wba_site_names has no default: until it lists this site's own host names,
no signed request is verified (unverified/no-site-names). A malformed value makes every signed request
unverified/bad-config, and is logged: a typo never becomes a silent default.

Engine facts this file is built around (libmodsecurity v3, src/engine/lua.cc
and src/variables/variable.h, confirmed in a live owasp/modsecurity-crs:nginx
container):
  * Every run gets a fresh lua_State, so the requires below, and the key-store
    read, happen per request. Nothing survives between requests.
  * m.getvar() with an unknown collection name throws a C++ exception that
    nothing catches: the nginx worker aborts. So no request-derived string is
    ever passed to m.getvar(); headers come from ONE fixed m.getvars() call.
  * REQUEST_URI is percent-decoded; RFC 9421 @path/@query need the raw form,
    so they come from REQUEST_URI_RAW.
  * Phase 2 rules run only when the body was read (transaction.cc
    processRequestBody returns before evaluating them when request body
    access is off), and REQUEST_BODY is then the raw body whatever the body
    processor. INBOUND_DATA_ERROR=1 marks a body cut at SecRequestBodyLimit.

Two runs per digest-bound request (wba.conf): phase 1 (headers), and phase 2
(tx.wba_stage=body) only when phase 1 left tx.wba_reason=digest-pending.
Phase 2 re-verifies everything with the body, at the phase-1 time.

Configuration: edit CONFIG below. Tests (and only tests) may predefine the
global WBA_CONFIG instead.
--]]

local CONFIG = WBA_CONFIG or {
    lua_path = "/etc/modsecurity.d/wba/lua/?.lua",       -- where wba/*.lua live
    keys_path = "/etc/modsecurity.d/wba/keys/wba-keys.tsv", -- written by wba-keysync; mount the DIRECTORY
    scheme = "https",  -- scheme clients use to reach this site (default port + @target-uri)
    policy = {},       -- overrides for verify.DEFAULT_POLICY
}

package.path = CONFIG.lua_path .. ";" .. package.path

local verify = require("wba.verify")
local keys = require("wba.keys")
local components = require("wba.components")
local sha256 = require("wba.sha256")
-- lua-openssl, loaded with this chunk: if it cannot load, main() is never
-- defined and wba.conf rule 3's unverified/engine-error stands.
local crypto = require("wba.crypto")
local replay = require("wba.replay")

local HASH = { ["sha-256"] = sha256.digest, ["sha-512"] = crypto.sha512 }

local DEFAULT_PORT = { https = "443", http = "80" }

--- Host header -> RFC 9421 @authority (2.2.3, normalized per RFC 9110
--- 4.2.3): lowercase; a port that is empty or the scheme's default removed
--- (RFC 3986 6.2.3).
local function normalize_authority(host, scheme)
    local h = verify.ascii_lower(verify.trim_ows(host))
    local name, port = h:match("^(.*):([0-9]*)$")
    if name and (port == "" or port == DEFAULT_PORT[scheme]) then
        return name
    end
    return h
end

local function build_request(body_stage)
    local fields = {}
    for _, h in ipairs(m.getvars("REQUEST_HEADERS") or {}) do
        local name = h.name:match("^REQUEST_HEADERS:(.+)$")
        if name then
            name = verify.ascii_lower(name)
            local list = fields[name]
            if not list then
                list = {}
                fields[name] = list
            end
            list[#list + 1] = h.value
        end
    end

    -- Exactly one Host header, or @authority is unavailable (invalid).
    local authority
    if fields["host"] and #fields["host"] == 1 then
        authority = normalize_authority(fields["host"][1], CONFIG.scheme)
    end

    -- Origin-form request target only; anything else leaves @path unavailable.
    local path, query
    local raw = m.getvar("REQUEST_URI_RAW") or ""
    if raw:sub(1, 1) == "/" then
        local q = raw:find("?", 1, true)
        if q then
            path, query = raw:sub(1, q - 1), raw:sub(q + 1)
        else
            path = raw
        end
    end

    -- REQUEST_BODY arrives byte for byte, NUL bytes included (lua.cc pushes
    -- variables with lua_pushlstring), and still in its content coding:
    -- ModSecurity never removes Content-Encoding. digest.lua decodes it for
    -- Unencoded-Digest only, within policy.max_decoded_body.
    local body
    if body_stage then
        local data, complete
        body = function()
            if data == nil then
                data = m.getvar("REQUEST_BODY") or "" -- unset when empty
                complete = m.getvar("INBOUND_DATA_ERROR") ~= "1"
            end
            return data, complete
        end
    end

    return {
        fields = fields,
        method = m.getvar("REQUEST_METHOD"),
        authority = authority,
        path = path,
        query = query,
        scheme = CONFIG.scheme,
        body = body,
    }
end

local function component_name(name)
    return name:match(components.FIELD_NAME) or name:match("^@[a-z-]+$")
end

--- Operator settings (web-bot-auth-config.conf), read through fixed names:
--- m.getvar never sees a name built from the request.
--- @return policy table, grants set, the replay directory (or nil) and the
---   components a grant needs, or nil and what is wrong
local function settings()
    local pol = {}
    for k, v in pairs(CONFIG.policy) do pol[k] = v end
    -- The site's own names, as @authority values (normalized like the Host
    -- header): a signature for any other name was made for another site.
    pol.authorities = false
    local names = m.getvar("TX.wba_site_names")
    if names ~= nil and names ~= "" then
        pol.authorities = {}
        for name in names:gmatch("%S+") do
            local host = name:match("^%[[%x:.]+%]") or name:match("^[%w.-]+")
            local rest = host and name:sub(#host + 1)
            if not host or not (rest == "" or rest:match("^:%d+$")) then
                return nil, "tx.wba_site_names: not a host name or host:port: " .. name
            end
            pol.authorities[normalize_authority(name, CONFIG.scheme)] = true
        end
    end
    local function seconds(var, key, max)
        local v = m.getvar(var)
        if v == nil or v == "" then return true end
        if not v:match("^%d%d?%d?%d?%d?%d?$") or (max and tonumber(v) > max) then
            return nil, var:lower() .. " must be a number of seconds" .. (max and (" from 0 to " .. max) or "") .. ": " .. v
        end
        pol[key] = tonumber(v)
        return true
    end
    local ok, err = seconds("TX.wba_max_age", "max_age")
    if not ok then return nil, err end
    if pol.max_age == 0 then pol.max_age = false end -- 0 turns the age limit off
    ok, err = seconds("TX.wba_expiry_grace", "expiry_grace", 60)
    if not ok then return nil, err end
    local malformed = m.getvar("TX.wba_malformed")
    if malformed ~= nil and malformed ~= "" then
        if malformed ~= "ignore" and malformed ~= "reject" then
            return nil, "tx.wba_malformed must be ignore or reject: " .. malformed
        end
        pol.malformed = malformed
    end
    local window = m.getvar("TX.wba_max_window")
    if window ~= nil and window ~= "" then
        if not window:match("^[1-9]%d?%d?%d?%d?%d?%d?%d?%d?$") then
            return nil, "tx.wba_max_window must be a positive number of seconds"
        end
        pol.max_window = tonumber(window)
    end
    local required = m.getvar("TX.wba_require_components")
    if required ~= nil and required ~= "" then
        pol.require_components = {}
        for name in required:gmatch("%S+") do
            if not component_name(name) then
                return nil, "tx.wba_require_components: not a component name: " .. name
            end
            pol.require_components[#pol.require_components + 1] = name
        end
    end
    -- Exact match on the identifier, never a substring or prefix:
    -- "https://agent.ex" must not grant https://agent.example. An entry is a
    -- directory's origin, or a jwks_uri / cimd identifier written exactly in
    -- its normal form (no query, no fragment).
    local grants = {}
    for entry in (m.getvar("TX.wba_grant_agents") or ""):gmatch("%S+") do
        local id = keys.identifier(entry, true)
        if not id and keys.url_identifier(entry) == entry then id = entry end
        if not id then return nil, "tx.wba_grant_agents: not an https origin (no port, no path) or identifier: " .. entry end
        grants[id] = true
    end
    -- A grant unlocks something, so the signature must say what it was for:
    -- one that covers only @authority verifies against any method and path of
    -- the site (draft 5.2) and would make the grant a bearer token.
    local grant_needs = { "@method", "@path" }
    local needs = m.getvar("TX.wba_grant_require_components")
    if needs ~= nil and needs ~= "" then
        grant_needs = {}
        if needs ~= "none" then
            for name in needs:gmatch("%S+") do
                if not component_name(name) then
                    return nil, "tx.wba_grant_require_components: not a component name: " .. name
                end
                grant_needs[#grant_needs + 1] = name
            end
        end
    end
    for _, s in ipairs({ { "TX.wba_require_nonce", "require_nonce" }, { "TX.wba_strict_field_lines", "strict_field_lines" } }) do
        local v = m.getvar(s[1])
        if v ~= nil and v ~= "" then
            if v ~= "0" and v ~= "1" then return nil, s[1]:lower() .. " must be 0 or 1: " .. v end
            pol[s[2]] = v == "1"
        end
    end
    -- An absolute path in a conservative alphabet, with no empty, "." or
    -- ".." segment; it names a directory the nginx workers can write
    -- (README, Replay accounting).
    local dir = m.getvar("TX.wba_replay_dir")
    if dir == "" then dir = nil end
    if dir then
        local padded = dir .. "/"
        if not dir:match("^/[%w._/-]*[%w._-]$") or padded:find("//", 1, true)
            or padded:find("/%.%.?/") then
            return nil, "tx.wba_replay_dir must be an absolute directory path: " .. dir
        end
        pol.replay_keys = true
    end
    return pol, grants, dir, grant_needs
end

--- True when the signature covered every component a grant needs; the full
--- @target-uri includes the path, so it counts as @path.
local function covers_all(covered, needs)
    local have = {}
    for _, name in ipairs(covered) do have[name] = true end
    for _, name in ipairs(needs) do
        if not (have[name] or (name == "@path" and have["@target-uri"])) then return false end
    end
    return true
end

function main()
    local ok, err = pcall(function()
        -- Phase 2 (rule 9534105 sets tx.wba_stage=body) only finishes a
        -- signature that phase 1 left digest-pending; any other outcome was
        -- decided in phase 1 and stands. Rule 9534104 normally skips phase 2
        -- then, but an operator's ctl:ruleRemoveById removes only SecRule
        -- rules: in libmodsecurity v3, rule 9534105 and this script still run.
        local body_stage = m.getvar("TX.wba_stage") == "body"
        if body_stage and m.getvar("TX.wba_reason") ~= "digest-pending" then return end
        local text, read_err -- the file is read once per request, at most
        local index = {} -- and indexed once, if a second lookup comes (keys.parse)
        local function load_store(want) -- called only if a signature reaches key lookup
            if text == nil then text, read_err = keys.read(CONFIG.keys_path) end
            local store, store_err
            if text then store, store_err = keys.parse(text, want, index) else store_err = read_err end
            if not store then
                m.log(2, "[wba] key store unavailable: " .. tostring(store_err))
            end
            return store
        end
        local policy, grants, replay_dir, grant_needs = settings()
        if not policy then
            m.log(2, "[wba] bad configuration: " .. grants)
            m.setvar("tx.wba_reason", "bad-config")
            m.setvar("tx.wba_status", "unverified")
            return
        end
        local now = os.time()
        if body_stage then
            -- m.getvar returns no value at all (not nil) for an unset
            -- variable, and tonumber() given no value raises: read it first.
            local t = m.getvar("TX.wba_time")
            now = tonumber(t) or now
        end
        local r = verify.verify(build_request(body_stage), load_store, now, crypto.verify, policy, HASH)
        if r.reason == "digest-pending" then m.setvar("tx.wba_time", tostring(now)) end
        -- Replay accounting counts a request once, at its final decision: a
        -- verified outcome happens in phase 1 or in phase 2, never both.
        -- Every verified signature is counted, not only the one reported:
        -- otherwise each extra signature in a captured request is a free use.
        local uses, nonce_uses
        if r.status == "verified" and replay_dir then
            local failed = #(r.replay or {}) == 0
            local why = failed and "no verified signature to count" or nil
            uses = 0
            for _, k in ipairs(r.replay or {}) do
                local n
                n, why = replay.count(replay_dir, "s", k.basehash, k.last)
                if not n then failed = true break end
                if n > uses then uses = n end
                if k.noncehash then
                    n, why = replay.count(replay_dir, "n", k.noncehash)
                    if not n then failed = true break end
                    if not nonce_uses or n > nonce_uses then nonce_uses = n end
                end
            end
            if failed then
                -- Fail closed, as for a key store that cannot be read: a
                -- count that cannot be kept never passes for a fresh one.
                m.log(2, "[wba] replay accounting unavailable: " .. tostring(why))
                r = { status = "unverified", reason = "replay-unavailable" }
            end
        end
        if r.status == "verified" then
            if uses then m.setvar("tx.wba_uses", tostring(uses)) end
            if nonce_uses then m.setvar("tx.wba_nonce_uses", tostring(nonce_uses)) end
            -- URL-less (draft 4.3): no directory to name, only the key.
            if r.agent then
                m.setvar("tx.wba_agent", r.agent)
                m.setvar("tx.wba_agent_proof", r.proof)
            end
            if #r.agents > 0 then m.setvar("tx.wba_agents", table.concat(r.agents, " ")) end
            m.setvar("tx.wba_keyid", r.keyid)
            m.setvar("tx.wba_label", r.label)
            m.setvar("tx.wba_created", tostring(r.created))
            m.setvar("tx.wba_expires", tostring(r.expires))
            -- Safe to log as is: a covered name that is not an RFC 9110
            -- token or a registered @name never verifies (components.lua,
            -- unsupported-component).
            m.setvar("tx.wba_covered", table.concat(r.covered, " "))
            m.setvar("tx.wba_sighash", r.sighash)
            if r.agent and grants[r.agent] and covers_all(r.covered, grant_needs) then m.setvar("tx.wba_granted", "1") end
        end
        -- Status last: if anything above raised, the handler below decides it.
        m.setvar("tx.wba_reason", r.reason)
        m.setvar("tx.wba_status", r.status)
    end)
    if not ok then
        m.log(2, "[wba] internal error: " .. tostring(err))
        m.setvar("tx.wba_status", "unverified")
        m.setvar("tx.wba_reason", "internal-error")
    end
    return nil -- no match: this rule only sets tx.wba_*; policy rules read them
end
