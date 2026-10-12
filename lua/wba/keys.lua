--[[
keys.lua: loads the verifier's key store, the file wba-keysync writes.

The store is data, never code. ModSecurity builds a fresh Lua state for every
request, so nothing can be cached in memory; this small file is read per
request instead. Format (version 2), one key per line, tab-separated:

    # wba-keys v2
    <identifier> TAB <keyid> TAB <type> TAB <alg|-> TAB <public key> TAB <nbf|-> TAB <exp|-> TAB <proof> TAB <proof expires|->

  identifier     the URL the key was resolved from, in normal form (draft 5.5;
                 identifier.lua): https://<host>[:<port>]/.well-known/
                 http-message-signatures-directory for a directory, the
                 jwks_uri or cimd URL otherwise
  keyid          RFC 7638 JWK thumbprint, base64url, 43 characters (draft 5.2:
                 RFC 7638 3.2 for RSA and EC, RFC 8037 A.3 for Ed25519)
  type           ed25519 | ec-p256 | ec-p384 | rsa (algorithms.lua)
  alg            the JWK's alg, an HTTP Signature Algorithms name for this
                 type, or "-" when the JWK has none (RFC 9421 3.2 step 6.3)
  public key     lowercase hex:
                   ed25519  the 32-byte key A (64 hex)
                   ec-*     the SEC1 uncompressed point 04 || x || y (130 or 194 hex)
                   rsa      <n>:<e>, each the minimal big-endian bytes (RFC 7518 2,
                            Base64urlUInt); n of 2048 to 16384 bits and odd, e
                            odd, 3 or more, at most 256 bits (algorithms.lua)
  nbf / exp      optional integer Unix times from the JWK, or "-"
  proof          draft Appendix B possession proof for this key in the
                 directory response key-sync last read: valid, invalid (a
                 signature named this key and failed), or none
  proof expires  the valid proof's expires (5.5.3: valid only until then);
                 "-" unless proof is valid

Version 1 (written by wba-keysync before RSA, ECDSA and proofs) is still
read: its lines are <identifier> <keyid> <Ed25519 key hex> <nbf> <exp>,
every key Ed25519 with no alg and proof none. So a store written before an
upgrade keeps verifying until key-sync rewrites it.

Lines starting with "#" are comments. The first line must be a version
header. Any malformed line rejects the whole file: a partly-corrupt store
means something is wrong, and every signature falls back to "unverified",
never to "verified".
--]]

local algorithms = require("wba.algorithms")
local identifier = require("wba.identifier")

local M = {}

M.HEADER = "# wba-keys v2"
M.HEADER_V1 = "# wba-keys v1"
M.WELL_KNOWN = identifier.WELL_KNOWN

--- The key-directory identifier for an https origin, or nil.
--- strict (a Signature-Agent `directory` member, draft section 5.5): the
--- value must be the ASCII serialization of the origin (RFC 6454 6.2),
--- optionally followed by "/", so an explicit ":443" is refused; the draft
--- says a verifier MUST ignore anything else. Not strict (agents.txt, the
--- key store): ":443" is normalized away. tx.wba_grant_agents is strict on
--- purpose: a grant is an exact match, so it is written as the origin is.
function M.identifier(origin, strict) return identifier.directory(origin, strict) end

--- The identifier of a jwks_uri or cimd member value (draft 5.5), or nil.
M.url_identifier = identifier.url

--- True when `id` is an identifier in normal form (identifier.lua).
M.valid_identifier = identifier.valid

local PROOFS = { valid = true, invalid = true, none = true }

local function time_field(s)
    if s == "-" then return true, nil end
    if not s:match("^[0-9]+$") or #s > 15 then return false end
    return true, math.tointeger(tonumber(s))
end

-- Hex to bytes through a lookup table (gsub with a table runs in C: an RSA
-- modulus is up to 4096 hex digits, and the store is read per request).
local UNHEX = {}
for i = 0, 255 do UNHEX[("%02x"):format(i)] = string.char(i) end
local function unhex(h) return (h:gsub("..", UNHEX)) end

-- Bits in a minimal big-endian hex number (its first byte is not 00).
local function bits(h)
    local top = tonumber(h:sub(1, 2), 16)
    local b = 0
    while top > 0 do b, top = b + 1, top // 2 end
    return (#h // 2 - 1) * 8 + b
end

local function minimal_hex(h)
    return #h % 2 == 0 and #h >= 2 and h:match("^[0-9a-f]+$") and h:sub(1, 2) ~= "00"
end

--- The public key column for a key type, decoded, or nil.
local function public_key(ktype, text)
    if ktype == "ed25519" then
        if #text == 64 and text:match("^[0-9a-f]+$") then return { key = unhex(text) } end
    elseif ktype == "ec-p256" or ktype == "ec-p384" then
        local want = ktype == "ec-p256" and 130 or 194
        if #text == want and text:match("^04[0-9a-f]+$") then return { key = unhex(text) } end
    elseif ktype == "rsa" then
        local n, e = text:match("^([0-9a-f]+):([0-9a-f]+)$")
        if n and minimal_hex(n) and minimal_hex(e)
            and bits(n) >= algorithms.RSA_MIN_BITS and bits(n) <= algorithms.RSA_MAX_BITS
            and tonumber(n:sub(-1), 16) % 2 == 1 -- n is a product of odd primes (RFC 8017 3.1)
            and tonumber(e:sub(-1), 16) % 2 == 1 and bits(e) <= algorithms.RSA_MAX_E_BITS
            and (bits(n) <= algorithms.RSA_LARGE_BITS or bits(e) <= algorithms.RSA_LARGE_MAX_E_BITS)
            and (#e > 2 or tonumber(e, 16) >= 3) then
            return { n = unhex(n), e = unhex(e) }
        end
    end
    return nil
end

--- The header line and only the lines a lookup needs: those whose identifier
--- is want.identifier, or (a url-less signature) whose keyid is want.keyid.
--- Found with plain string.find, so a request naming one agent does not pay
--- to parse every key in the store (it is read again for every ModSecurity
--- run). Matches are exact: the identifier is a whole first field, the keyid a
--- whole second field (checked again when the lines are parsed).
local function select_lines(text, want, index)
    local header = text:match("^[^\n]*")
    -- From a request's second distinct lookup on, one pass indexes every
    -- line by identifier and by keyid (the same lines the finds below take),
    -- so many signatures naming different keys cost one pass, not one each.
    if index then
        index.n = (index.n or 0) + 1
        if index.n > 1 and not index.by_id then
            index.by_id, index.by_keyid = {}, {}
            for line in text:gmatch("\n([^\n]*)") do
                local id, rest = line:match("^([^\t]*)\t(.*)")
                if id then
                    local l = index.by_id[id] or {}
                    l[#l + 1], index.by_id[id] = line, l
                    local kid = rest:match("^([^\t]*)\t")
                    if kid then
                        local k = index.by_keyid[kid] or {}
                        k[#k + 1], index.by_keyid[kid] = line, k
                    end
                end
            end
        end
        if index.by_id then
            local lines = want.identifier and index.by_id[want.identifier] or index.by_keyid[want.keyid]
            return lines and header .. "\n" .. table.concat(lines, "\n") or header
        end
    end
    local out, needle = { header }
    if want.identifier then needle = "\n" .. want.identifier .. "\t" else needle = "\t" .. want.keyid .. "\t" end
    local at = 1
    while true do
        local s = text:find(needle, at, true)
        if not s then break end
        local from = s + 1
        if not want.identifier then
            -- Back to this line's start: one line's bytes, never the store
            -- before it (copying that prefix cost O(store) per keyid).
            from = s - 1
            while from > 0 and text:byte(from) ~= 10 do from = from - 1 end
            from = from + 1
        end
        local to = (text:find("\n", s + 1, true) or #text + 1) - 1
        local line = text:sub(from, to)
        if want.identifier or line:match("^[^\t]*\t([^\t]*)") == want.keyid then out[#out + 1] = line end
        at = to + 1
    end
    return table.concat(out, "\n")
end

--- Parse store text: all of it, or with `want` ({ identifier = id } or
--- { keyid = k }) only the lines that lookup needs; every line kept is
--- checked exactly as in a full parse. key-sync validates the whole store
--- before it replaces the file.
--- @return table|nil store[identifier][keyid] = { type, alg?, key (ed25519
---   and ec: raw bytes) or n, e (rsa: raw big-endian bytes), nbf?, exp?,
---   proof, proof_exp? }, or nil + error. `index`: an optional table kept for
---   one request, so its lookups share one pass over the text.
function M.parse(text, want, index)
    if type(text) ~= "string" then return nil, "no key store" end
    if want then text = select_lines(text, want, index) end
    local store, lineno, version = {}, 0, nil
    for raw_line in (text .. "\n"):gmatch("([^\n]*)\n") do
        lineno = lineno + 1
        local line = raw_line:gsub("\r$", "")
        if not version then
            if line == M.HEADER then version = 2
            elseif line == M.HEADER_V1 then version = 1
            else return nil, "missing version header" end
        elseif line ~= "" and line:sub(1, 1) ~= "#" then
            local where = "line " .. lineno .. ": "
            local id, keyid, ktype, alg, key, nbf_s, exp_s, proof, proof_exp_s
            if version == 2 then
                id, keyid, ktype, alg, key, nbf_s, exp_s, proof, proof_exp_s = line:match(
                    "^([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)$")
                if not id then return nil, where .. "expected 9 tab-separated fields" end
            else
                id, keyid, key, nbf_s, exp_s = line:match("^([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)$")
                if not id then return nil, where .. "expected 5 tab-separated fields" end
                ktype, alg, proof, proof_exp_s = "ed25519", "-", "none", "-"
            end
            if not M.valid_identifier(id) then return nil, where .. "bad identifier" end
            if #keyid ~= 43 or not keyid:match("^[A-Za-z0-9_%-]+$") then return nil, where .. "bad keyid" end
            if alg ~= "-" then
                local a = algorithms.ALGORITHMS[alg]
                if not a or a.key ~= ktype then return nil, where .. "bad alg for key type" end
            end
            local entry = public_key(ktype, key)
            if not entry then return nil, where .. "bad key type or public key" end
            local ok1, nbf = time_field(nbf_s)
            local ok2, exp = time_field(exp_s)
            if not (ok1 and ok2) then return nil, where .. "bad nbf/exp" end
            local ok3, proof_exp = time_field(proof_exp_s)
            if not PROOFS[proof] or not ok3 or (proof == "valid") ~= (proof_exp ~= nil) then
                return nil, where .. "bad proof"
            end
            store[id] = store[id] or {}
            if store[id][keyid] then return nil, where .. "duplicate key" end
            entry.type, entry.nbf, entry.exp, entry.proof, entry.proof_exp = ktype, nbf, exp, proof, proof_exp
            if alg ~= "-" then entry.alg = alg end
            store[id][keyid] = entry
        end
    end
    if not version then return nil, "empty key store" end
    return store
end

--- Read the store at `path`: its text, or nil + error.
function M.read(path)
    local f = io.open(path, "rb")
    if not f then return nil, "key store not readable: " .. path end
    local text = f:read("a")
    f:close()
    return text
end

--- Read and parse the store at `path` (all of it, or what `want` needs).
function M.load(path, want)
    local text, err = M.read(path)
    if not text then return nil, err end
    return M.parse(text, want)
end

return M
