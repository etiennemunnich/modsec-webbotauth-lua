-- Wycheproof vectors against crypto.lua over the shipped lua-openssl build.
-- Run inside the image's test stage:
--   lua5.3 lua/tests/wycheproof/run.lua lua/tests/wycheproof/*.tsv
-- One line per file; exit 1 on any disagreement. "acceptable" vectors are
-- counted and either outcome is allowed (Wycheproof's own meaning).
package.path = ((arg[0]:match("(.*/)") or "./") .. "../../?.lua;") .. package.path
local crypto = require("wba.crypto")

local function unhex(h) return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) end

--- A key line's public key, as keys.lua would hold it.
local function entry(ktype, text)
    if ktype == "rsa" then
        local n, e = text:match("^(%x+):(%x+)$")
        return { type = "rsa", n = unhex(n), e = unhex(e) }
    end
    return { type = ktype, key = unhex(text) }
end

local failed = false
for _, path in ipairs(arg) do
    local alg, key, n, bad, counts = nil, nil, 0, {}, { valid = 0, invalid = 0, acceptable = 0 }
    for line in io.lines(path) do
        alg = alg or line:match("^# Wycheproof vectors for (%S+),")
        if line:sub(1, 1) ~= "#" then
            local ktype, text = line:match("^key\t(%S+)\t(%S+)$")
            if ktype then
                key = entry(ktype, text)
            else
                local id, want, msg, sig = line:match("^(%S+)\t(%a+)\t(%x*)\t(%x*)$")
                assert(id and counts[want] and key and alg, "bad vector line: " .. line)
                n = n + 1
                counts[want] = counts[want] + 1
                -- crypto.lua raises on a wrong length or an unusable key: a rejection.
                local ok, got = pcall(crypto.verify, alg, key, unhex(sig), unhex(msg))
                got = ok and got == true
                if (want == "valid" and not got) or (want == "invalid" and got) then bad[#bad + 1] = id end
            end
        end
    end
    print(("wycheproof %s: %d vectors (valid %d, invalid %d, acceptable %d), %d disagreements %s")
        :format(alg, n, counts.valid, counts.invalid, counts.acceptable, #bad, table.concat(bad, " ")))
    if #bad > 0 or n == 0 then failed = true end
end
os.exit(failed and 1 or 0)
