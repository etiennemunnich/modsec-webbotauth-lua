-- luacheck (.githooks/scan.ts runs it on the Lua files a commit holds).
std = "lua53"            -- the CRS image runs Lua 5.3
max_line_length = false

-- ModSecurity calls main() and provides m; tests may predefine the CONFIG.
files["lua/wba/modsecurity_entry.lua"] = { globals = { "main" }, read_globals = { "m", "WBA_CONFIG" } }
files["lua/wba/wba_log.lua"] = { globals = { "main" }, read_globals = { "m", "WBA_LOG_CONFIG" } }

-- Tests load those scripts and call their main(). Reusing a name in an inner
-- scope is normal in a test file, so shadowing (4xx) is not reported there.
files["lua/tests"] = { globals = { "main", "m", "WBA_CONFIG", "WBA_LOG_CONFIG" }, ignore = { "4.." } }
