#!/usr/bin/env bash
# mutants.sh: proves the Lua suites can fail. Each mutant re-introduces a bug
# found in the previous version of this verifier into a temporary copy; the
# suite named must reject it. A mutation that no longer applies (the code it
# targets changed) is a failure too, so this cannot pass silently.
#   lua/tests/mutants.sh            every mutant; crypto.lua's are reported as
#                                   SKIP unless lua-openssl loads here
#   lua/tests/mutants.sh --crypto   crypto.lua's mutants only, and lua-openssl
#                                   must load (the image's test stage runs this)
#   JOBS=2 lua/tests/mutants.sh     the same mutants in 2 shards at once (CI
#                                   uses the runner's 2 vCPUs); each mutant runs
#                                   in exactly one shard, by its place in this file
set -uo pipefail
LUA=${LUA:-lua}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
FAIL=0
CRYPTO_ONLY=0
[ "${1:-}" = "--crypto" ] && CRYPTO_ONLY=1
HAVE_OPENSSL=0
"$LUA" -e 'require "openssl"' >/dev/null 2>&1 && HAVE_OPENSSL=1
if [ "$CRYPTO_ONLY" = 1 ] && [ "$HAVE_OPENSSL" = 0 ]; then
  echo "FAIL  --crypto: lua-openssl does not load (LUA_CPATH?)"; exit 1
fi

JOBS=${JOBS:-1}
if [ -z "${SHARD:-}" ] && [ "$JOBS" -gt 1 ]; then
  out=$(mktemp -d) rc=0 pids=()
  for ((i = 0; i < JOBS; i++)); do
    SHARD=$i/$JOBS bash "${BASH_SOURCE[0]}" "$@" > "$out/$i" 2>&1 & pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  cat "$out"/*
  echo "== $JOBS shards: $(cat "$out"/* | grep -c '^PASS  caught') planted bugs caught, $(cat "$out"/* | grep -c '^SKIP') skipped"
  rm -rf "$out"
  [ "$rc" = 0 ] && echo "== every planted bug caught" || echo "== MUTATION CHECK FAILED"
  exit "$rc"
fi
N=0
mine() { # this shard's turn? Every mutant counts, run or not, so shards never overlap.
  N=$((N + 1))
  [ -z "${SHARD:-}" ] || [ $(((N - 1) % ${SHARD#*/})) = "${SHARD%/*}" ]
}

mutant() { # description, file, perl substitution, test suite
  mine || return 0
  run_mutant "$@"
}
run_mutant() {
  local tmp; tmp=$(mktemp -d)
  cp -R "$REPO/lua" "$tmp/"
  perl -pi -e "$3" "$tmp/lua/wba/$2"
  if cmp -s "$REPO/lua/wba/$2" "$tmp/lua/wba/$2"; then
    echo "FAIL  mutation did not apply: $1"; FAIL=1
  elif "$LUA" "$tmp/lua/tests/test_$4.lua" >/dev/null 2>&1; then
    echo "FAIL  survived: $1"; FAIL=1
  else
    echo "PASS  caught: $1"
  fi
  rm -rf "$tmp"
}

# crypto.lua runs lua-openssl, so only its own suites (test_crypto, test_sha256
# with WBA_REQUIRE_OPENSSL) can catch these, where the module loads.
crypto_mutant() {
  mine || return 0
  if [ "$HAVE_OPENSSL" = 1 ]; then run_mutant "$@"; else echo "SKIP  needs lua-openssl (run in the image's test stage): $1"; fi
}

if [ "$CRYPTO_ONLY" = 0 ]; then
mutant "string params serialized without quotes (old nonce bug)" structured_fields.lua \
  's/^(\s*)return .*%0.*$/$1return v.value/' verify
mutant "@authority coverage not required" verify.lua \
  's/if not binds_authority then return/if false then return/' verify
mutant "expiry never enforced" verify.lua \
  's/if now >= e \+ \(policy\.expiry_grace or 0\) then/if false then/' verify
mutant "expiry grace taken from the clock skew (60 s, not strict)" verify.lua \
  's/now >= e \+ \(policy\.expiry_grace or 0\)/now >= e + policy.clock_skew/' verify
mutant "max age not enforced (a day-old signature verifies)" verify.lua \
  's/if policy\.max_age and now - c > policy\.max_age then/if false then/' verify
mutant "expires at or before created accepted" verify.lua \
  's/if e <= c then return result\("invalid", "bad-param"\) end/-- removed/' verify
mutant "a created in the future accepted (not-yet-valid)" verify.lua \
  's/if c > now \+ policy\.clock_skew then return result\("invalid", "not-yet-valid"\) end/-- removed/' verify
mutant "a keyid that is not a 43-character thumbprint accepted" verify.lua \
  's/if #keyid\.value ~= 43 or not keyid\.value:match/if false and keyid.value:match/' verify
mutant "test keys accepted (draft 6.8)" verify.lua \
  's/if policy\.reject_test_keys and M\.TEST_KEY_THUMBPRINTS\[keyid\.value\] then/if false then/' verify
mutant "any tag accepted as web-bot-auth" verify.lua \
  's/if tag and tag\.type == "string" and tag\.value == TAG then/if tag then/' verify
mutant "a Signature member that is not a Byte Sequence used (RFC 9421 4.2)" verify.lua \
  's/if not sig_member or sig_member\.kind ~= "item" or sig_member\.value\.type ~= "binary"/if not sig_member/' verify
mutant "a day's window cap by default even with max_age on (draft 5.2 is advice to signers)" verify.lua \
  's/if window == nil and not policy\.max_age then window = 86400 end/if window == nil then window = 86400 end/' verify
mutant "no window cap with max_age off" verify.lua \
  's/if window == nil and not policy\.max_age then window = 86400 end/if false then window = 86400 end/' verify
mutant "site names not checked (cross-site replay)" verify.lua \
  's/if pol\.authorities and req\.authority and not pol\.authorities\[req\.authority\] then/if false then/' verify
mutant "@target-uri does not meet a required @path (unlike a grant)" verify.lua \
  's/if not \(has\[name\] or \(name == "\@path" and has\["\@target-uri"\]\)\) then/if not has[name] then/' verify
mutant "a non-origin http directory member is invalid, not ignored (draft 5.5)" verify.lua \
  's/if kind == "directory" and not keys\.identifier\("https" \.\. value:sub\(#scheme \+ 1\), true\) then/if false then/' verify
mutant "an http origin directory member is ignored, not invalid (draft 5.2.1)" verify.lua \
  's/if kind == "directory" and not keys\.identifier\("https" \.\. value:sub\(#scheme \+ 1\), true\) then/if true then/' verify
mutant "the @query-param spelling retry is not capped per request" verify.lua \
  's/local alt_base = spaced and not memo\.query_alt and sigbase/local alt_base = spaced and sigbase/' verify
mutant "no site names configured, yet signatures verify" verify.lua \
  's/if pol\.authorities == false then return result\("unverified", "no-site-names"\) end/do end/' verify
mutant "an unparsable field always malformed (a 400 for ActivityPub)" verify.lua \
  's/if pol\.malformed == "reject" then return result\("invalid", "malformed-headers"\) end/do return result("invalid", "malformed-headers") end/' verify
mutant "identity returned on a failed signature" verify.lua \
  's/return result\("invalid", "bad-signature"\) end$/return result("invalid", "bad-signature", { agent = identifier, keyid = keyid.value }) end/' verify
mutant "keys looked up by keyid alone" verify.lua \
  's/local agent_keys = store\[identifier\]/local agent_keys = select(2, next(store))/' verify
mutant "only the first signature checked" verify.lua \
  's/^(\s*)if best == nil or rank\(r\) > rank\(best\) then best = r end$/$1if best == nil or rank(r) > rank(best) then best = r end\n$1break/' verify
mutant "stops at the first verified signature (draft 5.2.2: validate each)" verify.lua \
  's/^(\s*)if best == nil or rank\(r\) > rank\(best\) then best = r end$/$1if best == nil or rank(r) > rank(best) then best = r end\n$1if r.status == "verified" then break end/' verify
mutant "request-derived name passed to m.getvar" modsecurity_entry.lua \
  's/method = m\.getvar\("REQUEST_METHOD"\),/method = m.getvar("REQUEST_HEADERS:" .. (fields["x-probe"] and "a.b" or "host")),/' entry
mutant "@path from the decoded URI" modsecurity_entry.lua \
  's/local raw = m\.getvar\("REQUEST_URI_RAW"\) or ""/local raw = (m.getvar("REQUEST_URI_RAW") or ""):gsub("%%3F", "?")/' entry

mutant "@query treated as absent for a non-origin-form target" components.lua \
  's/if path ~= nil then v = "\?" \.\. \(req\.query or ""\) end/v = "?" .. (req.query or "")/' verify
mutant "non-ASCII component values allowed" sigbase.lua \
  's/c\.value:find\(derived and "\[\^\\32-\\126\]" or "\[\^\\9\\32-\\126\]"\)/c.value:find("[\\r\\n]")/' verify

# Found by the final review.
mutant "backtracking (quadratic) whitespace trim" components.lua \
  's/^(\s*)local i = s:find\("\[\^ \\t\]"\)$/$1do return (s:match("^[ \\t]*(.-)[ \\t]*\$")) end\n$1local i = s:find("[^ \\t]")/' verify
mutant "locale-dependent lowercase" components.lua \
  's/return \(s:gsub\("\[A-Z\]".*$/return (s:lower())/' verify
mutant "any request with two covered Signature-Agent members refused (misses draft D.2)" verify.lua \
  's/^(\s*)local want$/$1local want if count > 1 then return nil, "invalid", "ambiguous-agent" end/' verify
mutant "attributed to the last covered member, not the label's" verify.lua \
  's/^(\s*)want = label$/$1want = only or label/' verify
mutant "key store read before the Signature member is checked" verify.lua \
  's/^(\s*)if not sig_member or sig_member\.kind ~= "item"/$1if store() and not sig_member or sig_member.kind ~= "item"/' verify

# RFC 9651 conformance (caught by the HTTP WG corpus).
mutant "decimal rounding half-up instead of half-to-even" structured_fields.lua \
  's/or n % 2 == 1\)\)/or true))/' sf_corpus
mutant "duplicate dictionary key keeps the first value" structured_fields.lua \
  's/^(\s*)map\[key\] = member$/$1if map[key] == nil then map[key] = member end/' sf_corpus
mutant "display string accepts invalid UTF-8" structured_fields.lua \
  's/if not M\.valid_utf8\(bytes\) then fail/if false then fail/' sf_corpus
# The UTF-8 guards the HTTP WG corpus never reaches: an overlong E0 form, a
# code point above U+10FFFF, a later byte that is not a continuation byte.
mutant "display string: overlong E0 form accepted (E0 80-9F)" structured_fields.lua \
  's/need, lo = 2, 0xA0/need, lo = 2, 0x80/' structured_fields
mutant "display string: F4 above U+10FFFF accepted (F4 90-BF)" structured_fields.lua \
  's/need, hi = 3, 0x8F/need, hi = 3, 0xBF/' structured_fields
mutant "display string: a third or fourth byte that is not a continuation byte accepted" structured_fields.lua \
  's/elseif b < 0x80 or b > 0xBF then/elseif false then/' structured_fields

# RFC 9421 components (caught by the RFC examples and the URLSearchParams vectors).
mutant "@query-param accepts a repeated name" components.lua \
  's/if not e or e\.count ~= 1 then/if not e then/' components
mutant "@query-param with a parameter other than name read as name alone" components.lua \
  's/^(\s*)other = true$/$1other = false/' components
mutant "@query-param leaves !()~ unencoded" components.lua \
  's/\[\^A-Za-z0-9\*%-\._\]/[^A-Za-z0-9*%-._!()~]/' components
mutant "@query-param: a %20-spelled name is not the same name (RFC 9421 2.2.8 example)" components.lua \
  's/local spaced = name:find\("%20", 1, true\) ~= nil/local spaced = false/' components
mutant "@query-param: the %20 spelling of a space is never tried (RFC 9421 2.2.8 example)" verify.lua \
  's/local alt_base = spaced and not memo\.query_alt and sigbase\.build\(alt, p, memo\)/local alt_base = false/' verify
mutant "UTF-8 replacement consumes the unexpected byte" components.lua \
  's/i = i \+ 1 \+ seen$/i = i + 1 + math.max(need, seen)/' components
mutant ";sf guesses Dictionary for a field of unknown type" components.lua \
  's/if not ftype then return nil, "unsupported-component" end/ftype = ftype or "dictionary"/' components

# Draft and RFC 9421 outcome rules (caught by the negative vectors and test_verify).
mutant "non-https Signature-Agent treated as ignorable (unverified)" verify.lua \
  's/return nil, "invalid", "agent-not-https"/return nil, "unverified", "bad-agent-url"/' negative_vectors
mutant "a signature over Content-Digest verifies without the body" digest.lua \
  's/^M\.FIELDS = \{.*$/M.FIELDS = {}/' negative_vectors

# Cost and outcome rules (caught by test_verify's cost budgets for hundreds
# of components over large fields, test_components and the negative vectors).
mutant "per-request memo disabled (cost = components x field size)" components.lua \
  's/local m = MEMO\[req\]$/local m = nil/' verify
mutant "backtracking obs-fold regex" components.lua \
  's/if not v:find\("\\n", 1, true\) then return v end/do return (v:gsub("[ \\t]*\\r\\n[ \\t]+", " ")) end/' verify
mutant "repeated components derived before they are refused" verify.lua \
  's/if seen\[id\] then return result\("invalid", "duplicate-component"\) end/-- removed/' verify
mutant ";key allowed on a field typed as a List or Item" components.lua \
  's/if known and known ~= "dictionary" then return nil, "unsupported-component" end/-- removed/' components
mutant "absent Signature-Agent treated as invalid (draft 4.3)" verify.lua \
  's/if agent_field == nil then return URL_LESS end/if agent_field == nil then return nil, "invalid", "agent-not-covered" end/' negative_vectors

# RFC 9530 body digests (caught by test_verify, test_entry and test_sha256).
mutant "an uncovered digest member is trusted" digest.lua \
  's/and \(members == true or members\[a\]\) and/and/' verify
mutant "the weakest covered algorithm is checked" digest.lua \
  's/^M\.PREFERENCE = \{ "sha-512", "sha-256" \}/M.PREFERENCE = { "sha-256", "sha-512" }/' verify
mutant "a truncated body is compared" digest.lua \
  's/if not complete then return "unverified", "body-incomplete" end/-- removed/' verify
mutant "Unencoded-Digest compared over the coded bytes" digest.lua \
  's/if codings and #codings == 0 then codings = nil end/codings = nil/' verify
mutant "a pending signature ranked below an invalid one" verify.lua \
  's/if r\.reason == "digest-pending" then return 3 end/-- removed/' verify
mutant "phase 2 judges freshness at its own time" modsecurity_entry.lua \
  's/now = tonumber\(t\) or now/now = now/' entry
mutant "phase 2 raises when tx.wba_time is unset (m.getvar gives no value to tonumber)" modsecurity_entry.lua \
  's/now = tonumber\(t\) or now/now = tonumber(m.getvar("TX.wba_time")) or now/' entry
mutant "phase 2 verifies again after phase 1 decided (ctl:ruleRemoveById leaves the script running)" modsecurity_entry.lua \
  's/if body_stage and m\.getvar\("TX\.wba_reason"\) ~= "digest-pending" then return end/-- removed/' entry
mutant "each signature hashes the body again" digest.lua \
  's/cache\[key\] = cache\[key\] or hash/cache[key] = hash/' verify
mutant "the SHA-256 size cap also applies to SHA-512" digest.lua \
  's/elseif c\.alg == "sha-256" and policy\.max_sha256_body and/elseif policy.max_sha256_body and/' verify

# RFC 9530 3 / RFC 9110 14.4, 14.5: partial content (caught by test_verify).
mutant "Content-Range honoured on every method (14.4: MUST ignore)" digest.lua \
  's/if range == nil or req\.method ~= "PUT" then return false end/if range == nil then return false end/' verify
mutant "Content-Range ignored on PUT as well" digest.lua \
  's/if range == nil or req\.method ~= "PUT" then return false end/do return false end/' verify
mutant "any PUT range taken as the whole representation" digest.lua \
  's/if first == 0 and last and length and length == last \+ 1 then return false, length end/do return false end/' verify
mutant "a whole-representation range not held to the content length" digest.lua \
  's/if c\.length and #body ~= c\.length then/if false then/' verify

# Unencoded-Digest over coded bodies (caught by test_verify and test_coding).
mutant "x-gzip not taken as gzip (RFC 9110 8.4.1.3)" digest.lua \
  's/if c == "x-gzip" then c = "gzip" end/-- removed/' verify
mutant "content codings compared case-sensitively" digest.lua \
  's/c = components\.ascii_lower\(c\)/-- removed/' verify
mutant "identity treated as a coding" digest.lua \
  's/if c ~= "identity" then/if true then/' verify
mutant "a body that is not its coding taken as unverified" digest.lua \
  's/if d\.kind == "corrupt" then return nil, "invalid", "bad-content-coding" end/-- removed/' verify
mutant "decoded before the received bytes are checked (draft 7)" digest.lua \
  's/for pass = 1, 2 do/for pass = 2, 1, -1 do/' verify
mutant "the body decoded once per signature" digest.lua \
  's/local d = cache\.decoded$/local d = nil/' verify
mutant "decoding not bounded by max_decoded_body" digest.lua \
  's/local budget = policy\.max_decoded_body or math\.maxinteger/local budget = math.maxinteger/' verify
mutant "decoding not bounded by max_decode_ratio" digest.lua \
  's/if policy\.max_decode_ratio and policy\.max_decode_ratio \* #body < budget then/if false then/' verify
mutant "stacked codings removed in the order listed" coding.lua \
  's/for i = #codings, 1, -1 do/for i = 1, #codings do/' coding
mutant "literals not counted against the budget" coding.lua \
  's/if o >= lim then fail\("limit", "decoded size"\) end/-- removed/' coding
mutant "matches not counted against the budget" coding.lua \
  's/if o \+ len > lim then fail\("limit", "decoded size"\) end/-- removed/' coding
mutant "blocks cost nothing" coding.lua \
  's/limit = limit - \(kind == 2 and M\.DYNAMIC_BLOCK_COST or M\.BLOCK_COST\)/limit = limit/' coding
mutant "a dynamic block costs what a stored one does" coding.lua \
  's/kind == 2 and M\.DYNAMIC_BLOCK_COST or M\.BLOCK_COST/M.BLOCK_COST/' coding
mutant "an FHCRC header costs nothing" coding.lua \
  's/b\.left = b\.left - \(pos - start\)/b.left = b.left/' coding
mutant "gzip CRC-32 not checked" coding.lua \
  's/if u32le\(src, pos\) ~= crc then fail/if false then fail/' coding
mutant "gzip ISIZE not checked" coding.lua \
  's/if u32le\(src, pos \+ 4\) ~= size & 0xffffffff then fail/if false then fail/' coding
mutant "gzip FHCRC not checked" coding.lua \
  's/if \(h1 \| \(h2 << 8\)\) ~= crc32\(0, src, start, pos - 1\) & 0xffff then/if false then/' coding
mutant "reserved gzip flags ignored" coding.lua \
  's/if flg & 0xe0 ~= 0 then fail/if false then fail/' coding
mutant "only the first gzip member decoded, the rest ignored" coding.lua \
  's/until pos > n$/until true/' coding
mutant "zlib Adler-32 not checked" coding.lua \
  's/~= a then fail\("corrupt", "incorrect data check"\) end/~= a and false then fail("corrupt", "incorrect data check") end/' coding
mutant "bytes after the zlib stream ignored" coding.lua \
  's/if pos \+ 4 <= n then fail/if false then fail/' coding
mutant "incomplete Huffman codes accepted" coding.lua \
  's/if left > 0 and not \(partial and max == 1\) then/if false then/' coding
mutant "over-subscribed Huffman codes accepted" coding.lua \
  's/if left < 0 then fail\("corrupt", "over-subscribed code"\) end/-- removed/' coding
mutant "a single one-bit code refused (zlib accepts it)" coding.lua \
  's/if left > 0 and not \(partial and max == 1\) then/if left > 0 then/' coding
mutant "stored LEN/NLEN not compared" coding.lua \
  's/if len ~= \(~nlen & 0xffff\) then fail/if false then fail/' coding
mutant "more than 286 length or 30 distance codes accepted" coding.lua \
  's/if nlen > 286 or ndist > 30 then fail/if false then fail/' coding
mutant "a distance before the start of the output accepted" coding.lua \
  's/if d > o then fail\("corrupt", "invalid distance too far back"\) end/-- removed/' coding
mutant "the window not kept across a stored block" coding.lua \
  's/local keep = len < 32768 and len or 32768/local keep = 0/' coding
# Requirements audit (RFC 9421 2, 2.1.2, 2.5; RFC 3986 6.2.3).
mutant "component identity depends on parameter order" sigbase.lua \
  's/^(\s*)table\.sort\(ps\)$/$1-- removed/' sigbase
mutant "a Dictionary key covered twice through ;sf" sigbase.lua \
  's/if not \(keyed and kv\[1\] == "sf"\) then/if true then/' verify
mutant "HTAB allowed in derived components" sigbase.lua \
  's/derived and "\[\^\\32-\\126\]" or //' verify
mutant "every value scanned again for each signature (no per-request memo)" sigbase.lua \
  's/if not \(ok and ok\[c\.value\]\) then/if not (ok and ok[c.value]) or true then/' sigbase
mutant ";key hides other parameters from the identity (RFC 9421 2)" sigbase.lua \
  's/if not \(keyed and kv\[1\] == "sf"\) then/if not keyed or kv[1] == "key" then/' sigbase
mutant "an empty Host port kept" modsecurity_entry.lua \
  's/port == "" or //' entry

# "Adhere to RFC" (2026-10-02): RFC 9421 4 and 2.2.8, WBA draft 4.3 and 5.5.
mutant "orphan labels ignored (RFC 9421 4)" verify.lua \
  's/if sigs\[label\] == nil then return result\("invalid", "orphan-label"\) end/-- removed/' verify
mutant "URL-less requests left unverified (draft 4.3)" verify.lua \
  's/if agent_field == nil then return URL_LESS end/if agent_field == nil then return nil, "unverified", "agent-absent" end/' verify
mutant "explicit :443 accepted in Signature-Agent (draft 5.5)" identifier.lua \
  's/if mode == "origin" then return nil end/-- removed/' verify
mutant "@query-param spaces as %20 (the RFC example, not its steps)" components.lua \
  's/if c == " " then return "\+" end/-- removed/' components

# Operator controls and attribution logs (2026-10-02).
mutant "label and sighash returned on a failed signature" verify.lua \
  's/if not \(alt_base and ok and good == true\) then return result\("invalid", "bad-signature"\) end/if not (alt_base and ok and good == true) then return result("invalid", "bad-signature", { label = label, sighash = "x" }) end/' verify
mutant "sighash over the signature base, not the signature" verify.lua \
  's/sighash = hex\(sha256\.digest\(sig_member\.value\.value\)\)/sighash = hex(sha256.digest(base))/' verify
mutant "coverage policy ignored" verify.lua \
  's/^            return result\("unverified", "insufficient-coverage"\)$/            local _ = 0/' verify
mutant "any configured grant grants every verified agent" modsecurity_entry.lua \
  's/if r\.agent and grants\[r\.agent\] and covers_all/if r.agent and next(grants) and covers_all/' entry
mutant "a grant ignores what the signature covered (bearer token)" modsecurity_entry.lua \
  's/ and covers_all\(r\.covered, grant_needs\) then/ then/' entry
mutant "the operator's tx.wba_grant_require_components list dropped (any coverage granted)" modsecurity_entry.lua \
  's/^(\s*)grant_needs\[#grant_needs \+ 1\] = name$/$1-- removed/' entry
mutant "@target-uri not counted as @path for a grant" modsecurity_entry.lua \
  's/ or \(name == "\@path" and have\["\@target-uri"\]\)//' entry
mutant "site names unset means unchecked, not unverified" modsecurity_entry.lua \
  's/^    pol\.authorities = false$/    pol.authorities = nil/' entry
mutant "a malformed setting falls back silently" modsecurity_entry.lua \
  's/return nil, "tx\.wba_max_window must be a positive number of seconds"/window = "86400"/' entry
mutant "quotes and backslashes not escaped in the JSON log line" wba_log.lua \
  's/e = "\\\\" \.\. c$/e = c/' log
mutant "log fields not capped (a line can exceed one pipe write)" wba_log.lua \
  's/if n \+ #e > limit then break end/-- removed/' log
mutant "unverified fields logged as \"n/a\", not null" wba_log.lua \
  's/if v == nil or v == "n\/a" then return "null" end/if v == nil then return "null" end/' log
mutant "a log line lost at close (a full disk) not reported" wba_log.lua \
  's/if not closed then error/if false then error/' log
mutant "a log line lost at write not reported" wba_log.lua \
  's/if not wrote then error/if false then error/' log

mutant "SHA-256 round constant" sha256.lua 's/0x428a2f98/0x428a2f99/' sha256
mutant "SHA-256 padding off by one" sha256.lua 's/\(55 - n\) % 64/(56 - n) % 64/' sha256

# Every RFC 9421 3.3 algorithm the draft allows (2026-10-03): selection
# (3.2 step 6), lengths, key types, the store's RSA and alg rules.
mutant "a declared algorithm for another key type accepted (3.2 step 8)" algorithms.lua \
  's/if M\.ALGORITHMS\[declared\]\.key ~= entry\.type then return nil, "alg-mismatch" end/-- removed/' verify
mutant "the key's alg pin and the alg parameter need not agree (3.2 step 6.5; 7.3.6 downgrade)" algorithms.lua \
  's/if from_key and from_key ~= declared then return nil, "alg-mismatch" end/-- removed/' verify
mutant "an RSA key's algorithm guessed when neither key nor signature states one" algorithms.lua \
  's/^M\.ONLY = \{ ed25519 = "ed25519",/M.ONLY = { rsa = "rsa-pss-sha512", ed25519 = "ed25519",/' verify
mutant "any alg string accepted (hmac-sha256 among them, draft 6.4)" verify.lua \
  's/if not \(alg\.type == "string" and algorithms\.ALGORITHMS\[alg\.value\]\) then/if not (alg.type == "string") then/' verify
mutant "signature length not checked against the algorithm and key" verify.lua \
  's/if #signature ~= algorithms\.signature_length\(use, k\) then return result\("invalid", "bad-signature"\) end/-- removed/' verify
mutant "URL-less: directories may disagree on the algorithm" verify.lua \
  's/if use and a ~= use then use, unusable = nil, "alg-mismatch" break end/-- removed/' verify
mutant "URL-less: one directory's entry decides alone" verify.lua \
  's/if current\(ke\) then held\[#held \+ 1\] = ke end/if current(ke) and #held == 0 then held[1] = ke end/' verify
mutant "RSA keys under 2048 bits stored" keys.lua \
  's/bits\(n\) >= algorithms\.RSA_MIN_BITS/bits(n) >= 1024/' keys
mutant "every lookup parses the whole key store" keys.lua \
  's/^    if want then text = select_lines\(text, want, index\) end$/    if false then text = select_lines(text, want, index) end/' keys
mutant "a key-store identifier matched as a prefix" keys.lua \
  's/needle = "\\n" \.\. want\.identifier \.\. "\\t"/needle = "\\n" .. want.identifier/' keys
mutant "a url-less lookup keeps lines where another field equals the keyid" keys.lua \
  's/if want\.identifier or line:match\("\^\[\^\\t\]\*\\t\(\[\^\\t\]\*\)"\) == want\.keyid then/if true then/' keys
mutant "an even RSA exponent stored" keys.lua \
  's/and tonumber\(e:sub\(-1\), 16\) % 2 == 1 //' keys
mutant "an RSA key OpenSSL cannot verify with (over 3072 bits, e over 64 bits) stored" keys.lua \
  's/and \(bits\(n\) <= algorithms\.RSA_LARGE_BITS or bits\(e\) <= algorithms\.RSA_LARGE_MAX_E_BITS\)/and true/' keys
mutant "an alg pin for another key type stored" keys.lua \
  's/if not a or a\.key ~= ktype then/if not a then/' keys
mutant "a version 1 store no longer read" keys.lua \
  's/elseif line == M\.HEADER_V1 then version = 1/elseif false then/' keys

# Agent types, identifiers and possession proofs (2026-10-03): draft 5.5,
# 5.5.3, Appendix B; RFC 3986 6.2.2/6.2.3, RFC 5952, RFC 6454 6.2, RFC 9110 4.2.4.
mutant "jwks_uri and cimd members ignored (draft 5.5)" verify.lua \
  's/^local AGENT_TYPES = \{ directory = true, jwks_uri = true, cimd = true \}$/local AGENT_TYPES = { directory = true }/' verify
mutant "an unsupported type resolved anyway (draft 5.2.1: MUST ignore)" verify.lua \
  's/if t\.type ~= "token" or not AGENT_TYPES\[t\.value\] then/if false then/' verify
mutant "a String type taken for a Token (draft 5.2.1)" verify.lua \
  's/if t\.type ~= "token" or not AGENT_TYPES/if not AGENT_TYPES/' verify
mutant "query kept in a jwks_uri/cimd identifier (draft 5.5)" identifier.lua \
  's/or remove_dot_segments\(path\)\)$/or remove_dot_segments(path)) .. suffix/' keys
mutant "dot segments not removed (RFC 3986 6.2.2.3)" identifier.lua \
  's/\(path == "" and "\/" or remove_dot_segments\(path\)\)$/(path == "" and "\/" or path)/' keys
mutant "percent-encoding not normalized (RFC 3986 6.2.2.2)" identifier.lua \
  's/^(\s*)path = pct_normal\(path\)$/$1-- removed/' keys
mutant "userinfo parsed as part of the host (RFC 9110 4.2.4)" identifier.lua \
  's/host:match\("\^\[a-z0-9\]\[a-z0-9\.-\]\*\$"\)/host:match("^[a-z0-9@][a-z0-9.@-]*\$")/' keys
mutant "uppercase accepted in an origin (RFC 6454 6.2)" identifier.lua \
  's/host:match\("\^\[a-z0-9\]\[a-z0-9\.-\]\*\$"\)/host:match("^[A-Za-z0-9][A-Za-z0-9.-]*\$")/' verify
mutant "IPv6 zero runs not compressed (RFC 5952 4.2)" identifier.lua \
  's/if len < 2 then return hex\(1, 8\) end/do return hex(1, 8) end/' keys
mutant "IPv6 \"::\" for one zero group (RFC 5952 4.2.2)" identifier.lua \
  's/if len < 2 then return hex\(1, 8\) end/if len < 1 then return hex(1, 8) end/' keys
mutant "IPv4-mapped IPv6 not in dotted form (RFC 5952 5)" identifier.lua \
  's/if g\[5\] == 0 and g\[6\] == 0xffff then return/if false then return/' keys
mutant "proof reported valid after its expires (5.5.3)" verify.lua \
  's/if k\.proof == "valid" and k\.proof_exp and now >= k\.proof_exp then return "expired" end/-- removed/' verify
mutant "proof reported for a URL-less request" verify.lua \
  's/^(\s*)if url_less then return result\("verified", "url-less", facts\) end$/$1facts.proof = proof_of(k, now)\n$1if url_less then return result("verified", "url-less", facts) end/' verify
mutant "proof columns not validated" keys.lua \
  's/if not PROOFS\[proof\] or not ok3 or \(proof == "valid"\) ~= \(proof_exp ~= nil\) then/if not ok3 then/' keys
mutant "url-less lookup takes the store before the line, not the line" keys.lua \
  's/while from > 0 and text:byte\(from\) ~= 10 do from = from - 1 end/from = 0/' keys
mutant "lookups never share an index (one pass over the store per signature)" keys.lua \
  's/if index\.n > 1 and not index\.by_id then/if false then/' keys
mutant "the index is built but never read (one pass per signature again)" keys.lua \
  's/^        if index\.by_id then$/        if false then/' keys
# Rule files (2026-10-11): Lua through SecRuleScript only; ids in the block.
mutant "the verifier loaded with @inspectFile again (a broken script would run as a program)" wba.conf \
  's/^SecRuleScript (\S+) "id:9534103,phase:1,pass,nolog,/SecRule REQUEST_METHOD "\@inspectFile $1" "id:9534103,phase:1,pass,nolog,t:none,/' conf
mutant "a recipe id back in the old range another plugin holds" recipes.conf \
  's/id:9534135,/id:9530135,/' conf
# Tags, version, severity and the on/off switch (2026-10-12).
mutant "the phase 2 Lua run without the plugin's tag (ctl:ruleRemoveByTag would miss it)" wba.conf \
  's/tag:\x27web-bot-auth\x27,// if $prev; $prev = /id:9534106,/' conf
mutant "rule 9534107 without a severity (v3 logs it as EMERGENCY)" wba.conf \
  's/,severity:\x27WARNING\x27//' conf
mutant "recipe F logs a forged signature as NOTICE" recipes.conf \
  's/severity:\x27WARNING\x27,chain/severity:\x27NOTICE\x27,chain/' conf
mutant "one recipe with another version string" recipes.conf \
  's/ver:\x27web-bot-auth-plugin\/0\.1\.0\x27,severity:\x27NOTICE\x27"/ver:\x27web-bot-auth-plugin\/0.0.9\x27,severity:\x27NOTICE\x27"/' conf
mutant "the phase 2 switch skips to another phase's marker" wba.conf \
  's/skipAfter:END-WBA-BODY"/skipAfter:END-WBA-VERIFY"/ if /^    skipAfter:END-WBA-BODY"$/ && !$done++' conf
mutant "the phase 5 switch moved to phase 2 (the log script still runs when off)" wba.conf \
  's/"id:9534111,phase:5,/"id:9534111,phase:2,/' conf
mutant "the image builds on a libmodsecurity linked against any Lua" Dockerfile \
  's/grep -q \x27liblua5\\\.3\x27/grep -q \x27liblua\x27/' conf
mutant "lua-openssl built for Lua 5.4 while the check still asks for 5.3" Dockerfile \
  's/liblua5\.3-dev/liblua5.4-dev/' conf
mutant "the index takes a keyid with no tab after it (other lines than the find)" keys.lua \
  's/local kid = rest:match\("\^\(\[\^\\t\]\*\)\\t"\)/local kid = rest:match("^([^\\t]*)")/' keys
mutant "tx.wba_agent_proof not set" modsecurity_entry.lua \
  's/m\.setvar\("tx\.wba_agent_proof", r\.proof\)/-- removed/' entry
mutant "a grant matched on a URL not in normal form" modsecurity_entry.lua \
  's/if not id and keys\.url_identifier\(entry\) == entry then id = entry end/if not id then id = keys.url_identifier(entry) end/' entry
mutant "agent_proof missing from the JSON log line" wba_log.lua \
  's/verified_str\(m\.getvar\("TX\.wba_agent_proof"\), 16\)/"null"/' log

# Replay accounting (draft 5.3; replay.lua).
mutant "every use counted as the first" replay.lua \
  's/^    return pos$/    return 1/' replay
mutant "uppercase hex accepted in a counter's file name" replay.lua \
  's/\[\^0-9a-f\]/[^0-9a-fA-F]/' replay
mutant "a URL-less signature not counted" modsecurity_entry.lua \
  's/if r\.status == "verified" and replay_dir then/if r.status == "verified" and r.agent and replay_dir then/' entry
mutant "a count that cannot be kept passes as verified" modsecurity_entry.lua \
  's/r = \{ status = "unverified", reason = "replay-unavailable" \}/r = r/' entry
mutant "the nonce not counted" modsecurity_entry.lua \
  's/if k\.noncehash then/if false then/' entry
mutant "the nonce counter keyed by the signature" verify.lua \
  's/noncehash = nonce and hex\(sha256\.digest\(nonce\.value\)\)/noncehash = nonce and hex(sha256.digest(sig_member.value.value))/' entry
mutant "a replay directory with an empty segment accepted" modsecurity_entry.lua \
  's/ or padded:find\("\/\/", 1, true\)//' entry
mutant "a replay directory with a .. segment accepted" modsecurity_entry.lua \
  's/\s*or padded:find\("\/%\.%\.\?\/"\)//' entry
mutant "replay counted by signature bytes, so ECDSA (r, n - s) is a fresh use" verify.lua \
  's/hex\(h\(base\)\)/hex(h(sig_member.value.value))/; s/hex\(sha256\.digest\(base\)\)/hex(sha256.digest(sig_member.value.value))/' entry
mutant "only the reported signature counted" modsecurity_entry.lua \
  's/for _, k in ipairs\(r\.replay or \{\}\) do/for _, k in ipairs({ (r.replay or {})[1] }) do/' entry
mutant "tx.wba_max_age does not reach the verifier" modsecurity_entry.lua \
  's/seconds\("TX\.wba_max_age", "max_age"\)/seconds("TX.wba_max_age", "max_age_unused")/' entry
mutant "tx.wba_expiry_grace does not reach the verifier" modsecurity_entry.lua \
  's/seconds\("TX\.wba_expiry_grace", "expiry_grace", 60\)/seconds("TX.wba_expiry_grace", "grace_unused", 60)/' entry
mutant "tx.wba_strict_field_lines does not reach the verifier" modsecurity_entry.lua \
  's/"strict_field_lines" \}/"strict_unused" }/' entry
mutant "tx.wba_max_window=0 accepted" modsecurity_entry.lua \
  's/window:match\("\^\[1-9\]/window:match("^[0-9]/' entry
mutant "a nonce not required when the operator asks" verify.lua \
  's/if policy\.require_nonce and not nonce then/if false then/' entry
mutant "statement counters named without their expiry" replay.lua \
  's/name = \("s\.%d\.%s"\):format\(expires, hash\)/name = "s." .. hash/' replay
mutant "a statement counter named with the request's expiry grace (another server block counts afresh)" verify.lua \
  's/expires = r\.expires \}/expires = r.expires + (pol.expiry_grace or 0) }/' entry
mutant "a statement counter named with the request's max_age (another server block counts afresh)" verify.lua \
  's/expires = r\.expires \}/expires = math.min(r.expires, r.created + (pol.max_age or r.expires)) }/' verify
mutant "a grant left standing after an internal error (recipe C reads it alone)" modsecurity_entry.lua \
  's/^(\s*)m\.setvar\("tx\.wba_granted", "0"\)$/$1-- removed/' entry
mutant "the identity left standing after an internal error" modsecurity_entry.lua \
  's/for _, name in ipairs\(VERIFIED_ONLY\) do m\.setvar\(name, "n\/a"\) end/-- removed/' entry
mutant "Signature-Agent parsed again for every signature" components.lua \
  's/if slot\[name\] == nil then/if true then/' verify

# RFC 9651 4.2's MAY (policy.strict_field_lines).
mutant "a field line that does not parse alone accepted" structured_fields.lua \
  's/if not pcall\(parse, line\) then return false end/local _ = pcall(parse, line)/' structured_fields
mutant "strict field lines ignored for the signature fields" verify.lua \
  's/if pol\.strict_field_lines then/if false then/' verify
mutant "strict field lines ignored for covered digests" digest.lua \
  's/if strict_lines and not sf\.every_line/if false and not sf.every_line/' verify
mutant "use counts missing from the JSON log line" wba_log.lua \
  's/verified_int\(m\.getvar\("TX\.wba_uses"\)\)/"null"/' log
mutant "the Host header missing from the JSON log line" wba_log.lua \
  's/str\(get\("REQUEST_HEADERS:Host"\)\)/"null"/' log

# Key-sync (TypeScript) mutants: wba-keysync and the fixtures it reads, copied
# and mutated the same way, run under Bun. Without Bun they are reported as
# SKIP (run_all.sh reports key-sync itself as skipped then).
ts_mutant() { # description, file in wba-keysync/, perl substitution, test file (keysync|proof|...), [test name pattern]
  mine || return 0
  if ! command -v bun >/dev/null 2>&1; then echo "SKIP  bun not found: $1"; return; fi
  local tmp; tmp=$(mktemp -d)
  mkdir -p "$tmp/lua/tests"
  cp -R "$REPO/wba-keysync" "$tmp/"
  cp -R "$REPO/lua/tests/fixtures" "$REPO/lua/tests/sf-corpus" "$tmp/lua/tests/"
  perl -pi -e "$3" "$tmp/wba-keysync/$2"
  if cmp -s "$REPO/wba-keysync/$2" "$tmp/wba-keysync/$2"; then
    echo "FAIL  mutation did not apply: $1"; FAIL=1
  elif (cd "$tmp" && bun test "./wba-keysync/$4.test.ts" ${5:+-t "$5"}) >/dev/null 2>&1; then
    echo "FAIL  survived: $1"; FAIL=1
  else
    echo "PASS  caught: $1"
  fi
  rm -rf "$tmp"
}

ts_mutant "kid that is not the thumbprint kept at the well-known URI (draft 5.5 MUST)" keysync.ts \
  's/if \(kidIsThumbprint && k\.kid !== undefined && k\.kid !== keyid\)/if (false)/' keysync
ts_mutant "a jwks_uri/cimd kid label refused (5.5: compute thumbprints instead)" keysync.ts \
  's/if \(kidIsThumbprint && k\.kid/if (k.kid/' keysync
ts_mutant "a JWK alg for another key type accepted (RFC 9421 3.2 step 6.5)" algorithms.ts \
  's/return name !== null && ALGORITHMS\[name\] === type \? name : null;/return name;/' keysync
ts_mutant "JOSE PS512 pinned to PKCS #1 v1.5, the same key type (RFC 7518 3.5; RFC 9421 7.3.6)" algorithms.ts \
  's/PS512: "rsa-pss-sha512"/PS512: "rsa-v1_5-sha256"/' keysync
ts_mutant "JOSE EdDSA not mapped, so Ed25519 keys labelled EdDSA dropped (RFC 7517 4.4; RFC 8037 3.1)" algorithms.ts \
  's/^  EdDSA: "ed25519",.*$//' keysync
ts_mutant "the raw JOSE name stored as the pin, not its HTTP twin (keys.lua refuses the store)" keysync.ts \
  's/\.\.\.\(pin !== undefined \? \{ alg: pin \} : \{\}\)/...(typeof k.alg === "string" ? { alg: k.alg } : {})/' keysync
ts_mutant "validate: IP lists fetched following redirects (draft 5.5 MUST NOT)" validate.ts \
  's/^    redirect: "manual", signal: AbortSignal\.timeout\(DEFAULT_LIMITS\.timeoutMs\),$/    redirect: "follow", signal: AbortSignal.timeout(DEFAULT_LIMITS.timeoutMs),/' validate
ts_mutant "validate: documentation pages fetched following redirects" validate.ts \
  's/const res = await fetchImpl\(url, \{ redirect: "manual",/const res = await fetchImpl(url, { redirect: "follow",/' validate
ts_mutant "validate: no address guard before fetching docs or lists (draft 6.7)" validate.ts \
  's/^      await guardAddress\(url, resolve\);$/      \/\/ removed/' validate
ts_mutant "validate: a list of 0.0.0.0/0 accepted" validate.ts \
  's/const broad = cs\.filter\(\(c\) => c\.bits < \(c\.v === 4 \? MIN_V4_BITS : MIN_V6_BITS\)\);/const broad: typeof cs = [];/' validate
# Bot lists (lists.ts): which lists are taken, what a failure keeps, and what
# the rules claim, verify and refuse.
ts_mutant "lists: a list touching private space accepted" lists.ts \
  's/^  if \(local\) throw /  if (false) throw /' lists
ts_mutant "lists: a list wider than an IPv4 /8 accepted" lists.ts \
  's/^  if \(broad\) throw /  if (false) throw /' lists
ts_mutant "lists: a single address written with /128, which libmodsecurity refuses" lists.ts \
  's/return BigInt\(c\.bits\) === WIDTH\[c\.v\] \?/return false ?/' lists
ts_mutant "lists: the version ignores the ranges, so a changed list keeps its version" lists.ts \
  's/version: `\$\{creationTime \?\? "undated"\}#\$\{sha256\.slice\(0, 8\)\}`/version: `\${creationTime ?? "undated"}`/' lists
ts_mutant "lists: a new bot takes a slot another bot holds" lists.ts \
  's/const used = new Set\(Object\.values\(slots\)\);/const used = new Set<number>();/' lists
ts_mutant "lists: a list that fails loses its previous version" lists.ts \
  's/if \(kept && existsSync\(join\(dataDir, `\$\{b\.name\}\.data`\)\)\)/if (false)/' lists
ts_mutant "lists: a bot whose list never arrived treats every claim as an impostor" lists.ts \
  's/setvar:tx\.bot_reason=\$\{list \? "not-in-list" : "no-list"\}/setvar:tx.bot_reason=not-in-list/' lists
ts_mutant "lists: a claim-only bot's claims from outside its list refused" lists.ts \
  's/\} else if \(b\.policy === "allow" && b\.claim_only\) \{/} else if (false) {/' lists
ts_mutant "lists: deny on a claim-only bot refuses a mere claim" lists.ts \
  's/\$\{b\.claim_only \? ",chain" : ""\}/""/; s/^      if \(b\.claim_only\) out\.push\(`    SecRule TX:bot_status/      if (false) out.push(`    SecRule TX:bot_status/' lists
ts_mutant "lists: a signature maps to its bot whatever the plugin decided" lists.ts \
  's/SecRule TX:wba_status "\@streq verified" "id:\$\{base \+ 2\}/SecRule TX:wba_status "\@rx ." "id:\${base + 2}/' lists
ts_mutant "lists: no address guard before fetching a list (draft 6.7)" lists.ts \
  's/^        else await guardAddress\(url, resolve\);$/        else {}/' lists
ts_mutant "lists: a failed check leaves the new files in place" lists.ts \
  's/for \(const \[p, text\] of before\) \{/for (const [p, text] of new Map<string, string | null>()) {/' lists
ts_mutant "lists: a failed reload leaves the new files, so the next run never reloads them" lists.ts \
  's/if \(!r\.ok\) \{ putBack\(\); log/if (!r.ok) { log/' lists
ts_mutant "lists: a removed bot's data file left behind" lists.ts \
  's/if \(f !== "tokens\.data" && !lists\.has\(name\)\)/if (false)/' lists
ts_mutant "lists: the WAF checked and reloaded when nothing it reads changed" lists.ts \
  's/if \(o\.check && !changed\) log/if (false) log/' lists
ts_mutant "lists: the rules written as an after file, so an operator's after file that sorts first reads a signing bot as claimed" lists.ts \
  's/^export const CONF = "web-bot-auth-bots-before\.conf";/export const CONF = "web-bot-auth-bots-after.conf";/' lists
ts_mutant "lists: the after file an older lists.ts wrote left in place, so both sets of rules load" lists.ts \
  's/if \(existsSync\(old\) && readFileSync\(old, "utf8"\)\.startsWith\(OLD_HEADER\)\)/if (false)/' lists
ts_mutant "lists: the old after file not put back when the check fails" lists.ts \
  's/keep\(old\); rmSync\(old\);/rmSync(old);/' lists
ts_mutant "lists: an operator's own file named web-bot-auth-bots-after.conf removed too" lists.ts \
  's/ && readFileSync\(old, "utf8"\)\.startsWith\(OLD_HEADER\)//' lists
ts_mutant "lists: a range inside another kept, which libmodsecurity's address tree can lose (ModSecurity #3588)" lists.ts \
  's/if \(!kept\.length \|\| !overlaps\(kept\[kept\.length - 1\], c\)\) kept\.push\(c\);/kept.push(c);/' lists
ts_mutant "lists: generated rules name no release (no ver)" lists.ts \
  "s/ver:'\\\$\\{VER\\}',//g" lists
ts_mutant "lists: policy rules log with no severity, which ModSecurity v3 records as emergency" lists.ts \
  "s/severity:'NOTICE',//" lists
ts_mutant "validate: a User-Agent token that would claim two bots accepted" validate.ts \
  's/const other = owner\.find\(\(\[b, tb\]\) => b !== a && tb\.includes\(ta\)\);/const other = undefined;/' validate
ts_mutant "robots: bots with other policies asked to stay away too" robots.ts \
  's/bots\.filter\(\(x\) => x\?\.policy === "deny"\)/bots.filter((x) => x?.policy !== undefined)/' robots
ts_mutant "robots: a User-Agent fragment written as a product token" robots.ts \
  's/if \(!PRODUCT\.test\(t\)\) \{ skipped/if (false) { skipped/' robots
ts_mutant "report: a broken entry still credited with proofs" report.ts \
  's/const broken = checkEntries\(\[b\]\)\.some\(\(f\) => f\.level === "fail"\);/const broken = false;/' report
ts_mutant "report: names and quotes written into Markdown unescaped" report.ts \
  's/^const text = \(s: string\) => .*$/const text = (s: string) => s;/' report
ts_mutant "redirects followed (draft 5.5 MUST NOT)" keysync.ts \
  's/redirect: "manual"/redirect: "follow"/' keysync
ts_mutant "key sync keeps an RSA key OpenSSL cannot verify with (over 3072 bits, e over 64 bits)" keysync.ts \
  's/if \(bits > RSA_LARGE_BITS && bitLength\(e\) > RSA_LARGE_MAX_E_BITS\)/if (false)/' keysync
ts_mutant "the store reader accepts an RSA key OpenSSL cannot verify with" keysync.ts \
  's/\(hexBits\(n\) <= RSA_LARGE_BITS \|\| hexBits\(e\) <= RSA_LARGE_MAX_E_BITS\)/true/' keysync
ts_mutant "a JSON media type required away from the well-known URI (draft 5.5 sets none)" keysync.ts \
  's/if \(atWellKnown && type !== MEDIA_TYPE\)/if (atWellKnown ? type !== MEDIA_TYPE : !type.includes("json"))/' keysync
ts_mutant "any media type accepted at the well-known URI (draft 5.5.1)" keysync.ts \
  's/if \(atWellKnown && type !== MEDIA_TYPE\)/if (false)/' keysync
ts_mutant "an agent's own URL not guarded (draft 6.7)" keysync.ts \
  's/^(\s*)await guardUnlessAllowed\(a\.url, resolve, ctx\.allowPrivate, warn\);$/$1\/\/ removed/' keysync
ts_mutant "the CIMD jwks_uri hop not guarded (draft 6.7)" keysync.ts \
  's/^(\s*)await guardAddress\(jwksUri, resolve\);$/$1\/\/ removed/' keysync
ts_mutant "IP literals handed to DNS, never checked as written (draft 6.7)" keysync.ts \
  's/const literal = host\.startsWith\("\["\) \? host\.slice\(1, -1\) : v4\(host\) \? host : null;/const literal = null as string | null;/' keysync
ts_mutant "SIIT IPv4-translated addresses not judged by their IPv4 address" keysync.ts \
  's/g\[4\] === 0xffff && g\[5\] === 0\) return embedded/g[4] === 0xffff && g[5] === 0) return false && embedded/' keysync
ts_mutant "CIMD client_id not checked (CIMD 4)" keysync.ts \
  's/if \(doc\.client_id !== a\.url\) \{/if (false) {/' keysync
ts_mutant "CIMD jwks and jwks_uri both accepted (RFC 7591 2)" keysync.ts \
  's/if \(doc\.jwks !== undefined && doc\.jwks_uri !== undefined\) throw/if (false) throw/' keysync
ts_mutant "CIMD shared secret accepted (CIMD 4.1)" keysync.ts \
  's/if \("client_secret" in doc \|\| "client_secret_expires_at" in doc/if (false/' keysync
ts_mutant "query kept in a jwks_uri/cimd identifier (draft 5.5)" identifier.ts \
  's/const p = pctNormal\(path\);/const p = pctNormal(path + suffix);/' keysync
ts_mutant "IPv6 zero runs not compressed (RFC 5952 4.2)" identifier.ts \
  's/if \(len < 2\) return hex\(0, 8\);/return hex(0, 8);/' keysync
ts_mutant "Appendix B evaluated for a jwks_uri" keysync.ts \
  's/if \(a\.type !== "directory"\) return \{ keys, life, etag, lastModified \};/\/\/ removed/' keysync
ts_mutant "proofs judged at the start of the run, not at receipt" keysync.ts \
  's/keys, now: ctx\.clock\(\) \}\);/keys, now });/' keysync
ts_mutant "a 304 allowed to stand in for a held valid proof" keysync.ts \
  's/ && !held\.some\(\(e\) => e\.proof === "valid"\)//' keysync
ts_mutant "a valid proof does not bound freshness" keysync.ts \
  's/freshUntil: Math\.min\(now \+ r\.life, proofEnd\)/freshUntil: now + r.life/' keysync
ts_mutant "a valid proof written without its expires" keysync.ts \
  's/valid \? e\.proofExpires : "-"/"-"/' keysync
ts_mutant "a version 1 store no longer read" keysync.ts \
  's/: lines\[0\] === HEADER_V1 \? 5 : 0/: 0/' keysync
ts_mutant "content coding left to the server" keysync.ts \
  's/, "accept-encoding": "identity",/,/' keysync
ts_mutant "proof: created in the future accepted (B.1 MUST reject)" proof.ts \
  's/if \(created > now \+ PROOF_CLOCK_SKEW\) return/if (false) return/' proof
ts_mutant "proof: no clock skew on created (fresh proofs read as in the future)" proof.ts \
  's/if \(created > now \+ PROOF_CLOCK_SKEW\) return/if (created > now) return/' proof
ts_mutant "proof: expired signature accepted (5.5.3)" proof.ts \
  's/if \(expires <= now\) return/if (false) return/' proof
ts_mutant "proof: Content-Digest not checked against the body (B.1 MUST)" proof.ts \
  's/const digest = await contentDigestMismatch\(headers\.get\("content-digest"\), body\);/const digest = null;/' proof
ts_mutant "proof: content-digest coverage not required (B.1)" proof.ts \
  's/if \(!seen\.has\(\x27"content-digest"\x27\)\) return/if (false) return/' proof
ts_mutant "proof: \"@authority\";req coverage not required (B.1)" proof.ts \
  's/if \(!seen\.has\(\x27"\@authority";req\x27\)\) return/if (false) return/' proof
ts_mutant "proof: @authority without ;req resolved in a response (RFC 9421 2.4)" proof.ts \
  's/if \(name === "\@authority" && it\.params\.size === 1 && it\.params\.get\("req"\)\?\.value === true\)/if (name === "\@authority")/' proof
ts_mutant "proof: only the first Active digest checked (RFC 9530)" proof.ts \
  's/checked\+\+;/checked++; break;/' proof
ts_mutant "proof: any alg string accepted (RFC 9421 3.2 step 6.1; draft 6.4)" proof.ts \
  's/if \(!\(algParam\.type === "string" && allowed\(algParam\.value\)\)\) return/if (algParam.type !== "string") return/' proof
ts_mutant "proof: an alg for another key type accepted (RFC 9421 3.2 step 8)" algorithms.ts \
  's/if \(ALGORITHMS\[declared\] !== key\.type\) return \{ error: "alg-mismatch" \};/\/\/ removed/' proof
ts_mutant "proof: the key's alg pin and the alg parameter need not agree (RFC 9421 3.2 step 6.5)" algorithms.ts \
  's/if \(fromKey !== undefined && fromKey !== declared\) return \{ error: "alg-mismatch" \};/\/\/ removed/' proof
ts_mutant "proof: an RSA key's algorithm guessed (RFC 9421 3.2 step 6)" algorithms.ts \
  's/= \{ ed25519: "ed25519", "ec-p256"/= { rsa: "rsa-pss-sha512", ed25519: "ed25519", "ec-p256"/' proof
ts_mutant "proof: signature length not checked against the algorithm and key" proof.ts \
  's/sig\.value\.value\.length !== want/false/' proof
ts_mutant "proof: RSA-PSS salt length 32, not 64 (RFC 9421 3.3.1)" proof.ts \
  's/\{ name, saltLength: 64 \}/{ name, saltLength: 32 }/' proof
ts_mutant "proof: ECDSA verified with SHA-256 on P-384 (RFC 9421 3.3.5)" proof.ts \
  's/\["P-384", "SHA-384"\]/["P-384", "SHA-256"]/' proof
ts_mutant "SF: a repeated dictionary key keeps the first value (RFC 9651 4.2.2)" sf.ts \
  's/out\.set\(k, member\);/if (!out.has(k)) out.set(k, member);/' proof
ts_mutant "SF: a Decimal with four fractional digits accepted (RFC 9651 4.2.4)" sf.ts \
  's/frac\.length > 3/frac.length > 4/' proof
ts_mutant "sweeper removes a statement before its signature expires" sweep.ts \
  's/Number\(statement\[1\]\) \+ skew < now/Number(statement[1]) < now + skew/' sweep
ts_mutant "sweeper keeps a statement unused past the window until its own far-off expires" sweep.ts \
  's/if \(!expired\) \{ \/\/ a statement not yet expired/if (!expired && !statement) { \/\/ a statement not yet expired/' sweep
ts_mutant "sweeper treats a symlink as a counter" sweep.ts \
  's/!entry\.isFile\(\) \|\| //' sweep
ts_mutant "sweeper aborts when another sweeper removed a counter after readdir" sweep.ts \
  's/=== "ENOENT"\) continue;/=== "ENOENT") throw e;/' sweep
ts_mutant "sweeper prints usage for a runtime error" sweep.ts \
  's/e instanceof UsageError \? usage/true ? usage/' sweep
ts_mutant "test signer's private key created with the default mode" sign.ts \
  's/\{ mode: 0o600, flag: "wx" \}/{ flag: "wx" }/' sign "init:"
ts_mutant "test signer's curl always disables TLS verification" sign.ts \
  's/\.\.\.\(opts\.has\("--insecure"\) \? \["-k"\] : \[\]\)/"-k"/' sign "init:"
ts_mutant "validate: a reset mid-body reported as larger than 4 MiB" validate.ts \
  's/throw \/exceeds maxBytes\/\.test\(e\.message\) \?/throw true ?/' validate
ts_mutant "allow-private: one named origin excepts every origin" keysync.ts \
  's/if \(allow\.has\(origin\)\) \{ warn/if (allow.size > 0) { warn/' keysync
ts_mutant "allow-private: an origin with a path accepted" keysync.ts \
  's/return directoryIdentifier\(value\) === null \? null : new URL\(value\)\.origin;/return urlIdentifier(value) === null ? null : new URL(value).origin;/' keysync
ts_mutant "allow-private: an excepted fetch not reported" keysync.ts \
  's/if \(allow\.has\(origin\)\) \{ warn\(`\$\{origin\} fetched without the private-address check \(--allow-private-origin\)`\); return; \}/if (allow.has(origin)) return;/' keysync
ts_mutant "agents: a JWK Set written as a key directory" agents.ts \
  's/: `\$\{agent\.url\} type=\$\{agent\.type\}`;/: agent.url;/' agents
ts_mutant "agents: a key directory written as its identifier" agents.ts \
  's/agent\.id\.slice\(0, -WELL_KNOWN\.length\)/agent.id/' agents
ts_mutant "agents: a bad wba skipped instead of failing the run" agents.ts \
  's/if \(typeof agent === "string"\) throw new Error/if (typeof agent === "string") continue; if (0) throw new Error/' agents
ts_mutant "agents: bots sharing a key source listed twice" agents.ts \
  's/else if \(held\.line === line\) held\.names\.push\(bot\.name\);/else if (held.line === line) byId.set(agent.id + bot.name, { line, names: [bot.name] });/' agents
ts_mutant "agents: --only ignored" agents.ts \
  's/if \(only && !only\.has\(bot\.name\)\) continue;//' agents
ts_mutant "agents: --out written through a symlink" agents.ts \
  's/renameSync\(tmp, out\);/writeFileSync(out, readFileSync(tmp)); rmSync(tmp);/; s/^import \{ readFileSync, renameSync, writeFileSync \}/import { readFileSync, renameSync, rmSync, writeFileSync }/' agents


ts_mutant "allow-private: the jwks_uri a CIMD document names excepted too" keysync.ts \
  's/^(\s*)await guardAddress\(jwksUri, resolve\);$/$1await guardUnlessAllowed(jwksUri, resolve, ctx.allowPrivate, warn);/' keysync
ts_mutant "key sync: the DNS lookup has no time limit (a silent DNS server holds the run)" keysync.ts \
  's/const resolve = withDeadline\(opts\.resolve \?\? lookupHost, limits\.timeoutMs\);/const resolve = opts.resolve ?? lookupHost;/' keysync
ts_mutant "key sync: the DNS deadline timer never cleared, so every run waits it out" keysync.ts \
  's/^(\s*)clearTimeout\(timer\);$/$1\/\/ kept/' keysync
ts_mutant "key sync: a body that is not JSON quoted into the error" keysync.ts \
  's/throw new Error\(`the body \(\$\{body\.length\} bytes\) is not UTF-8 JSON`\);/throw new Error(`not JSON: \${new TextDecoder().decode(body)}`);/' keysync
ts_mutant "key sync: printable leaves C1 control characters (U+0080-U+009F)" keysync.ts \
  's/\[\\x00-\\x1f\\x7f-\\x9f\]/[\\x00-\\x1f\\x7f]/' keysync
ts_mutant "cli: what the network sent printed with its control characters" cli.ts \
  's/const error = \(l: string\) => \(io\.error \?\? console\.error\)\(printable\(l\)\);/const error = (l: string) => (io.error ?? console.error)(l);/' keysync
ts_mutant "cli: an agents.txt line that does not parse dropped, so its agent's keys are dropped (exit 2)" cli.ts \
  's/if \(errors\.length > 0\) \{/if (false) {/' keysync
ts_mutant "lists: --allow-private-url matched by origin, so one named list excepts every list on its host" lists.ts \
  's/if \(allow\.has\(new URL\(url\)\.href\)\)/if ([...allow].some((u) => new URL(u).origin === new URL(url).origin))/' lists
ts_mutant "lists: an origin accepted as --allow-private-url" lists.ts \
  's/if \(u\.pathname === "\/" && u\.search === ""\) return null;/\/\/ removed/' lists
ts_mutant "validate: a name that is not a string accepted (YAML name: 360)" validate.ts \
  's/if \(typeof name !== "string"\) return name === undefined/if (name === undefined) return name === undefined/' validate
ts_mutant "validate: a bot named tokens accepted, so lists.ts overwrites its IP list with the token file" validate.ts \
  's/else if \(RESERVED_NAMES\.has\(b\.name\)\)/else if (false)/' validate
ts_mutant "validate: a wba with a space accepted, so \"URL type=cimd\" changes the agent's type" validate.ts \
  's/if \(typeof b\.wba === "string" && \/\\s\/\.test\(b\.wba\)\)/if (false)/' validate
ts_mutant "validate: a nested value serialised whole into a message (YAML aliases nest)" validate.ts \
  's/return Array\.isArray\(v\) \? "a list" : typeof v === "object" \? "a mapping" : typeof v;/return String(JSON.stringify(v));/' validate
ts_mutant "validate: a long value written whole into a message" validate.ts \
  's/return s\.length > 200 \? `\$\{s\.slice\(0, 200\)\}\.\.\."` : s;/return s;/' validate
ts_mutant "agents: a bot name with a newline written into agents.txt" agents.ts \
  's/if \(bad\) throw new Error\(`\$\{bad\} \(validate\.ts checks every entry\)`\);/\/\/ removed/' agents
ts_mutant "agents: a wba with a space handed to the line parser, so its type can change" agents.ts \
  's/if \(typeof bot\.wba !== "string" \|\| \/\\s\/\.test\(bot\.wba\)\) throw/if (false) throw/' agents
ts_mutant "robots: a bot name with a newline written into robots.txt" robots.ts \
  's/if \(bad\) throw new Error\(`\$\{bad\} \(validate\.ts checks every entry\)`\);/\/\/ removed/' robots
fi

# crypto.lua (lua-openssl): RFC 9421 3.3.1's parameters, 3.3.4/3.3.5's r || s.
crypto_mutant "RSA-PSS salt length 32, not 64" crypto.lua \
  's/\{ "rsa_pss_saltlen", "64" \}/{ "rsa_pss_saltlen", "32" }/' crypto
crypto_mutant "RSA-PSS salt length auto-detected (any accepted)" crypto.lua \
  's/\{ "rsa_pss_saltlen", "64" \}/{ "rsa_pss_saltlen", "auto" }/' crypto
crypto_mutant "RSA-PSS with MGF1-SHA-256" crypto.lua \
  's/\{ "rsa_mgf1_md", "sha512" \}/{ "rsa_mgf1_md", "sha256" }/' crypto
crypto_mutant "RSA-PSS key verified with PKCS #1 v1.5 padding" crypto.lua \
  's/\{ "rsa_padding_mode", "pss" \}/{ "rsa_padding_mode", "pkcs1" }/' crypto
crypto_mutant "a DER-encoded ECDSA signature accepted" crypto.lua \
  's/if #signature ~= algorithms\.signature_length\(alg, entry\) then error\("bad signature size"\) end/-- removed/; s/ok = key:verify\(message, ecdsa_der\(signature, ECDSA\[alg\]\[1\]\), ECDSA\[alg\]\[2\]\)/ok = key:verify(message, #signature == 2 * ECDSA[alg][1] and ecdsa_der(signature, ECDSA[alg][1]) or signature, ECDSA[alg][2])/' crypto
crypto_mutant "ECDSA r and s swapped" crypto.lua \
  's/integer\(signature:sub\(1, size\)\) \.\. integer\(signature:sub\(size \+ 1\)\)/integer(signature:sub(size + 1)) .. integer(signature:sub(1, size))/' crypto
crypto_mutant "DER INTEGER without its 00 byte before a set top bit" crypto.lua \
  's/if bytes == "" or bytes:byte\(1\) >= 0x80 then/if bytes == "" then/' crypto
crypto_mutant "the key type not checked against the algorithm" crypto.lua \
  's/if not a or a\.key ~= entry\.type then/if not a then/' crypto
crypto_mutant "the OpenSSL error queue left full after a failed check" crypto.lua \
  's/^    openssl\.clear_error\(\)$/    -- removed/' crypto
crypto_mutant "body SHA-512 computed as SHA3-512" crypto.lua \
  's/digest\.digest\("sha512", data, true\)/digest.digest("sha3-512", data, true)/' sha256

[ "$FAIL" = 0 ] && echo "== every planted bug caught" || { echo "== MUTATION CHECK FAILED"; exit 1; }
