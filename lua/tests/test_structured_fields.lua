-- test_structured_fields.lua: typed RFC 9651 parsing in the shapes the verifier
-- uses, exact re-serialization, and rejection. The full RFC 9651 conformance
-- check is test_sf_corpus.lua (the HTTP WG corpus). Run: lua lua/tests/test_structured_fields.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local sf = require("wba.structured_fields")

-- 1. RFC 9421 B.2.6 Signature-Input, verbatim.
local d, order = sf.parse_dictionary('sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"')
H.eq(#order, 1)
H.eq(order[1], "sig-b26")
local e = d["sig-b26"]
H.eq(e.kind, "inner-list")
H.eq(#e.items, 6)
H.eq(e.items[4].value.value, "@authority")
H.eq(sf.param(e.params, "created").type, "integer")
H.eq(sf.param(e.params, "created").value, 1618884473)
H.eq(sf.param(e.params, "keyid").type, "string")
H.pass("RFC 9421 B.2.6 Signature-Input parses with types (created is an Integer, keyid a String)")

-- 2. Draft E.2.1 Signature-Input: component parameters survive, and the whole
-- member re-serializes byte-for-byte (the old parser dropped ;key= and lost
-- the quotes on nonce).
local e21 = 'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"'
local d21 = sf.parse_dictionary(e21)
local m21 = d21["sig2"]
H.eq(sf.param(m21.items[2].params, "key").value, "agent2", "component parameter kept")
H.eq("sig2=" .. sf.serialize_member(m21), e21, "exact re-serialization")
H.pass("draft E.2.1 Signature-Input: ;key= kept, nonce stays quoted, re-serializes byte-for-byte")

-- 3. Signature: byte sequence decodes to the raw 64 bytes.
local sig = sf.parse_dictionary("sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:")
H.eq(sig["sig2"].value.type, "binary")
H.eq(#sig["sig2"].value.value, 64)
H.pass("Signature byte sequence decodes to 64 raw bytes")

-- 4. Signature-Agent, dictionary form with a type parameter, and legacy item form.
local agents = sf.parse_dictionary('sig1="https://a.test/jwks.json";type=jwks_uri, agent2="https://b.test"')
H.eq(agents["sig1"].value.value, "https://a.test/jwks.json")
H.eq(sf.param(agents["sig1"].params, "type").type, "token")
H.eq(sf.serialize_member(agents["sig1"]), '"https://a.test/jwks.json";type=jwks_uri')
H.eq(sf.parse_item(' "https://signature-agent.test"').value.value, "https://signature-agent.test")
H.pass("Signature-Agent: dictionary members with parameters, and the legacy bare string")

-- 5. Whitespace rules: OWS around commas, SP inside inner lists and after ';'.
local ws = sf.parse_dictionary('a=1 ,\tb=( "x"  "y" );  p=?1 , c')
H.eq(#ws.b.items, 2)
H.eq(sf.param(ws.b.params, "p").value, true)
H.eq(ws.c.value.value, true, "bare key is Boolean true")
H.eq(sf.serialize_member(ws.b), '("x" "y");p', "Boolean true param serializes as bare key")
H.pass("OWS/SP handling matches RFC 9651 and canonical serialization")

-- 6. Strictness: every one of these must raise, never guess.
local bad = {
    { 'a=("x"', "unterminated inner list" },
    { "a=:AAAA", "unterminated byte sequence" },
    { 'a="x', "unterminated string" },
    { 'a="\\n"', "invalid escape" },
    { 'a="\1"', "control character in string" },
    { 'a="\27[31m"', "ESC in string" },
    { 'a="caf\195\169"', "non-ASCII in string" },
    { "a=1234567890123456", "16-digit integer" },
    { "a=0x10", "hex is not an integer" },
    { "a=1e999", "exponent is not an integer" },
    { "a=1.2345", "decimal with 4 fraction digits" },
    { "a=1234567890123.5", "decimal with 13 integer digits" },
    { "a=1.", "decimal ending in '.'" },
    { "a=@1.5", "decimal date" },
    { 'a=%"%FF"', "uppercase percent-encoding in a display string" },
    { 'a=%"%ff"', "display string that is not UTF-8" },
    { 'a=%"%ed%a0%80"', "UTF-8-encoded surrogate in a display string" },
    { "a=1,", "trailing comma" },
    { "A=1", "uppercase key" },
    { "a=:not base64!:", "invalid byte sequence" },
    { 'a=("x")junk', "junk after inner list" },
    { "a=?2", "invalid boolean" },
}
for _, b in ipairs(bad) do
    H.raises(function() sf.parse_dictionary(b[1]) end, b[2])
end
H.raises(function() sf.parse_item('"x" trailing') end, "item with trailing text")
H.pass("rejects " .. (#bad + 1) .. " malformed inputs (control bytes, hex, exponent, bad decimals, bad display strings...)")

-- 6b. RFC 9651 behaviours the previous, stricter parser refused.
local dup, dorder = sf.parse_dictionary("a=1, b=2, a=3;p=1;p=2")
H.eq(#dorder, 2, "duplicate key keeps one entry")
H.eq(dorder[1], "a", "in the position of its first occurrence")
H.eq(dup.a.value.value, 3, "with the value of its last")
H.eq(#dup.a.params, 1, "duplicate parameter keeps one entry")
H.eq(sf.param(dup.a.params, "p").value, 2, "with the value of its last")
H.eq(sf.serialize(sf.parse("a=1, b=2, a=3", "dictionary")), "a=3, b=2")
local num = sf.parse_item("-12.340")
H.eq(num.value.type, "decimal")
H.eq(num.value.value, -12.34)
H.eq(sf.serialize_item(num), "-12.34", "canonical decimal drops trailing zeros")
H.eq(sf.parse_item("@1659578233").value.type, "date")
H.eq(sf.serialize_item(sf.parse_item("@-1")), "@-1")
local ds = sf.parse_item('%"f%c3%bc%c3%bc"')
H.eq(ds.value.type, "displaystring")
H.eq(ds.value.value, "f\195\188\195\188", "percent-decoded UTF-8")
H.eq(sf.serialize_item(ds), '%"f%c3%bc%c3%bc"')
H.eq(#sf.parse("1, (a b);x, c", "list").members, 3, "List fields parse")
H.pass("duplicates keep first position and last value; decimals, dates, display strings and Lists parse and re-serialize")

-- 7. Empty field and empty inner list.
local _, eorder = sf.parse_dictionary("")
H.eq(#eorder, 0)
H.eq(#sf.parse_dictionary("a=()").a.items, 0)
H.pass("empty dictionary and empty inner list parse cleanly")

-- 8. RFC 9651 4.2's MAY: lines that combine (", ") into a valid field, one of
-- which does not parse alone, fail every_line; lines that each parse pass.
H.eq(sf.every_line(nil, sf.parse_dictionary), true, "no field")
H.eq(sf.every_line({ 'a="x' }, sf.parse_dictionary), true, "one line is the combined value: parsed by the caller")
H.eq(sf.every_line({ "a=1", "b=2" }, sf.parse_dictionary), true)
local split = { 'a="x', 'y"' }
H.eq(sf.parse_dictionary(table.concat(split, ", ")).a.value.value, "x, y", "combined, the two lines are one valid String")
H.eq(sf.every_line(split, sf.parse_dictionary), false, "a line alone does not parse")
H.pass("every_line: each line of a multi-line field must parse alone (RFC 9651 4.2 MAY)")

-- 9. RFC 9651 4.2.10 refuses a Display String that is not UTF-8 (RFC 3629 4).
-- The corpus's invalid cases all fail at the first continuation byte, so
-- these reach the guards it never does: E0's raised floor, F4's lowered
-- ceiling and the later continuation bytes; the valid ones pin F1-F3 and the
-- last code point from the other side.
for _, b in ipairs({
    { '%"%e0%80%af"', "overlong '/' (E0 needs A0-BF next)" },
    { '%"%f4%90%80%80"', "U+110000, above U+10FFFF (F4 needs 80-8F next)" },
    { '%"%e2%82%28"', "third byte not a continuation byte" },
}) do
    H.raises(function() sf.parse_item(b[1]) end, b[2])
end
for _, g in ipairs({
    { '%"%f1%80%80%80"', "\241\128\128\128", "U+40000" },
    { '%"%f4%8f%bf%bf"', "\244\143\191\191", "U+10FFFF" },
}) do
    local item = sf.parse_item(g[1])
    H.eq(item.value.type, "displaystring", g[3])
    H.eq(item.value.value, g[2], g[3] .. " decoded")
    H.eq(sf.serialize_item(item), g[1], g[3] .. " re-serialized")
end
H.pass("Display Strings: overlong E0, F4 above U+10FFFF and a bad third byte refused; U+40000 and U+10FFFF parse")

H.done("test_structured_fields")
