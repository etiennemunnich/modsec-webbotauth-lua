-- test_components.lua: components.lua against RFC 9421's own examples, byte
-- for byte (sections 2.1, 2.1.1, 2.1.2, 2.1.3, 2.2.4, 2.2.5, 2.2.7, 2.2.8),
-- plus the URL Standard's decoding rules @query-param depends on.
-- Run: lua lua/tests/test_components.lua
package.path = ((arg[0]:match("(.*/)") or "./") .. "?.lua;") .. package.path
local H = require("helpers")
local sf = require("wba.structured_fields")
local c = require("wba.components")

--- A request as modsecurity_entry.lua builds it. headers: { {name, value}, ... }
local function req(o)
    local fields = {}
    for _, h in ipairs(o.headers or {}) do
        local name = h[1]:lower()
        fields[name] = fields[name] or {}
        table.insert(fields[name], h[2])
    end
    return { fields = fields, method = o.method or "GET", authority = o.authority or "www.example.com",
             path = o.path, query = o.query, scheme = o.scheme or "https" }
end

--- The component value for an identifier string, or "ERR:<reason>".
local function value(r, identifier, types)
    local v, why = c.value(r, sf.parse_item(identifier), types)
    return v or ("ERR:" .. why)
end

--- The RFC's signature-base line for an identifier.
local function line(r, identifier, types)
    return sf.serialize_item(sf.parse_item(identifier)) .. ": " .. value(r, identifier, types)
end

-- 1. 2.1 HTTP fields: instances combined with ", ", whitespace trimmed.
local r21 = req({ path = "/", headers = {
    { "Host", "www.example.com" }, { "X-OWS-Header", "   Leading and trailing whitespace." },
    { "Cache-Control", "max-age=60" }, { "Cache-Control", "   must-revalidate" },
    { "Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c)" }, { "X-Empty-Header", "" } } })
H.eq(line(r21, '"x-ows-header"'), '"x-ows-header": Leading and trailing whitespace.')
H.eq(line(r21, '"cache-control"'), '"cache-control": max-age=60, must-revalidate')
H.eq(line(r21, '"example-dict"'), '"example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c)')
H.eq(line(r21, '"x-empty-header"'), '"x-empty-header": ')
H.eq(value(r21, '"x-absent"'), "ERR:missing-component")
local rfold = req({ path = "/", headers = { { "X-Obs-Fold-Header", "Obsolete\r\n    line folding." } } })
H.eq(line(rfold, '"x-obs-fold-header"'), '"x-obs-fold-header": Obsolete line folding.', "2.1 step 3: obs-fold")
H.eq(c.unfold("a\r\nb"), "a\r\nb", "a CRLF without following whitespace is not obs-fold")
H.eq(c.unfold("a  \r\n\t b\r\n c"), "a b c")
H.pass("2.1: field values combined with ', ', trimmed and unfolded; an empty field is the empty string")

-- 2. 2.1.1 ;sf, strict re-serialization, needs the field's type.
H.eq(line(r21, '"example-dict";sf', { ["example-dict"] = "dictionary" }), '"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)')
H.eq(value(r21, '"example-dict";sf'), "ERR:unsupported-component", "type unknown: an error, as 2.1.1 says")
local rp = req({ path = "/", headers = { { "Priority", "u=3,   i" }, { "Accept-CH", "Sec-CH-UA,  Sec-CH-UA-Platform" } } })
H.eq(line(rp, '"priority";sf'), '"priority";sf: u=3, i', "IANA-registered Dictionary")
H.eq(line(rp, '"accept-ch";sf'), '"accept-ch";sf: Sec-CH-UA, Sec-CH-UA-Platform', "IANA-registered List")
H.eq(value(req({ path = "/", headers = { { "Priority", "u=3, ===" } } }), '"priority";sf'), "ERR:missing-component", "malformed")
H.pass("2.1.1: ;sf re-serializes known Structured Fields; unknown types and malformed values are errors")

-- 3. 2.1.2 ;key, a Dictionary member, strictly serialized.
local r212 = req({ path = "/", headers = { { "Example-Dict", " a=1, b=2;x=1;y=2, c=(a   b    c), d" } } })
H.eq(line(r212, '"example-dict";key="a"'), '"example-dict";key="a": 1')
H.eq(line(r212, '"example-dict";key="d"'), '"example-dict";key="d": ?1')
H.eq(line(r212, '"example-dict";key="b"'), '"example-dict";key="b": 2;x=1;y=2')
H.eq(line(r212, '"example-dict";key="c"'), '"example-dict";key="c": (a b c)')
H.eq(value(r212, '"example-dict";key="z"'), "ERR:missing-component", "2.1.2: an absent key is an error")
H.eq(value(req({ path = "/", headers = { { "Accept-CH", "sec-ch-ua, x" } } }), '"accept-ch";key="x"'),
    "ERR:unsupported-component", "2.1.2 is for Dictionaries: a field IANA types as a List is refused")
H.pass("2.1.2: ;key selects and strictly serializes one Dictionary member")

-- 4. 2.1.3 ;bs, each instance wrapped as a Byte Sequence.
local rbs2 = req({ path = "/", headers = { { "Example-Header", "value, with, lots" }, { "Example-Header", "of, commas" } } })
local rbs1 = req({ path = "/", headers = { { "Example-Header", "value, with, lots, of, commas" } } })
H.eq(line(rbs2, '"example-header";bs'), '"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:')
H.eq(line(rbs1, '"example-header";bs'), '"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:')
H.eq(value(req({ path = "/", headers = { { "X-A", "caf\195\169" } } }), '"x-a";bs'), ":Y2Fmw6k=:",
    "non-ASCII bytes travel as base64, which is the point of ;bs")
H.pass("2.1.3: ;bs wraps each instance, so two instances and one combined value differ")

-- 5. 2.2.4 @scheme, 2.2.5 @request-target, 2.2.7 @query.
H.eq(line(req({ path = "/path", query = "param=value", scheme = "http" }), '"@scheme"'), '"@scheme": http')
H.eq(value(req({ path = "/", scheme = "HTTPS" }), '"@scheme"'), "https", "lowercased")
H.eq(line(req({ path = "/path", query = "param=value" }), '"@request-target"'), '"@request-target": /path?param=value')
H.eq(value(req({}), '"@request-target"'), "ERR:missing-component", "non-origin-form: the request-line target is not available")
H.eq(line(req({ path = "/path", query = "param=value&foo=bar&baz=bat%2Dman" }), '"@query"'),
    '"@query": ?param=value&foo=bar&baz=bat%2Dman')
H.eq(line(req({ path = "/path", query = "queryString" }), '"@query"'), '"@query": ?queryString')
H.eq(line(req({ path = "/path" }), '"@query"'), '"@query": ?')
H.pass("2.2.4, 2.2.5, 2.2.7: @scheme, @request-target and @query as in the RFC's examples")

-- 6. 2.2.8 @query-param, both RFC examples. A space is "+", as the steps'
-- serializer gives it; the RFC's second example prints "%20", so a name
-- spelled that way is the same name and its value is spelled the same way
-- (test_verify 14d checks both spellings end to end; CONFORMANCE.md choice 9).
local q1 = req({ path = "/path", query = "param=value&foo=bar&baz=batman&qux=" })
H.eq(line(q1, '"@query-param";name="baz"'), '"@query-param";name="baz": batman')
H.eq(line(q1, '"@query-param";name="qux"'), '"@query-param";name="qux": ')
H.eq(line(q1, '"@query-param";name="param"'), '"@query-param";name="param": value')
local q2 = req({ path = "/parameters",
    query = "var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something" })
H.eq(line(q2, '"@query-param";name="var"'), '"@query-param";name="var": this+is+a+big%0Amultiline+value')
H.eq(line(q2, '"@query-param";name="bar"'), '"@query-param";name="bar": with+plus+whitespace')
H.eq(line(q2, '"@query-param";name="fa%C3%A7ade%22%3A+"'), '"@query-param";name="fa%C3%A7ade%22%3A+": something')
H.eq(value(q2, '"@query-param";name="fa%C3%A7ade%22%3A%20"'), "something",
    "the example's %20 spelling of the name is the same name")
local q3 = req({ path = "/p", query = "a%20b=c+d" })
H.eq(value(q3, '"@query-param";name="a%20b"'), "c%20d", "a %20-spelled name gives a %20-spelled value")
H.eq(value(q3, '"@query-param";name="a+b"'), "c+d", "a +-spelled name gives a +-spelled value")
H.pass("2.2.8: both RFC examples, every byte as printed in either spelling of a space")

-- 7. 2.2.8 rules and the URL Standard's decoding.
local function qp(query, name) return value(req({ path = "/", query = query }), '"@query-param";name="' .. name .. '"') end
H.eq(qp("a=1&b=2", "z"), "ERR:missing-component", "absent name is an error")
H.eq(qp("a=1&a=2", "a"), "ERR:missing-component", "a repeated name MUST NOT be included")
H.eq(value(req({ path = "/", query = "a=1" }), '"@query-param"'), "ERR:unsupported-component", "name is REQUIRED")
H.eq(value(req({ query = "a=1" }), '"@query-param";name="a"'), "ERR:missing-component", "non-origin-form: query unavailable")
H.eq(qp("a", "a"), "", "no '=' means an empty value")
H.eq(qp("=v&&b=2", ""), "v", "empty name; empty sequences skipped")
H.eq(qp("q=a!b'c(d)e~f*g-h.i_j", "q"), "a%21b%27c%28d%29e%7Ef*g-h.i_j", "form set: only alphanumerics and *-._ stay literal")
H.eq(qp("q=%2B+%2b", "q"), "%2B+%2B", "%2B is '+' (stays %2B), '+' is a space (re-encoded '+')")
H.eq(qp("q=100%&r=%zz", "q"), "100%25", "a '%' without two hex digits stays a '%'")
H.eq(qp("q=%FF", "q"), "%EF%BF%BD", "invalid UTF-8 becomes U+FFFD")
H.eq(qp("q=%E2%82", "q"), "%EF%BF%BD", "a truncated sequence is one U+FFFD (maximal subpart)")
H.eq(qp("q=%C0%80", "q"), "%EF%BF%BD%EF%BF%BD", "an overlong form is one U+FFFD per byte")
H.eq(qp("q=%ED%A0%80", "q"), "%EF%BF%BD%EF%BF%BD%EF%BF%BD", "an encoded surrogate is one U+FFFD per byte")
H.eq(qp("q=%E2%82%ACx", "q"), "%E2%82%ACx", "valid UTF-8 is kept")
H.pass("2.2.8 errors (absent, repeated, unnamed) and URL Standard decoding: '+', stray '%', U+FFFD replacement")

-- 8. Differential: every vector the runtime's WHATWG URLSearchParams produced
-- (query-param/gen.ts; Bun and Node agree byte for byte).
local n, mismatches = 0, {}
for l in H.read(H.here .. "query-param/vectors.tsv"):gmatch("[^\n]+") do
    local query, name, want = l:match("^([^\t]*)\t([^\t]*)\t([^\t]*)$")
    local got = qp(query, name)
    if want == "!" then want = "ERR:missing-component" end
    n = n + 1
    if got ~= want then mismatches[#mismatches + 1] = ("%q name=%q got %q want %q"):format(query, name, got, want) end
end
for _, m in ipairs(mismatches) do print("MISMATCH: " .. m) end
H.eq(#mismatches, 0, #mismatches .. " of " .. n .. " @query-param vectors disagree with URLSearchParams")
H.pass(n .. " differential @query-param vectors agree with WHATWG URLSearchParams")

-- 9. 2.2.8 defines one parameter for @query-param, name. Any other one is not
-- understood, so the identifier is refused, never read as plain name="id".
local qid = req({ path = "/", query = "id=1" })
H.eq(value(qid, '"@query-param";name="id"'), "1", "name alone: the value")
H.eq(value(qid, '"@query-param";name="id";x'), "ERR:unsupported-component", "an extra parameter after name")
H.eq(value(qid, '"@query-param";x;name="id"'), "ERR:unsupported-component", "an extra parameter before name")
H.pass("2.2.8: @query-param with a parameter other than name is unsupported-component")

H.done("test_components")
