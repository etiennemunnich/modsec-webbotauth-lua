# ModSecurity's regular expression work limit and signed requests: evidence

Captured 2026-10-12 by [`lua/tests/live/pcre-limit.sh`](../../tests/live/pcre-limit.sh) (67 of 67 checks passed) on the Debian 13 setup that [GETTING-STARTED.md](../GETTING-STARTED.md) builds. The script runs the page as written in a clean `debian:trixie` container, then probes it. Versions:

- nginx 1.26.3 (`nginx` 1.26.3-3+deb13u9)
- libmodsecurity 3.0.14 (`libmodsecurity3t64` 3.0.14-1+deb13u1)
- ModSecurity-nginx (the connector) 1.0.3 (`libnginx-mod-http-modsecurity` 1.0.3-2+b3)
- PCRE2 10.46 (`libpcre2-8-0` 10.46-1~deb13u3), the regular expression library libmodsecurity uses
- CRS 4.30.0, from the CRS release
- Lua 5.3.6 (`liblua5.3-0` 5.3.6-2+b4), lua-openssl 0.11.1 (commit `bd640c2`)
- arm64, on Finch

## The question

ModSecurity caps how much work one regular expression match may do (`SecPcreMatchLimit` and `SecPcreMatchLimitRecursion`). ModSecurity's sample configuration, `modsecurity.conf-recommended`, sets both to 1,000. The CRS image uses 100,000, and GETTING-STARTED.md copies that. Does 1,000 refuse real signed requests? Signed requests carry long header values: a 4096-bit RSA signature is 684 characters of base64, and CRS runs many regular expressions over every header.

## The answer

No. With both limits at 1,000, no request we sent made any regular expression reach the limit, at paranoia level 1 or 4, signed or not. Every request got the same answer at 1,000 as at 100,000, and every signed one was verified. At level 4 we went lower still: at 60, no regular expression on a signed request reached the limit. The first requests to reach it were ordinary browser requests at 60 (their long `Accept` header, CRS rule 920600). At 40 every request did, signed or not (the request line, rule 920100).

So GETTING-STARTED.md keeps 100,000: it leaves more room, and it is what CRS and the plugin are tested with. The comment next to the setting there says what was tested.

We also found that rule 200005, which is meant to refuse a request where the limit was reached, sees only some of those requests ([below](#where-rule-200005-looks)).

## What was sent

Each request carries `X-WBA-Test` with its name, so its audit log entry can be found. A test-only rule (9534990, phase 5) flags any request where a regular expression reached the limit. The debug log (level 4) names each such expression: the rule, and what it was reading.

- Signed by `lua/tests/live/gen.lua`, which signs with openssl. Each request is Ed25519, RSA-PSS with a 2048-bit key, or RSA-PSS with a 4096-bit key. Each is sent as a `GET /agents/hello`, and as a `POST /api/search` whose JSON body's sha-256 `Content-Digest` is signed: `{"query": "weather in Sydney tomorrow", "page": 2, "filters": {"lang": "en-AU", "safe": true}}`.
- Signed by the page's test bot, `wba-keysync/sign.ts`: Ed25519 with a nonce, covering `@method`, `@authority`, `@path` and `Signature-Agent`.
- Unsigned:
  - a browser's request for `/`, with a Chrome `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`, `Cookie`, `Sec-Fetch-*` and `Upgrade-Insecure-Requests`;
  - the same browser searching: `GET /search?q=red+running+shoes&size=10&sort=price_asc&page=2`;
  - a login form: `POST /login` with `username=alice%40example.com&password=correct+horse+battery+staple&remember=on`;
  - a JSON API call (the body above, unsigned);
  - `GET /agents/hello`, which recipe A refuses and asks to be signed.

## Results: 100,000 and 1,000

Every row is the same at 1,000 and at 100,000 (both limits set to that value), so each request is listed once per paranoia level. "Refused by" is the rule in nginx's error log, followed by the CRS rules the audit log lists. "wba.log" is the plugin's outcome for that request.

| PL | Request | HTTP | Refused by | Regular expressions that hit the limit | wba.log |
|---|---|---|---|---|---|
| 1 | signed, Ed25519, GET /agents/hello | 200 | - | none | verified/ |
| 1 | signed, Ed25519, POST /api/search with a signed JSON body | 200 | - | none | verified/ |
| 1 | signed, RSA-PSS 2048-bit key, GET /agents/hello | 200 | - | none | verified/ |
| 1 | signed, RSA-PSS 2048-bit key, POST with a signed JSON body | 200 | - | none | verified/ |
| 1 | signed, RSA-PSS 4096-bit key, GET /agents/hello | 200 | - | none | verified/ |
| 1 | signed, RSA-PSS 4096-bit key, POST with a signed JSON body | 200 | - | none | verified/ |
| 1 | signed by the page's test bot (sign.ts, Ed25519, with a nonce), GET /agents/hello | 200 | - | none | verified/ |
| 1 | unsigned, a browser's request for / | 200 | - | none | - |
| 1 | unsigned, a browser's search, GET /search?q=red+running+shoes&size=10&sort=price_asc&page=2 | 200 | - | none | - |
| 1 | unsigned, a browser's login form, POST /login | 200 | - | none | - |
| 1 | unsigned, a JSON API call, POST /api/search | 200 | - | none | - |
| 1 | unsigned, GET /agents/hello (recipe A asks for a signature) | 403 | 9534130 | none | - |
| 4 | signed, Ed25519, GET /agents/hello | 200 | - | none | verified/ |
| 4 | signed, Ed25519, POST /api/search with a signed JSON body | 403 | 949110 (CRS: 920273) | none | verified/ |
| 4 | signed, RSA-PSS 2048-bit key, GET /agents/hello | 200 | - | none | verified/ |
| 4 | signed, RSA-PSS 2048-bit key, POST with a signed JSON body | 403 | 949110 (CRS: 920273) | none | verified/ |
| 4 | signed, RSA-PSS 4096-bit key, GET /agents/hello | 200 | - | none | verified/ |
| 4 | signed, RSA-PSS 4096-bit key, POST with a signed JSON body | 403 | 949110 (CRS: 920273) | none | verified/ |
| 4 | signed by the page's test bot (sign.ts, Ed25519, with a nonce), GET /agents/hello | 200 | - | none | verified/ |
| 4 | unsigned, a browser's request for / | 200 | - | none | - |
| 4 | unsigned, a browser's search, GET /search?q=red+running+shoes&size=10&sort=price_asc&page=2 | 403 | 949110 (CRS: 920273,932236) | none | - |
| 4 | unsigned, a browser's login form, POST /login | 403 | 949110 (CRS: 920273) | none | - |
| 4 | unsigned, a JSON API call, POST /api/search | 403 | 949110 (CRS: 920273) | none | - |
| 4 | unsigned, GET /agents/hello (recipe A asks for a signature) | 403 | 9534130 | none | - |

**Why every POST is refused at level 4, at both values.** CRS rule 920273 (level 4) allows only letters, digits and `& , - . : = _` in request arguments. A JSON body's spaces, quotes and braces fall outside that, and so does the `@` in the login form. This is CRS's normal behaviour at level 4, the same for signed and unsigned requests, and it has nothing to do with the limit. The plugin verified each signed POST (the wba.log column) before CRS refused it.

## How low can it go?

The script records these runs but does not check them. All at level 4, the strictest, with the same 12 requests:

| Both limits, PL 4 | Requests refused by rule 200005 | Signed requests among them | Regular expressions that hit the limit (rule:what it read) |
|---|---|---|---|
| 500 | 0 of 12 | 0 of 7 | none |
| 250 | 0 of 12 | 0 of 7 | none |
| 120 | 0 of 12 | 0 of 7 | none |
| 60 | 3 of 12 | 0 of 7 | 920600:REQUEST_HEADERS:Accept |
| 40 | 12 of 12 | 7 of 7 | 920100:REQUEST_LINE, 920600:REQUEST_HEADERS:Accept |

At 60, no regular expression on a signed request reached the limit: none needed as much as 60 of the work this library counts. At 40, every request was refused in phase 1, on its request line, before any rule read the signature headers. The signature headers never became the costly part.

Two cautions. PCRE2 counts this work in its own units, and another build (another PCRE2 version, or the old PCRE library) may count differently. So these numbers show the room this build has, not a value for everyone. And the test always changed both settings together, as the guide and the sample configuration set them, so it does not tell their effects apart.

## Where rule 200005 looks

When a regular expression reaches the limit, ModSecurity gives up, treats it as **no match**, and sets `TX:MSC_PCRE_LIMITS_EXCEEDED` (libmodsecurity 3.0.14, `src/operators/rx.cc`). Rule 200005 refuses a request where any such flag is set. But ModSecurity runs the rules of each phase in the order they were loaded. `modsecurity.conf` is loaded first, so rule 200005 runs at the start of phase 2, before every CRS rule in phase 2. Almost all of CRS's attack rules (files 930 to 944) run in phase 2, and CRS 4.30.0 never reads that flag itself.

The test shows this with a test-only rule, `SecRule ARGS_GET:probe "@rx ^(a+)+$"`. That expression's work roughly doubles with each extra `a` when the text ends in `b`, so 30 letters `a` then `b` reach a limit of 1,000. Both limits were 1,000, at level 4:

| The test rule runs in | Request | Response | Refused by |
|---|---|---|---|
| phase 2 | `GET /?probe=aaaa` (it matches; no limit reached) | 418 | the test rule (9534991) |
| phase 2 | `GET /?probe=` 30 × `a`, then `b` (limit reached) | **200** | **nothing** |
| phase 1 | the same | 403 | 200005 |
| phase 2, with a copy of rule 200005 in a `plugins/*-after.conf` file | the same | 403 | the copy (9534992) |

**What this means.** In phase 2, reaching the limit causes a missed detection, not a refusal. If an attacker can make a CRS rule's regular expression reach the limit, that rule does not match, and rule 200005 does not catch it. This is true at any limit, but a lower limit makes it easier: the attacker needs less costly input. That is one more reason to keep 100,000. ModSecurity's sample configuration places rule 200005 the same way, so this is not specific to the guide. It is already reported upstream and open since July 2025: [ModSecurity issue #3415](https://github.com/owasp-modsecurity/ModSecurity/issues/3415), "Recommended rule 200005 misses MSC_PCRE_LIMITS_EXCEEDED in phase 2". This probe reproduces it on libmodsecurity 3.0.14 with CRS 4.30.0.

**A fix you can add:** a copy of rule 200005 in a CRS plugin "after" file, so it also runs after CRS's phase 2 rules, as the last row shows. The copy needs a rule id of your own. GETTING-STARTED.md does not add it; whether to add it is your choice.

## Rerun

```bash
bash lua/tests/live/pcre-limit.sh                 # Finch (DOCKER=docker for Docker), about 8 minutes
REPORT=out.md bash lua/tests/live/pcre-limit.sh   # also writes the results to out.md, one row per limit
```

It fails if any request reaches the limit at 1,000 or at 100,000, if any request gets a different answer at the two values, if a signed request is not verified, or if rule 200005 starts or stops catching the test rule's hits. It is not part of `run_all.sh`.
