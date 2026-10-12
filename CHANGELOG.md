# Changelog

## v0.1.0-alpha.1

First alpha, for a few testers. Not for production use.

- Checks Web Bot Auth signatures (RFC 9421 HTTP Message Signatures, draft-ietf-webbotauth-httpsig-protocol-00) inside ModSecurity v3 and the OWASP CRS, in Lua 5.3 on the official CRS nginx image.
- Base image: `owasp/modsecurity-crs:4.30.0-nginx-202610051210` (ModSecurity 3.0.17, CRS 4.30.0).
- Rule IDs 9534000-9534999. Every rule carries the tag `web-bot-auth` and a version, and every rule that logs has a severity. Setting `tx.web-bot-auth-plugin_enabled=0` turns the plugin off.
- The Lua runs through `SecRuleScript`, so ModSecurity refuses to start when a script does not compile.
- Tested at CRS paranoia levels 1 to 4, over HTTP/1.1 and HTTP/2.
- `wba-keysync`: downloads bot keys, checks a list of bots against each operator's own sources, writes `agents.txt` from that list, writes IP and User-Agent rules from it (`lists.ts`), prints a suggested `robots.txt` (`robots.ts`), signs test requests, reports what the WAF saw, and cleans up replay files.
- Six example rules in `lua/wba/recipes.conf`.
- go-ftw tests for the rules in `tests/regression/`, sent through a test bot that signs them.
- `lua/wba/GETTING-STARTED.md` installs nginx, ModSecurity, the CRS and the plugin on Debian 13 without the image.
- Known limits: see the README.

Settled in a review against RFC 9421 and the draft before this alpha:

- A space in a signed query parameter may be sent as `+` or as `%20`. Both verify (RFC 9421 gives one in its steps and the other in its example).
- No limit on a signature's window by default: a signature already counts for only an hour after it was made. With that hour turned off, the limit is a day.
- `wba-keysync` reads a JWK Set URL or a client metadata document whatever its `Content-Type`, as long as it is JSON with good keys. Only the well-known key directory needs its own media type.
- A `Signature-Agent` key directory that is more than an origin is ignored (`unverified/bad-agent-url`), whatever its scheme. An origin that is not `https` is still `invalid/agent-not-https`.
- The `Accept-Signature` header now asks for `@method` and `@path` too, which a grant needs.
- Recipes A and D also cover `/agents` without a slash and `/agents;jsessionid=x/`.
- An RSA key over 3072 bits with a public exponent over 64 bits is refused, because OpenSSL cannot verify with it.
- `@target-uri` meets a required `@path` in `tx.wba_require_components`, as it already did for a grant.
- A request with many signatures costs less: each value is checked once per request, and the key store is indexed once.
- More known limits in the README: the key store can be probed, shared platform keys, request body access, and site names per port.
