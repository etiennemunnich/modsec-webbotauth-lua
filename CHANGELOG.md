# Changelog

Versioning: git tags are `v0.1.0-alpha.N`. Every ModSecurity rule this plugin ships (and the bot-list rules `lists.ts` writes) carries `ver:'web-bot-auth-plugin/0.1.0'` for the whole 0.1.0 alpha line. After a version bump merges to `main`, a maintainer tags that commit and publishes a GitHub Release from this file. There is no automated release workflow.

## v0.1.0-alpha.2 (2026-10-23)

Second public alpha, for testing on test sites. Not for production use. The rule version string stays `web-bot-auth-plugin/0.1.0`.

Changes since v0.1.0-alpha.1:

- Hardening: the nginx guard that answered 400 for signed requests over plain HTTP or with an absolute-form request line is gone. Signed plain HTTP verifies (draft 6.1 is a declared deviation); absolute-form vs `Host` is a known limit. Replay counters follow the signature's own expiry; an internal error clears grant and identity; the JSON log line includes the `Host` header.
- Key sync and bot lists: `--allow-private-origin` never covers a CIMD document's `jwks_uri` hop; `lists.ts` takes `--allow-private-url` (exact URL); control characters are stripped from key sync output; a bad `agents.txt` line leaves the store untouched.
- Docs rewritten for a public alpha (operator README, GETTING-STARTED, TESTING, SECURITY, issue forms). No private-repo wording in workflow comments.
- CI: suites plus live on Finch and Docker (`run.sh`, Quick start, real-IP, go-ftw, ftw-planted, registry, bot-lists, paranoia; getting-started on Docker only), ASH security scan, workflow lint, monthly CRS matrix, manual interop.
- GETTING-STARTED: `chmod 644` after writing the logrotate config so a loose Docker-exec umask does not make logrotate ignore the file.
- Dependabot: GitHub Actions pin bumps.

## v0.1.0-alpha.1 (2026-10-12)

First public alpha, for testing on test sites. Not for production use.

- Checks Web Bot Auth signatures (RFC 9421 HTTP Message Signatures, draft-ietf-webbotauth-httpsig-protocol-00) inside ModSecurity v3 and the OWASP CRS, in Lua 5.3 on the official CRS nginx image.
- Base image: `owasp/modsecurity-crs:4.30.0-nginx-202610051210` (ModSecurity 3.0.17, CRS 4.30.0).
- Rule IDs 9534000-9534999. Every rule in `wba.conf` and `recipes.conf` carries the tag `web-bot-auth` and the version `web-bot-auth-plugin/0.1.0`, and each one that logs has a severity.
- Setting `tx.web-bot-auth-plugin_enabled=0` turns the verifier off. The bot-list rules that `lists.ts` writes do not read it and keep running.
- The two entry scripts (`modsecurity_entry.lua`, `wba_log.lua`) are loaded with `SecRuleScript`, so nginx does not start when either does not compile. The modules they load are compiled per request: a syntax error in one makes every signed request `unverified/engine-error`.
- Tested at CRS paranoia levels 1 to 4, over HTTP/1.1 and HTTP/2.
- `wba-keysync`: downloads bot keys, checks a list of bots against each operator's own sources, writes `agents.txt` from that list, writes IP and User-Agent rules from it (`lists.ts`), prints a suggested `robots.txt` (`robots.ts`), signs test requests, reports what the WAF saw, and cleans up replay files.
- Six example rules in `lua/wba/recipes.conf`.
- go-ftw tests for the rules in `tests/regression/`, sent through a test bot that signs them.
- GitHub Actions workflows: the suites on the runner, the container tests on Finch and on Docker, a security scan, a workflow lint, a manual interop check and a monthly run across the CRS images of the last 12 months (`lua/tests/live/crs-images.txt`).
- `lua/wba/GETTING-STARTED.md` installs nginx, ModSecurity, the CRS and the plugin on Debian 13 without the image.
- Known limits: the Known limits section of `lua/wba/README.md`. Among them: the key store can be probed, some platforms sign every customer's traffic with one key, the recipes need request body access on, and site names are one list for the whole plugin, not per port.

Decided in a review against RFC 9421 and the draft:

- A space in a signed query parameter (`@query-param`) verifies whether the bot encoded it as `+` or as `%20`. RFC 9421 gives one spelling in its steps and the other in its example.
- There is no cap on a signature's window (`created` to `expires`) by default. A signature counts for at most an hour after it was made (`tx.wba_max_age`, 3600 seconds). With the maximum age turned off, the window may be at most a day.
- `wba-keysync` reads a JWK Set URL or a client metadata document whatever its `Content-Type`, as long as the body is JSON with usable keys. Only the well-known key directory must answer with the directory media type.
- A `Signature-Agent` key directory that is more than an origin (it has a path or a query) is ignored (`unverified/bad-agent-url`), whatever its scheme. An origin that is not `https` is `invalid/agent-not-https`.
- The `Accept-Signature` header that nginx sends asks for `@authority`, `@method`, `@path` and `signature-agent`. `@method` and `@path` are what a grant needs by default.
- Recipes A and D match `/agents` with or without a trailing slash, and `/agents;jsessionid=x/`.
- An RSA key over 3072 bits with a public exponent over 64 bits is refused, because OpenSSL cannot verify with it.
- `@target-uri` counts as `@path` in `tx.wba_require_components` and in `tx.wba_grant_require_components`.
- The `Signature-Agent` header is parsed once per request, not once per signature, and the key store is read and indexed once per request. A request with many signatures stays cheap.
