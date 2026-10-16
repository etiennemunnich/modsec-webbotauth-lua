# Web Bot Auth for ModSecurity: design and reasons

Read [HOW-IT-WORKS.md](HOW-IT-WORKS.md) first: it has the diagrams and defines the terms. The [README](README.md) says how to set the plugin up and use it. This page says why it works the way it does. [TESTING.md](TESTING.md) says what is proven and how; [CONFORMANCE.md](CONFORMANCE.md) traces every sentence of the standards.

## What `verified` means

Exactly this, and nothing weaker:

- **The request is for your site.** Its `Host` is one of your site names (`tx.wba_site_names`). Any other host is `invalid/foreign-authority`. Until the names are set, nothing verifies (`unverified/no-site-names`).
- **The signature is tagged `web-bot-auth` and carries `created` and `expires`.** Its times pass these checks:
  - `created` is at most 60 s ahead of this clock (`not-yet-valid`);
  - `expires` has not passed, strictly, unless `tx.wba_expiry_grace` allows up to 60 s more (`expired`);
  - `created` is at most `tx.wba_max_age` seconds ago, an hour by default (RFC 9421 3.2.1, `too-old`);
  - its window (`expires` minus `created`) is no longer than `tx.wba_max_window`, if you set one (`window-too-long`). While the maximum age is on there is no window cap by default, since the age already bounds how long a signature counts (draft 5.2's 24 hours is only RECOMMENDED for signers); with `tx.wba_max_age=0`, the cap is a day.
- **It covers the site and the bot.** It covers `@authority` (or `@target-uri`) and the `Signature-Agent` member it is attributed to (draft 5.2.1). If it covers one member, that one. If it covers several (draft Appendix D.2: an outer signer also covers an inner signer's member), the one keyed to its own label; if none is, `invalid/ambiguous-agent`.
- **That member names a key source you listed.** It is an `https` URL of a supported type (draft 5.5, [Agent URLs](#agent-urls)) whose identifier is in `agents.txt` and was resolved by `wba-keysync`. For `directory` (the default) the identifier is the origin's key directory, `https://<origin>/.well-known/http-message-signatures-directory`; for `jwks_uri` and `cimd`, the URL itself without query or fragment.
- **The key is held for exactly that bot.** The key store holds a current key for that (identifier, keyid) pair. A key never counts for another agent (draft 5.4).
- **The signature is genuine.** Its algorithm is the one RFC 9421 3.2 step 6 determines from the key and the `alg` parameter (they must agree), and it verifies the RFC 9421 signature base rebuilt from this request's raw bytes ([Algorithms](#algorithms)).
- **A covered body digest matches the body.** If it covers `Content-Digest`, `Repr-Digest` or `Unencoded-Digest`, the body matches that digest (RFC 9421 7.2.8, RFC 9530); for `Unencoded-Digest`, once its content codings are removed. See [Body digests](#body-digests).
- **It meets your own settings.** The minimum coverage (`tx.wba_require_components`) and a nonce (`tx.wba_require_nonce`) where you require them. With replay accounting on, its use was counted (`unverified/replay-unavailable` otherwise).

A request with no `Signature-Agent` header is the one exception to the agent bullets: a held key verifies it as `verified/url-less`, attributed to the key alone (see [Agent URLs](#agent-urls)).

A verified signature proves who signed, not that they are benign or authorised (draft 4.1). It is an input to your policy, not a policy.

### Body digests

A signature binds the body only through a digest field it covers. RFC 9421 7.2.8 says the verifier must then check that digest against the content received, and the body arrives after the headers:

- **Phase 1** (headers): a good signature that covers a digest is `unverified/digest-pending`, never `verified`.
- **Phase 2** (body read): a second rule re-runs the whole verification with `REQUEST_BODY`, at phase 1's time, and decides. A match is `verified`. A mismatch, an added body or a removed body is `invalid/digest-mismatch`.
- If phase 2 never runs, the request stays `unverified/digest-pending`: libmodsecurity skips every phase-2 rule when it has not read the body, so a body-bound signature is never verified without its body.

What is checked:

- **Only covered members count.** A bare, `;sf` or `;bs` component covers the whole field; `;key="sha-256"` covers that one member. A member the signature does not cover can be added by anyone on the path, so it is never read.
- **Only Active algorithms** (RFC 9530 5; IANA: `sha-256`, `sha-512`). Deprecated ones (`md5`, `sha` and the checksums) MUST NOT be used where an attacker may be present; with no Active covered member the result is `unverified/digest-algorithm-unsupported`.
- **The strongest covered algorithm decides** (`sha-512`, then `sha-256`). Skipping the weaker cannot be exploited (RFC 9530 6.6, 6.7): a forger would need a SHA-512 collision.
- **What each field is compared with.**
  - **Content-Digest** (RFC 9530 2): the body as received.
  - **Repr-Digest** (RFC 9530 3): the body as received too. A representation is defined in its coded form (RFC 9110 8.4), so a gzip body's Repr-Digest is over the gzip bytes, and nothing is decoded for it.
  - **Unencoded-Digest** ([draft-ietf-httpbis-unencoded-digest-05](https://datatracker.ietf.org/doc/draft-ietf-httpbis-unencoded-digest/) 3, 5): the body with its content codings removed, last applied first. Decoded here: `gzip` (and `x-gzip`) and `deflate`, which is the zlib format (RFC 9110 8.4.1.2), not raw deflate; `identity` is no coding. Any other coding is `unverified/digest-coding-unsupported`, decided in phase 1 ([Not implemented](#not-implemented)). A body that is not valid data in its declared coding is `invalid/bad-content-coding`: truncated, a failed checksum, bytes after the last gzip member or the zlib stream, a zlib preset dictionary (RFC 1950 2.3: HTTP defines none), or the wrong coding.
- **Partial content.** `Content-Range` in a request means something only on PUT (RFC 9110 14.5) and is ignored on any other method, as 14.4 says. On a PUT, Repr-Digest and Unencoded-Digest are checked only when the range is the whole representation, `bytes 0-(n-1)/n` with n bytes of content; anything else is `unverified/digest-partial`. Content-Digest is over the content, so it is checked either way.
- **The received bytes first.** Content-Digest and Repr-Digest are compared before anything is decoded, so a body that fails them never reaches the decoder (the unencoded-digest draft's section 7 mitigation).
- **Incomplete bodies are never compared.** `INBOUND_DATA_ERROR=1` (the body was cut at `SecRequestBodyLimit` or `SecRequestBodyNoFilesLimit`) gives `unverified/body-incomplete`, so a signed prefix can never verify.
- **Cost.** SHA-512 runs in C (OpenSSL through lua-openssl, 0.76 ms per MiB in the CRS image). SHA-256 runs in Lua at about 4.2 MB/s, so a body over `max_sha256_body` (128 KiB, about 31 ms) is not hashed with it: `unverified/body-too-large` (RFC 9530 6.7). For Unencoded-Digest that limit applies to the decoded body. Only a good signature from a key in your store gets a body hashed or decoded, and each algorithm runs at most once per request. The limits are set in code (`CONFIG.policy` in `modsecurity_entry.lua` overrides `verify.lua`'s `DEFAULT_POLICY`).
- **Decoding is bounded.** [`coding.lua`](coding.lua) decodes at 3.2 MB/s in the worst case a sender can build, 9.5 MB/s on typical gzip'd JSON, at most once per request. It stops at `min(max_decoded_body, max_decode_ratio × body length)` units with `unverified/body-too-large`. A decoded byte is one unit, a deflate block 16 more (a dynamic one 1024), a gzip header under FHCRC its length, so floods of empty blocks or a giant header are bounded like output. Defaults: 128 KiB (about 40 ms at worst) and a ratio of 200, Apache httpd's default `DeflateInflateRatioLimit`. A 10 MiB gzip bomb (about 10 KB on the wire) stops there.

**Unencoded-Digest vouches for the decoded representation, not for the bytes.** One representation has many gzip encodings (free-form header fields, several members: RFC 1952 2.2), all decoding to the same bytes. So whoever holds a signature that covers Unencoded-Digest but not Content-Digest can replay it with a re-encoded body. That is harmless only if your application decodes `Content-Encoding` exactly as RFC 1952 and RFC 1950 define it. An application that reads the raw body, or a decoder that stops after the first gzip member (zlib's `inflate()` does, unless called again), can be handed bytes the signer never signed: a prefix, or bytes hidden in a gzip header. If yours might, require the raw bytes signed too, `tx.wba_require_components=content-digest` ([Controls and defaults](README.md#controls-and-defaults)), and cover `Content-Encoding` as well (RFC 9530 6.3).

**In the CRS image, content-coded JSON is refused first.** The image's rule 200001 turns on the JSON body processor for `Content-Type: application/json` without removing `Content-Encoding`, so a gzip JSON body fails to parse and rule 200002 answers 400 in phase 2, before this plugin's phase-2 rule. A coded body with no body processor (`application/octet-stream`, say) reaches it. This is read from the image's configuration, not tested live.

## Algorithms

The algorithms are RFC 9421 3.3's, less `hmac-sha256` (draft 6.4 forbids shared HMAC). Each is implemented exactly as its section says, through OpenSSL ([Crypto dependency](#crypto-dependency)):

| `alg` | Key (JWK) | RFC 9421 | Signature |
|---|---|---|---|
| `ed25519` | OKP, Ed25519 | 3.3.6 | 64 bytes; pure Ed25519, no prehash |
| `ecdsa-p256-sha256` | EC, P-256 | 3.3.4 | r ‖ s, 32 bytes each: 64 bytes, never DER |
| `ecdsa-p384-sha384` | EC, P-384 | 3.3.5 | r ‖ s, 48 bytes each: 96 bytes, never DER |
| `rsa-pss-sha512` | RSA | 3.3.1 | modulus length; SHA-512, MGF1 with SHA-512, salt length exactly 64 |
| `rsa-v1_5-sha256` | RSA | 3.3.2 | modulus length; PKCS #1 v1.5 with SHA-256 |

**Which algorithm** (RFC 9421 3.2 step 6, in order):

- An `alg` parameter naming anything else, `hmac-sha256` included, is `invalid/unsupported-alg` (step 6.1).
- The key gives one if its JWK carries `alg` (key sync stores it), or if its type allows only one: Ed25519, P-256 and P-384 keys do (step 6.3). An RSA key allows two, so its type alone gives none.
- The signature's `alg` parameter gives one (step 6.4).
- Where both give one, they must be the same, or the result is `invalid/alg-mismatch` (step 6.5). An `alg` for another key type is `invalid/alg-mismatch` too (step 8: the key material must be appropriate). So a key whose directory pins it to `rsa-pss-sha512` never verifies a PKCS #1 v1.5 signature (7.3.6).
- Neither: `invalid/alg-undetermined`. Only an RSA key without a JWK `alg`, under a signature without `alg`, gets here; the verifier never guesses.
- A signature of any other length than the table's is `invalid/bad-signature` and never reaches the crypto. A DER-encoded ECDSA signature is the wrong length, so it is refused.
- URL-less (no `Signature-Agent`, draft 4.3): every directory that lists the key must allow the same algorithm, so one directory's pin is never bypassed through another.

**Keys.** Key sync and the store enforce the same rules; RFC 9421 3.2.1 makes key size an application requirement.

- An RSA modulus is 2048 to 16384 bits and odd: the floor is [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) 3.3 and 3.5's for RS256 and PS512, these algorithms' JOSE twins; the ceiling is OpenSSL's.
- An RSA public exponent is odd, at least 3 and below 2^256 (RFC 8017 3.1, plus FIPS 186-5's upper bound). Verification cost grows with the exponent, and any client can make the verifier pay it by naming a held keyid.
- Above 3072 bits, the exponent must be at most 64 bits: OpenSSL verifies nothing with a wider one there (`OPENSSL_RSA_SMALL_MODULUS_BITS`, `OPENSSL_RSA_MAX_PUBEXP_BITS`), so such a key could never verify a request.
- EC coordinates are full size (RFC 7518 6.2.1.2) and the point must be on its curve.

**Cost of one verification** (`crypto.lua` end to end, in the pinned CRS image's test stage, OpenSSL 3.5.7, arm64 under Finch):

| Ed25519 | P-256 | P-384 | RSA 2048 | RSA 4096 | RSA 8192 | RSA 16384 |
|---|---|---|---|---|---|---|
| 0.096 ms | 0.080 ms | 0.47 ms | 0.04 ms | 0.10 ms | 0.30 to 0.42 ms | 1.1 ms |

Loading lua-openssl into the fresh Lua state libmodsecurity builds per run costs another 0.49 ms per signed request. Unsigned requests never run the Lua.

### Covered components

RFC 9421 sections 2.1 and 2.2, each checked against the RFC's own examples:

- Derived: `@method`, `@authority`, `@scheme`, `@path`, `@query`, `@query-param;name="..."`, `@target-uri`, `@request-target`. `@scheme` and `@target-uri` use the scheme configured in `modsecurity_entry.lua` (`CONFIG.scheme`, `https`), because ModSecurity gives Lua no scheme ([What ModSecurity cannot see](#what-modsecurity-cannot-see)). That is the scheme clients use on an HTTPS site, through a load balancer that ends TLS too. A signature made over plain HTTP that covers either does not verify: the bot signed `http`, and the verifier rebuilds `https`.
- Any lowercase header field, all instances trimmed, unfolded and combined per 2.1, optionally with:
  - `;key="..."`, one Dictionary member (2.1.2); refused on a field the IANA registry types as a List or Item;
  - `;sf`, strict re-serialization (2.1.1), for fields whose Structured Field type is known: the IANA field registry's types, plus `Signature-Agent` and `Accept-Signature`;
  - `;bs`, each instance wrapped as a Byte Sequence (2.1.3).

These are refused as `invalid/unsupported-component`, because RFC 9421 2.5 requires an error when a component cannot be resolved: `@status` and `;req` (responses only), `;tr` (trailers never reach ModSecurity's request phase), `;sf` on a field of unknown type, `;bs` combined with `;sf` or `;key`, and unregistered names.

`@query-param` decodes the query with the URL Standard's form parser and re-encodes it with the form percent-encode set, as 2.2.8 says, so spaces become `+`. That is the URL Standard's reading of the query, not necessarily an application's: PHP turns `.` and space in a name into `_` and keeps the last value, so `?a_b=1&a.b=evil` verifies `a_b` as `1` while PHP reads `evil`. Where parameters decide anything, operators require the raw `@query` (`tx.wba_require_components`). The RFC's own example prints `%20` instead. Both spell the same decoded parameters, so both verify: if the `+` base fails while a covered `@query-param` value has a space, the `%20` spelling is tried, at most once per request and only for a key you hold ([CONFORMANCE.md](CONFORMANCE.md), choice 9). A parameter name that appears more than once cannot be signed (2.2.8) and gives `invalid/missing-component`.

### Agent URLs

How a `Signature-Agent` member is read:

- A URL whose scheme is not `https` (`http://bot.example`, say) is `invalid/agent-not-https` (draft 5.2.1), except a `directory` member that is not an origin, which is ignored whatever its scheme (below).
- The `type` parameter (a Token, draft 5.2.1) picks the mechanism: absent or `directory`, `jwks_uri`, `cimd`. Any other type, or a type sent as a String, is ignored, as 5.2.1 requires: `unverified/unsupported-agent-type`. The mechanism is never inferred from the URL.
- `directory`: a value that is not the exact ASCII serialization of an origin (a path, a mixed-case host, an explicit default port such as `https://agent.example:443`, RFC 6454 6.2) is ignored, as draft 5.5 requires, which leaves the request `unverified/bad-agent-url`. An empty path `/` is accepted, as 5.5 allows.
- `jwks_uri` and `cimd`: the identifier is the member value normalized per RFC 3986 6.2.2 and 6.2.3, query and fragment dropped, so every spelling of one URL is one identifier. A value that is not a URI, carries userinfo (RFC 9110 4.2.4), or names a port with a leading zero is ignored: `unverified/bad-agent-url`. Lookup is keyed on (identifier, keyid) whatever the type: a `jwks_uri` member naming a listed directory's well-known URI is that directory.
- IPv6 literal hosts (`https://[2001:db8::1]:8443`) work in every type. The identifier holds the address in RFC 5952 canonical text, so `[2001:0db8:0:0::1]` and `[2001:db8::1]` are one identifier; uppercase hex, a zone identifier or an IPvFuture literal is ignored.
- No `Signature-Agent` header at all: draft 4.3 makes the keyid thumbprint the identifier. A held key (under any identifier in the store) verifies the request as `verified/url-less`, attributed to the key alone; a key not held is `unverified/agent-absent`. A header that is present but whose member the signature does not cover is `invalid/agent-not-covered` (5.2.1).

## Several signatures on one request

When a request carries several `web-bot-auth` signatures, every one is validated, each against its own components and key (draft 5.2.2). The request gets the best outcome, ranked `verified` for a directory > `verified/url-less` > `digest-pending` > `invalid` > `unverified`: a pending signature can still verify in phase 2. `tx.wba_agent` is the first directory verified in Signature-Input order, and `tx.wba_agents` lists them all.

Work that does not grow with the number of signatures is done once per request: each covered value is resolved once, `Signature-Agent` is parsed once, the store is indexed from the second key lookup on, and the `%20` retry runs at most once. So 150 signatures in about 35 KiB of headers (nginx's default limit) cost 9 to 17 ms on the host before the crypto, whatever their shape ([TESTING.md](TESTING.md#cost-of-a-hostile-request)). There is no cap by default, because draft 5.2.2 says verifiers MUST validate each signature; `policy.max_signatures` in `CONFIG.policy` sets one (`unverified/too-many-signatures`). The crypto adds one verification per signature: at most 165 ms for 150 signatures that each name a held 16384-bit RSA key, the largest key sync accepts; about 14 ms for Ed25519.

**Unparsable fields.** A label in only one of `Signature-Input` and `Signature` is `invalid/orphan-label` (RFC 9421 4), Web Bot Auth or not. For a field that is not a valid Structured Field, RFC 9651 4.2 allows ignoring it or treating the message as malformed; `tx.wba_malformed` picks:

- `Signature-Input` or `Signature`: with `ignore` (the default) the field counts as absent, `not-signed/unparsable-field`; with `reject`, `invalid/malformed-headers` and 400 from rule 9534107 (draft 5.4 allows the 400).
- `Signature-Agent`: in the usual form, `"signature-agent";key="sig1"`, the covered member cannot be found in a field that does not parse, so the result is `invalid/missing-component` under both settings, with no 400. Only a signature over the whole field (bare `"signature-agent"`) reaches the agent parse: `invalid/unparsable-agent` with `ignore`; `invalid/malformed-headers` and 400 with `reject`.
- A covered body digest field always takes the malformed branch: `invalid/malformed-digest` and 400. Only a good signature from a key you list reaches that check, and ignoring the field would leave the body unchecked while the signature says it is bound to it.

## What ModSecurity cannot see

ModSecurity sees a request as nginx hands it over. Two facts about the client's request never reach it.

**Whether the client used TLS.** No ModSecurity variable says so, and behind a load balancer that ends TLS, nginx itself receives plain HTTP. So a signed request over plain HTTP is verified like any other. Draft 6.1 says an origin SHOULD refuse Signature headers sent over an unsecured channel. This plugin cannot: that is one of its two declared deviations ([CONFORMANCE.md](CONFORMANCE.md#declared-deviations); the other is the 2 s clock allowance for a directory's [possession proof](#possession-proofs)). Serve signed traffic over HTTPS: over plain HTTP anyone on the path can change what a signature does not cover, or take the whole request and send it first. The same gap is why `@scheme` and `@target-uri` use a configured scheme ([Covered components](#covered-components)).

**The host in a request line that holds a full URL.** For an absolute-form request line (`GET http://other.example/ HTTP/1.1`), nginx serves the host in the request line but hands ModSecurity only what follows it. libmodsecurity reads the `Host` header the client chose, so no ModSecurity variable holds the host nginx served. What follows from that:

- The Lua takes `@path` and `@query` only from a target that starts with `/` (`REQUEST_URI_RAW`, in `modsecurity_entry.lua`). For `GET http://example.com?evil=1` nginx hands over `?evil=1`, so both are unavailable, and a signature that covers either is `invalid/missing-component`.
- `GET http://other.example/ HTTP/1.1` sent with `Host: example.com` reaches ModSecurity as `/` with Host example.com. A signature made for example.com verifies, while nginx serves the request as other.example. It matters whenever a request-line host other than the `Host` header can reach an application: several server blocks, a default block, or `proxy_set_header Host $host` in front of an application that serves several names. The README lists it, with the catch-all server and the replay settings that limit it, under [Known limits](README.md#known-limits).
- A correctly signed `GET http://example.com/` verifies, as RFC 9112 3.2.2 requires. [TESTING.md](TESTING.md#live) lists the other request-line spellings nginx accepts and the live suite sends.
- ModSecurity-nginx v1.0.4, the connector in every official CRS image, reads request headers before any other module can rewrite `Host`, so no nginx setting can show ModSecurity the request-line host.

**What replay accounting does about the full-URL case.** [Replay accounting](#sessions-and-replay) counts this replay: nothing in the signature base differs (nginx passes only the path, and `@authority` is the Host header), so the copy lands in the bot's counter file and reads `tx.wba_uses=2`. But only a rule refuses on that count, and the shipped one, recipe D (rule 9534133), covers `/agents` only. A signature covering only `@authority` and `signature-agent` lets the holder pick the path, so on `/` it is `verified` with uses=2 and nothing refuses it. To make a captured signature count once everywhere:

- set `tx.wba_replay_dir` (rule 9534014), on a filesystem of its own, with `sweep.ts` on a timer;
- either widen recipe D to every path where `verified` or `tx.wba_granted` changes anything, and set `tx.wba_require_components=@method @path` (rule 9534011); or require a nonce (`tx.wba_require_nonce=1`, rule 9534015) and use recipe E (rule 9534134), which is site-wide and never refuses honest traffic;

The limits stay: only the second copy to arrive is refused, and counts are per host.

## wba-keysync in detail

Keys are fetched **out of band**, never on the request path. ModSecurity makes no network calls, and a request's `Signature-Agent` header can never steer a fetch: only URLs you list are fetched, and a CIMD's `jwks_uri` hop only from a document at a URL you listed. Their DNS is still someone else's, so before every fetch, the hop included, key sync refuses a host that is, or resolves to, a private, loopback or link-local address (draft 6.7), unless you name that exact origin with `--allow-private-origin` ([README](README.md#3-keep-their-keys-current)), which covers the URLs `agents.txt` lists there and never the `jwks_uri` hop; the DNS lookup is bounded by the same time limit as the fetch; an IP literal is checked as written and never sent to DNS. A name that changes its answer between that check and the fetch (DNS rebinding) is not caught; TLS certificate validation is what stops that reaching an internal service.

Run it every minute; that is cheap. Each directory is cached under HTTP's rules (draft 5.5.2 and C.4; RFC 9111 freshness, capped at a day) and fetched again only when stale, conditionally (`If-None-Match`, `If-Modified-Since`). So a key a directory removes stops verifying when that directory's cache lifetime says. A failed fetch backs off from 30 s to at most 5 minutes, or for the directory's `Retry-After` (draft C.5).

The same code runs on Bun and Node, tested on Bun 1.3.11 and Node 26.10; so do `sign.ts` and `sweep.ts`. `validate.ts`, `agents.ts`, `report.ts`, `lists.ts` and `robots.ts` need Bun. Older Node versions need native TypeScript type stripping; they are untested. Keep the host's clock NTP-synced: a directory's possession proof whose `created` is more than 2 s ahead of that clock is refused (draft B.1; `proof.ts`).

What it does:

- Every response must be `200`, within 64 KiB, 32 keys and 5 s, and no redirect is followed (draft 5.5, 6.7). At the well-known URI the media type must be `application/http-message-signatures-directory+json` (5.5.1); the draft sets none for a `jwks_uri` or `cimd` response, so any `Content-Type` is read there. It asks for no content coding, so a Content-Digest can be checked against the bytes received.
- It keeps Ed25519 (`OKP`), EC P-256 and P-384, and RSA keys; other key types and curves (X25519, P-521, `oct`) have no algorithm here and are ignored.
- It never trusts `kid`: each key is indexed by the RFC 7638 thumbprint it computes itself (draft 5.2; RFC 8037 A.3 for Ed25519). At the well-known URI a key whose `kid` is not that thumbprint is rejected (draft 5.5: it MUST be); elsewhere `kid` is the bot operator's label and is ignored.
- It checks each key's encoding before computing that thumbprint: strict base64url (no padding, zero pad bits), EC coordinates full size and the point on its curve, RSA `n` and `e` minimal (RFC 7518 2), and the RSA rules under [Algorithms](#algorithms). So each key has one spelling, and one thumbprint.
- A `cimd` document must name itself: its `client_id` is the URL fetched (CIMD 4). Its keys come from `jwks`, or from `jwks_uri` fetched under the same rules, never both (RFC 7591 2); a document with a shared secret is refused (CIMD 4.1). Its freshness is the shorter of the two responses'.
- It rejects keys whose private half is published (draft 6.8): RFC 9421 B.1.1 to B.1.4, RFC 8032 7.1's five, and the JOSE examples (RFC 7517 A.2, RFC 7515 A.2 and A.3); and any key published with private members (`d`, `p`, `k` and the like).
- It reads a key's `alg`, when present, as the HTTP name for its own type ([Algorithms](#algorithms)) or that name's exact JOSE twin (`EdDSA` or `Ed25519`, `ES256`, `ES384`, `PS512`, `RS256`). Draft 5.5.1 restricts `alg` to the HTTP registry but also makes every key set a JWK Set, whose `alg` is a JOSE name (RFC 7517 4.4); no value satisfies both (WG issue #136), and live signers publish the JOSE names ([CONFORMANCE.md](CONFORMANCE.md), item 7b). A key with any other `alg`, or one for another key type, is skipped (RFC 9421 3.2 step 6.5). A valid `alg` is stored as its HTTP name, and the verifier holds every signature to it.
- It validates a directory's [possession proofs](#possession-proofs), with the same algorithm rules, and records each key's in the store. Every key is used either way.
- If a directory resolves without a key, that key is revoked. If a fetch fails, the last-good keys are kept (draft 6.10).
- It writes the store (format version 2: [`keys.lua`](keys.lua)) with an atomic rename, and appends every key added or removed to `<out>.history` for attributing a signature later.

Exit codes, and which to alert on, are in the [README](README.md#3-keep-their-keys-current). A proof that is `invalid` or `none` does not change them.

### Possession proofs

Draft Appendix B lets a directory sign its own response, one HTTP Message Signature per key, so a key set cannot be re-served under another name or swapped under a captured signature. `wba-keysync` checks every such signature (tag `http-message-signatures-directory`) on a directory's response:

- `keyid` is the thumbprint of a key that directory lists, and the signature verifies with that key under the same rules as a request ([Algorithms](#algorithms)): an allowed `alg` that agrees with the key, and the exact signature length. WebCrypto does the verification, in `proof.ts`;
- it covers `"@authority";req` (the host key sync asked for) and `content-digest`, and the Content-Digest matches the body (every Active algorithm present, RFC 9530);
- `created` is at most 2 s after the moment the response arrived (B.1 MUST reject a `created` in the future; the 2 s for clock accuracy is a declared deviation, [CONFORMANCE.md](CONFORMANCE.md#declared-deviations)), and `expires` has not passed (5.5.3).

Each key in the store gets `valid` (until that signature's `expires`), `invalid` (a signature named the key and failed), or `none` (no signature named it). `tx.wba_agent_proof` reports it for the key that verified a request, and turns `valid` into `expired` once the proof's `expires` passes. A directory with a valid proof is fetched again no later than that expiry, and never conditionally, since a `304` carries no new proof. Appendix B is defined for the directory type only, so `jwks_uri` and `cimd` keys are `none`.

The proof is a fact, not a gate: draft B.1 lets a verifier use keys it resolved itself with or without one, and this verifier does. A rule can demand it (`SecRule TX:wba_agent_proof "!@streq valid" ...` in phase 2), but some live directories publish proofs that fail (no `;req` on `"@authority"`, no `content-digest`, or a `keyid` that is not a thumbprint), and such a rule refuses those bots.

## Sessions and replay

Web Bot Auth has no sessions: every request carries its own signature and is checked alone. The draft lets an origin issue its own session credential after one verified request (5.6), and warns that "a reused signature already has token semantics until `expires`." This plugin issues none. A session bounded by the signature saves almost nothing (one verification costs 0.04 to 1.1 ms, [Algorithms](#algorithms)); one that outlives it is a long-lived bearer credential, the thing Web Bot Auth replaces.

Without a count, a signature can be replayed until it expires or is `tx.wba_max_age` old, to any path it does not cover (draft 5.2), so require `@method @path` where it matters (`tx.wba_require_components`).

**Replay accounting** (draft 5.3; RFC 9421 7.2.2) is off by default; the README's [Replay accounting](README.md#replay-accounting) has the setup, sizing and limits. With `tx.wba_replay_dir` set, each verified signature's signed statement is counted, and its nonce if it has one; recipes D and E turn a count over 1 into a 429 that asks for a new signature. The design reasons:

- **The statement, not the bytes.** The counter is keyed on a hash of the RFC 9421 signature base, which holds every covered value, `keyid`, `created` and `expires`. ECDSA's (r, n - s) verifies as well as (r, s), and a signer can make any number of ECDSA signatures over one base, so counting bytes would let each such copy through once. Every verified signature on a request is counted, so the second of a captured pair is not a free use.
- **Exact under concurrency.** [`replay.lua`](replay.lua) appends one byte to `s.<expires>.<hash>`, or to `n.<hash>` for a nonce, and reads back its own offset; `O_APPEND` makes that one step, so every use gets a different count. ModSecurity's persistent collections cannot do this in the CRS image: they keep no count, or lose increments under load ([TESTING.md](TESTING.md#replay-accounting-why-not-modsecuritys-collections)).
- **The file name carries the policy.** `<last>` is the sooner of `expires` plus `tx.wba_expiry_grace` and `created` plus `tx.wba_max_age`, so `sweep.ts` can remove a file by its name and the directory holds at most `tx.wba_max_age` of verified traffic. The cost: those two settings must be the same wherever one signature can arrive, or the same statement gets two files ([What ModSecurity cannot see](#what-modsecurity-cannot-see)).
- **Fails closed, on its own filesystem.** A directory that cannot be written, or is full, makes every request that would have verified `unverified/replay-unavailable`. An inode budget on a filesystem of its own means a flood of fresh signatures fills nothing else.

## Asking for a signature, in detail

The README's [Asking for a signature](README.md#asking-for-a-signature) shows the `403` or `429` with `Accept-Signature` (draft 5.3, RFC 9421 5.1) and the nginx file that writes it. The nonce in it is nginx's `$request_id`, 128 random bits, sent with `Cache-Control: no-store` so a shared cache never hands one client's nonce to another.

**The verifier does not check that a nonce is one it issued.** The rules can neither read nor set a response header, so the nonce is made in nginx and the rules never see it; storing each one would let any unsigned client fill the store. With replay accounting on, recipe E refuses a nonce seen before. A connector that carries a value from the rules to the response (Envoy's ext_proc can) could issue a keyed-hash nonce and check it with no state.

## Asking bots for body digests

RFC 9530 4 lets an origin ask for digests on future requests with `Want-Content-Digest` and `Want-Repr-Digest` response fields (the unencoded-digest draft adds `Want-Unencoded-Digest`): a Dictionary of algorithm and weight, 1 the least preferred, 10 the most, 0 "not acceptable". ModSecurity rules cannot add a response header, so this is nginx's job:

```nginx
# In each server or location block that answers bots. nginx inherits
# add_header only into blocks that set none of their own, and "always"
# sends it on 4xx responses too.
add_header Want-Content-Digest "sha-512=10, sha-256=3" always;
```

Why those weights here: SHA-512 runs in C with no size limit, SHA-256 in Lua capped at 128 KiB ([Body digests](#body-digests)). Ask for `Want-Unencoded-Digest` only if your application decodes `Content-Encoding` itself and you require `content-digest` coverage too, for the reason given there.

Preferences are a hint, never a protocol error when ignored (RFC 9530 4), and the verifier does not read them: it checks the strongest Active algorithm a signature covers, whatever was asked for. **Not live-tested.**

## Bot lists, in detail

[`wba-keysync/lists.ts`](../../wba-keysync/lists.ts) writes plain SecRules, no Lua; the README's [Bot lists and policies](README.md#bot-lists-and-policies) has the setup. Here "bot operator" is the company that runs the bot and "you" the site operator. Why it is built this way:

- **Compiled data, not lookups.** ModSecurity builds an Aho-Corasick automaton for `@pmFromFile` and a radix tree for `@ipMatchFromFile` when it loads the rules, so a request does two in-memory matches and never waits on a fetch or a DNS lookup. Fetching happens in your cron, which can fail without touching traffic.
- **The claim first.** One `@pmFromFile` over every bot's tokens says which bot the User-Agent claims, and only that bot's list is checked. `validate.ts` refuses a token inside another bot's token: libmodsecurity reports the earliest-ending match and Coraza the longest, so the two engines would name different bots.
- **A missing list is never an impostor.** A bot whose list was never fetched gets `no-list`, and `allow` refuses only `not-in-list`. A list that fails later keeps its last good version, whole.
- **Lists are refused, not trimmed.** A list that is empty, too wide or touches private space is broken or tampered with; dropping lines would hide that, so the whole list is refused.
- **A `before` file.** CRS loads plugin files of one kind in name order, so `web-bot-auth-bots-before.conf` runs right after the verifier's `web-bot-auth-before.conf`, whose results are final by then, and before every `*-after.conf`, where your rules see `tx.bot_*` set. Its rules read only the User-Agent, the client address, `tx.wba_status`, `tx.wba_agent` and their own `tx.bot_*`, and set nothing of CRS's, so running ahead of CRS's rules changes nothing CRS decides.
- **`deny`, not `block`.** A policy is your own decision, so it refuses directly instead of adding to CRS's anomaly score. `allow` never uses ModSecurity's `allow` action, which would skip the attack rules.
- **Separate from the off switch.** The bot-list rules carry the tag `web-bot-auth-bots`, not `web-bot-auth`, and do not read `tx.web-bot-auth-plugin_enabled`. So turning the plugin off (rule 9534112) stops the verifier only; the bot lists keep running.
- **Traceable decisions.** Each list's version goes into `tx.bot_list_version` and every policy log line, and each bot keeps its four rule ids (`ids.json`), so a log line points at the list and the bot that made it.
- **Reverse DNS is not built.** Some bot operators publish host names rather than IP ranges; nothing here checks those.

## Design notes

- **No request-derived string reaches `m.getvar()`.** In libmodsecurity v3 an unknown variable name throws a C++ exception nothing catches, and the nginx worker aborts. Headers are read with one fixed `m.getvars("REQUEST_HEADERS")` call.
- **`@path` and `@query` come from `REQUEST_URI_RAW`.** `REQUEST_URI` is percent-decoded, and RFC 9421 signs the raw form. A target that does not start with `/` gives neither, never an empty one ([What ModSecurity cannot see](#what-modsecurity-cannot-see)).
- **A fresh Lua state per request.** libmodsecurity builds one for every run, so the modules and the key store are loaded per request. The key store is a small data file, never code.
- **Exact parsing.** Structured fields follow RFC 9651's algorithms step for step, so this parser and a compliant signer's agree on every input, including duplicate keys (the last value wins) and decimals. Values written to `tx.*` are constants or validated identifiers, so nothing attacker-shaped reaches your logs.
- **Two runs for a body-bound signature, one decision.** Phase 1 records its time in `tx.wba_time`; phase 2 (`tx.wba_stage=body`, set by the rules, never by the request) re-verifies everything at that time, so a slow upload cannot expire a signature that was fresh when it arrived. Both names are fixed strings in the `TX` collection, which libmodsecurity resolves without throwing.
- **Content codings are decoded in Lua, not by a library.** [`coding.lua`](coding.lua) implements RFC 1950, 1951 and 1952: the Debian and Alpine CRS images ship different zlib bindings, and lua-openssl exposes no compression. In Lua the decoder runs the same on every image, is covered by the planted-bug suite, and checks its budget at every symbol and block, where a binding inflates a whole chunk per call. Where the RFCs leave room, it follows zlib's acceptance rules, so an origin's zlib decodes what it accepts the same way; where zlib-based tools are laxer than the RFC text (bytes after a gzip member or a zlib stream), it follows the text and refuses.

## Crypto dependency

Signature verification and SHA-512 come from [lua-openssl](https://github.com/zhaozg/lua-openssl) 0.11.1 (MIT), pinned to commit `bd640c2` in the Dockerfile's build stage and linked against the image's own OpenSSL 3 (3.5.7 in the pinned image), so OpenSSL fixes arrive with the base image. All of it sits behind [`crypto.lua`](crypto.lua), two functions (`verify`, `sha512`) that the host tests replace with the openssl CLI:

- Keys are rebuilt per call as DER SubjectPublicKeyInfo from the store's raw fields; OpenSSL parses them and checks that an EC point is on its curve.
- ECDSA's r ‖ s becomes DER only from exactly 64 or 96 bytes. RSA-PSS parameters (SHA-512, MGF1 with SHA-512, salt length 64) are set on the `EVP_PKEY_CTX`, never auto-detected.
- A failed check's reason is cleared from the OpenSSL error queue, which the nginx worker thread shares.
- If the module named `openssl` is not lua-openssl (luaossl installs one by that name too), the chunk stops: `unverified/engine-error`.

SHA-256 is [`sha256.lua`](sha256.lua), pure Lua 5.3, hence its 128 KiB body cap.

Why this library and not another: [TESTING.md](TESTING.md#why-lua-openssl). In short, the CRS images link plain Lua 5.3, not LuaJIT, so FFI-based libraries are out; `luaossl` cannot verify Ed25519; and the Ed25519-only alternatives have no ECDSA or RSA. The cost is the module load on every signed request ([Algorithms](#algorithms)).

## Not implemented

- Unencoded-Digest over `br`, `zstd`, `compress`, `aes128gcm` or an unknown coding (`unverified/digest-coding-unsupported`): no `br` or `zstd` binding ships in the image and plain Lua 5.3 has no FFI; `compress` is obsolete for HTTP; `aes128gcm` (RFC 8188) needs a key the WAF does not have. `Repr-Digest` over these bodies is checked: it covers the coded bytes.
- Repr-Digest and Unencoded-Digest over a partial PUT (`unverified/digest-partial`): the rest of the representation is not in the request.
- Digests sent in trailers: trailers never reach ModSecurity.
- `@request-target` in absolute-form (RFC 9421 2.2.5): ModSecurity gets only what follows the host, so it is built in origin-form (`/x` for `GET http://example.com/x`), which a signature over the full URL does not match ([What ModSecurity cannot see](#what-modsecurity-cannot-see)).
- Checking that a nonce is one this origin issued ([Asking for a signature](#asking-for-a-signature-in-detail)): nonces are counted, never matched to an issuer.
- Replay counts shared between hosts: each host counts alone ([README](README.md#replay-accounting)).
- `hmac-sha256` (draft 6.4: MUST NOT), and JOSE algorithms (RFC 9421 3.3.7): a JOSE `alg` with no HTTP twin (`PS256`, `RS512`, `ES512`, `Ed448` and others) makes the key unusable ([wba-keysync in detail](#wba-keysync-in-detail)).
- Keys with no RFC 9421 algorithm: X25519, Ed448, P-521.
- Attribution from redistributed key material (draft 5.5.3): none is consumed; possession proofs are recorded, never used to attribute.
- Reverse DNS checks for bot lists ([Bot lists, in detail](#bot-lists-in-detail)).

**Not live-tested:** ModSecurity v2 (Apache) and HTTP/3.
