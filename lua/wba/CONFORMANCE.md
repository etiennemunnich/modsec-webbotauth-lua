# Standards conformance

The rule: implement each standard as written, and deviate only for a compelling security reason, stated with its clause and pinned by a test.

## Summary by standard

This file traces all 248 BCP 14 sentences of the documents below (the four core ones and the unencoded-digest draft), what the audit fixed, and the choices made. First, each standard and how it is checked:

| Standard | How it is checked |
|---|---|
| RFC 9651 Structured Fields | All 2137 records of the HTTP Working Group's corpus pass, none skipped. One `can_fail` record is declined: extra base64 padding, which RFC 4648 forbids. Key-sync's parser (`sf.ts`) passes the corpus's 1593 parse records, declining the same one. |
| RFC 9421 HTTP Message Signatures | Every example in sections 2.1 and 2.2 reproduces byte for byte, except 2.2.5's `@request-target` for the absolute, authority and asterisk forms: it is built from the path and query only (the known limit under [Declared deviations](#declared-deviations)). 2.2.8's `@query-param` example reproduces in its own `%20` spelling, which verifies beside the steps' `+` (choice 9), and B.2.1 to B.2.4 and B.2.6 verify. `@query-param` agrees with WHATWG `URLSearchParams` (Bun and Node) on 2720 generated queries. 7.2.8's body check is done (RFC 9530 row). 3.3: every algorithm but `hmac-sha256` (draft 6.4), chosen per 3.2 step 6, against Wycheproof ([Algorithms](DESIGN.md#algorithms)); possession proofs follow the same rules. |
| RFC 9530 Digest Fields, and draft-ietf-httpbis-unencoded-digest-05 | Content-Digest, Repr-Digest and Unencoded-Digest checked against the body in phase 2, with the RFCs' example digests in the unit suite and the live suite; Active algorithms only; covered members only. Unencoded-Digest decodes gzip and deflate first (draft 5), checked against the draft's own Figure 2 and 2895 zlib-decided inputs. Repr-Digest and Unencoded-Digest are checked on a partial PUT only when its range is the whole representation; `Content-Range` on any other method is ignored (RFC 9110 14.4). |
| Web Bot Auth draft-00 | Appendix E.1 and E.2 vectors verify, and E.2.3's signed directory response validates as an Appendix B proof. All 17 [negative vectors](https://github.com/ParallaxGrain/webbotauth-negative-vectors) are checked for outcome and reason. 16 match as written. NV-10 is dispositioned: it expects RFC 9651 4.2's "malformed" branch, which `tx.wba_malformed=reject` gives (checked), while the default `ignore` takes the RFC's other branch, `not-signed/unparsable-field`. |
| RFC 3986 / RFC 5952 / RFC 6454 (identifiers, draft 5.5) | 100 vectors (`fixtures/identifiers.tsv`): normalization, query and fragment dropped, IPv6 canonical text, origin serialization; run by the Lua verifier and by key-sync, which must agree. |
| OAuth Client ID Metadata Document (draft-02) | For `cimd` agents: `client_id` is the URL fetched (4), `jwks` or `jwks_uri` (RFC 7591 2), no shared secrets (4.1), Client Identifier URL rules (3). The sections below say what is not taken and why. |
| RFC 8037 / RFC 7638 / RFC 8032 | `wba-keysync` reproduces the RFC 8037 A.3 and RFC 7638 3.1 thumbprints; the 13 published test keys (RFC 9421 B.1.1 to B.1.4, RFC 8032 7.1's five, four JOSE examples) are refused by both the verifier and key-sync. |
| RFC 8017 / RFC 7518 | RSA keys: `n` odd and `e` odd and at least 3 (8017 3.1), and above 3072 bits `e` at most 64 bits (OpenSSL verifies none wider), integers minimal (7518 2), EC coordinates full size (7518 6.2.1.2); RSA-PSS and PKCS #1 v1.5 against Wycheproof. |
| RFC 1950 / RFC 1951 / RFC 1952 (content codings) | `coding.lua` decodes zlib, deflate and gzip as the RFCs write them, agreeing with zlib on 2895 inputs; where zlib-based tools accept more than the text (trailing bytes after a member or stream), it refuses. |

**Deviations, each with its reason:**

- **WBA 6.1** (WBA-051: an origin SHOULD refuse Signature headers sent over an unsecured channel): not met. ModSecurity cannot see whether the client used TLS, so a signed request over plain HTTP is verified like any other; [below](#declared-deviations).
- **WBA B.1** (WBA-083: a verifier MUST reject a directory proof whose `created` is in the future): 2 s allowed for clock accuracy; [below](#declared-deviations).

**Choices the standards leave open** (RFC 9421 3.2.1 expects application requirements):

- A signature counts for at most an hour after its `created` (`tx.wba_max_age`; RFC 9421 3.2.1 lets a verifier set a maximum age), which bounds replay (draft 6.9). So the window (`expires` minus `created`) has no cap by default: draft 5.2's 24 hours is RECOMMENDED for signers. With the maximum age off, the cap is a day; `tx.wba_max_window` sets an operator's own. Published test keys are refused (draft 6.8, SHOULD).
- A signature whose `expires` is not after its `created` is `invalid/bad-param`. RFC 9421 2.3 defines both only as integers; such a signature is expired at the moment it was made.
- How often a signature or nonce may be used (draft 5.3: "more often than its policy permits"): no limit unless you set one; recipes D and E show once, counted per host.
- Body digests (RFC 9530 2: a recipient MAY ignore digests and MAY set local constraints; 6.7 allows limits): the strongest covered Active algorithm is the one checked; SHA-256 bodies over 128 KiB are not hashed; decoding for Unencoded-Digest stops at 128 KiB of work or 200 units per byte received; br, zstd and compress are not decoded (unverified).
- RSA keys of 2048 to 16384 bits with a public exponent below 2^256, and at most 64 bits above 3072 bits, where OpenSSL verifies nothing with a wider one (`OPENSSL_RSA_SMALL_MODULUS_BITS`, `OPENSSL_RSA_MAX_PUBEXP_BITS`), so key sync and the store refuse such a key (RFC 9421 3.2.1 names key size as an application requirement; the floor is RFC 7518 3.3 and 3.5's MUST for the same algorithms in JOSE). A URL-less signature verifies only if every directory listing its key allows the same algorithm (draft 4.3 does not say how to choose among them; this keeps a pin from being bypassed, RFC 9421 7.3.6).
- Identifiers (draft 5.5 names RFC 3986 6.2.2 and 6.2.3): IPv6 literals are also put in RFC 5952 text, so spellings of one address compare equal; a port with a leading zero, and hosts that are not DNS names or IP addresses, are refused.

## How this was checked

Every sentence carrying a BCP 14 keyword (MUST, SHOULD, MAY and the rest) was extracted mechanically from each document: 248 in all.

| Document | Sentences |
|---|---|
| RFC 9421 HTTP Message Signatures | 113 |
| draft-ietf-webbotauth-httpsig-protocol (Web Bot Auth) | 83 |
| RFC 9651 Structured Fields | 29 |
| RFC 9530 Digest Fields | 15 |
| draft-ietf-httpbis-unencoded-digest-05 | 8 |

Each sentence was traced to the code, a test, or a stated reason, by auditors working from a copy of the tree at commit `0684bb6` of the development history, who ran the suites and wrote their own probes. That commit is not in this repository, so the file and line numbers in the matrix's first notes point into it. The unencoded-digest draft's 8 sentences were traced when its decoding was written. Every finding acted on below was re-checked against the primary text and pinned by a test before it changed anything.

The full matrix, one row per sentence with who it binds, its status and the evidence, is [`conformance/requirements.tsv`](conformance/requirements.tsv):

- 122 comply.
- 20 were fixed, in the 2026-10-01 audit pass or when the open choices were settled.
- 2 are declared deviations: WBA-051 (draft 6.1, refuse signatures sent over plain HTTP: not met) and WBA-083 (draft B.1, a 2 s clock tolerance), [below](#declared-deviations).
- 104 do not apply here. 99 bind someone else, or no one: the signer, the directory operator, the origin's policy or an intermediary, IANA, the authors of other field specifications, responses, or informative text. 5 bind this verifier in a case that cannot arise: digests sent as trailers (R9530-006, R9530-011, UD05-006) and header and trailer values combined (R9421-030), because no trailer reaches ModSecurity, and JWS algorithms (R9421-079), because none is used.

One MAY is declined: WBA-037, fetching an unknown key while a request waits. Key-sync fetches the directories you list ahead of time instead. No row is unclassified and none is open. Everything that applies to this verifier and key-sync, and is not plainly met, is listed here with its status.

## Fixed in the audit pass

| Clause | Found by the audit | Behaviour |
|---|---|---|
| RFC 9421 2 | Repeated components compared by serialization, so `"d";key="a";sf` beside `"d";sf;key="a"` verified | Identity ignores parameter order (`sigbase.identity`) |
| RFC 9421 2.1.2 | `"d";key="a"` beside `"d";key="a";sf` verified | A Dictionary key is covered once; `;sf` beside `;key` adds nothing. Only `;sf` is redundant there: any other parameter beside `;key` still makes a different component (RFC 9421 2) |
| RFC 9421 2.5 (ABNF) | HTAB accepted in derived components | Refused (`bad-component-value`); still allowed in field values |
| RFC 9421 2.2.3, RFC 3986 6.2.3 | `Host: example.com:` kept its empty port | Removed |
| RFC 9421 3.2 step 6.5 | Key-sync stored keys whose JWK `alg` named another algorithm | Skipped with a warning |
| RFC 9421 7.2.8, RFC 9530 | A signature over a digest was never verified (`content-digest-unchecked`) | Checked against the body in phase 2 (DESIGN.md, Body digests) |
| RFC 9421 2.1 | Header-line order through libmodsecurity assumed | Proven live: both orders signed, only the arrival order verifies |
| WBA 5.5.1 | Key-sync stored keys published with their private part (`d`) | Rejected |
| WBA 6.8 | Only RFC 9421's test key refused | Also RFC 8032 7.1's five, RFC 9421 B.1.1 to B.1.3 and four JOSE examples (TEST 1 is RFC 8037's example key; the fixtures use a key generated for them) |

## Every RFC 9421 3.3 algorithm the draft allows

All five asymmetric algorithms of RFC 9421 3.3 are supported; `hmac-sha256` is refused, as WBA 6.4 requires ("Implementations MUST NOT use shared HMAC"). The matrix rows this touches (R9421-068, 070, 071, 076, 078, 079; WBA-007, 046, 053, 066) carry a note on it. Nothing here is a deviation: each rule is the text's, or an application requirement RFC 9421 3.2.1 allows.

| Clause | Behaviour | Pinned by |
|---|---|---|
| RFC 9421 3.2 step 6.1, WBA 6.4 | allowed set: `rsa-pss-sha512`, `rsa-v1_5-sha256`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `ed25519`; any other `alg` is `invalid/unsupported-alg` | test_verify 5; planted bug |
| RFC 9421 3.2 steps 6.3 to 6.5, step 8 | the algorithm from the JWK's `alg` (stored) or the one its key type allows, and from the `alg` parameter; disagreement or an `alg` for another key type is `invalid/alg-mismatch`; none determined (an RSA key without either) is `invalid/alg-undetermined` | test_verify 15a to 15c, 15h; test_entry 12; three planted bugs |
| RFC 9421 7.3.6 | a key pinned to `rsa-pss-sha512` never verifies `rsa-v1_5-sha256`; URL-less, every directory listing the key must allow the same algorithm | test_verify 15b, 15h; two planted bugs |
| RFC 9421 3.3.1 | RSASSA-PSS, SHA-512, MGF1 with SHA-512, salt length exactly 64 (never auto-detected) | test_crypto 3; Wycheproof (149 vectors made with other parameters must fail); four planted bugs |
| RFC 9421 3.3.2 | RSASSA-PKCS1-v1_5 with SHA-256 | test_crypto 1; Wycheproof 776 |
| RFC 9421 3.3.4, 3.3.5 | ECDSA signatures are r ‖ s, 64 or 96 bytes; any other length, DER included, is `invalid/bad-signature` before the crypto; re-encoded to DER only inside `crypto.lua` | test_verify 15d, 15e; test_crypto 4; Wycheproof P1363 542; three planted bugs |
| RFC 9421 3.3.6 | pure Ed25519 over the base | Wycheproof 151 (against OpenSSL) |
| RFC 8017 8.1.2, 8.2.2 step 1 | an RSA signature must be k bytes, the modulus length | test_verify 15d; planted bug |
| WBA 5.2, RFC 7638 3.2, RFC 8037 A.3 | keyids are RFC 7638 thumbprints for RSA and EC, RFC 8037 A.3 for Ed25519 | keysync.test.ts (RFC 7638 3.1, draft E.1 and E.2 keyids, openssl-computed fixtures) |
| WBA 5.5.1, RFC 7517 4.4 | a JWK `alg` names an algorithm for the key's own type: the HTTP Signature Algorithms name or its exact JOSE twin (`EdDSA`, `Ed25519`, `ES256`, `ES384`, `PS512`, `RS256`), stored as the HTTP name; other JOSE names make the key unusable (choice 7b) | keysync.test.ts; test_keys; 5 planted bugs |
| RFC 7518 2, 6.2.1.2; RFC 8017 3.1 | RSA `n` and `e` minimal; `n` odd; `e` odd and at least 3; EC coordinates full size; the EC point on its curve | keysync.test.ts; test_keys; test_crypto 5; planted bug (even e) |
| RFC 9421 3.2.1 (application requirement) | RSA modulus 2048 to 16384 bits (floor: RFC 7518 3.3 and 3.5's MUST for RS256 and PS512; ceiling: OpenSSL's); `e` below 2^256 (FIPS 186-5's bound; verification cost grows with `e`) | keysync.test.ts; test_keys (2047 and 1024-bit openssl keys); test_verify 15g; planted bug |
| WBA 6.8 | test keys: RFC 9421 B.1.1 to B.1.4, RFC 8032 7.1's five, RFC 7517 A.2's two and RFC 7515 A.2 and A.3 | keysync.test.ts; test_verify 15i |
| WBA B.1 with RFC 9421 3.2 step 6 | a directory's possession proof is verified with the same algorithm rules as a request (`algorithms.ts`, shared by `keysync.ts` and `proof.ts`), for every algorithm, through WebCrypto (ECDSA's WebCrypto format is r ‖ s; RSA-PSS with SHA-512, MGF1 with SHA-512, salt 64) | proof.test.ts (every algorithm; 14 refusals, each matched to its reason); keysync.test.ts (an ECDSA P-256 directory end to end); 7 planted bugs |

Ground truth: RFC 9421 B.2.1 to B.2.4 and the draft's E.1.1 and E.1.2 verify over the bases built here (test_sigbase, test_crypto, test_verify 15i); RFC 7638 3.1's thumbprint (keysync.test.ts); 1798 Wycheproof vectors against the lua-openssl build the image ships. The live suite runs with these algorithms (TESTING.md).

## Declared deviations

- **WBA 6.1** (WBA-051: an origin SHOULD refuse Signature headers when communicated over an unsecured channel): not met. ModSecurity cannot see whether the client used TLS, and behind a load balancer that ends TLS, nginx cannot either. So a signed request over plain HTTP is verified like any other. The README tells operators to serve signed traffic over HTTPS and to redirect plain HTTP: a signature does not cover every header, so over plain HTTP anyone on the path could change the parts it does not cover. Pinned by the live case `cleartext-signed` (`verified`).
- **WBA B.1** (WBA-083: a verifier MUST reject a directory response signature whose `created` is in the future): "in the future" allows 2 s for clock accuracy (`PROOF_CLOCK_SKEW`). Signers stamp `created` with their current second, so a key-sync clock a fraction of a second behind theirs read OpenAI's fresh proofs as future-dated on 12 of 25 fetches in one test. The draft's reason for the rule, that a future-dated proof would outrank later fetches (4.4), is bounded to 2 s. Pinned by proof.test.ts, keysync.test.ts and 3 planted bugs.

**A known limit, not a deviation from a traced sentence.** Request lines that carry a full URL (absolute-form, `GET http://example.com/x HTTP/1.1`) are accepted, as RFC 9112 3.2.2 requires (live: `absform-matching`, `verified`). RFC 9112 3.3 makes that URL the target URI, and RFC 9421 2.2.3 takes `@authority` from it, but ModSecurity sees only the `Host` header and the path and query nginx passes on:

- `@authority` and `@target-uri` come from the `Host` header, so `GET http://other.example/` sent with `Host: example.com` verifies a signature made for example.com while nginx serves the request as other.example (live: `absform-host-attack` and its three other spellings, `verified`). It matters only where a request-line host other than the `Host` header can reach an application. Replay accounting counts such a copy with the bot's own request, but only a recipe refuses it, and only the second copy to arrive: widen recipe D, which as shipped covers `/agents` only, to every path where `verified` matters, or require a nonce and use recipe E ([README, Known limits](README.md#known-limits); [DESIGN.md, What ModSecurity cannot see](DESIGN.md#what-modsecurity-cannot-see)).
- `@request-target` is built from the path and query, so a signature that covers the full URL as `@request-target` does not verify (live: `absform-request-target`, `invalid/bad-signature`).

## Not implemented (MAY, or optional appendices)

- Request trailers (RFC 9421 2.1's `;tr`, digests sent as trailers): libmodsecurity 3.0.17 takes a request only through `addRequestHeader` and `appendRequestBody` (headers/modsecurity/transaction.h:380-386; its one "trailer" is the audit-log format, :422), and ModSecurity-nginx v1.0.4's request path never mentions trailers, so none reaches the rules. `;tr` is `invalid/unsupported-component` (RFC 9421 2.5).
- Response signatures (`@status`, `;req`, a signed response): Web Bot Auth signs requests (draft 5.1); the plugin verifies requests, so the response-side rows bind someone else (n/a).
- Checking that a nonce is one this origin issued (no BCP 14 sentence asks for it; README, Asking for a signature): ModSecurity-nginx gives the rules no way to read or set a response header, and storing every issued nonce would let unsigned clients fill the store.
- WBA 5.5.3 attribution from redistributed key material: none is consumed. Appendix B proofs are recorded, never used to attribute.

## Failing a field line by line

R9651-026, RFC 9651 4.2: "Parsers MAY fail when processing a field value spread across multiple field lines, when one of those lines does not parse as that field." Taken as an option, `tx.wba_strict_field_lines` (off by default, since 4.2's algorithm combines the lines and the RFC makes this a MAY). On, Signature-Input, Signature, Signature-Agent and every covered digest field must parse line by line as well as combined. A Signature-Input, Signature or Signature-Agent line that does not parse is handled as `tx.wba_malformed` says (choice 11): by default the request is `not-signed/unparsable-field`, and with `reject` it is `invalid/malformed-headers` and 400 (rule 9534107). A covered digest field's line that does not parse is always `invalid/malformed-digest` and 400 (rule 9534107). Uncovered digest fields are never read. The case it changes is a String split across lines, which combined is valid (`a="x` and `y"` make `a="x, y"`): test_verify 16 checks each field, with a clean split still verifying, and three planted bugs pin it.

## Requesting signatures and limiting reuse

Draft 5.3's three MAYs are taken. What each clause does here:

| Row | Clause | Behaviour |
|---|---|---|
| WBA-029 | an Origin MAY request signatures from clients that did not provide them | recipes.conf A denies with 460, and nginx/web-bot-auth-accept-signature.conf answers 403 with `Accept-Signature` |
| WBA-032 | the status code SHOULD be 403 | 403 |
| WBA-031 | the Origin MAY request additional parameters, including nonce | the request carries `created`, `expires` and `nonce="$request_id"` (128 random bits per response); `tx.wba_require_nonce=1` makes a signature without a nonce `unverified/missing-nonce` |
| WBA-033 | an Origin that detects a signature or nonce used more often than its policy permits MAY request a new signature and respond 429 | replay accounting (replay.lua, `tx.wba_replay_dir`) counts, per host, every verified signature's signed statement and nonce; recipes D and E deny with 461, answered as 429 with a new `Accept-Signature` |
| R9421-097 | the sender of Accept-Signature MUST include only identifiers appropriate for the target message | `@authority`, `@method`, `@path` and `"signature-agent";key="sig1"`: request components |

Choices made, each with its reason:

- **Counting in Lua, not in libmodsecurity's persistent collections.** Probed live in the CRS nginx image: the collections' LMDB database cannot be created in nginx's working directory, so they hold nothing; with a writable one, 201 increments left a `setvar:+1` counter at 70 in one run and 62 in another, because it reads and writes in separate transactions (lua/tests/live/collections-probe.sh). replay.lua's `O_APPEND` counter gave 200 concurrent requests 200 different counts. A count that loses concurrent uses is no limit against an attacker who sends them at once.
- **The signed statement is the key, not the signature bytes.** Counting signature bytes would let a captured ECDSA request through once more as (r, n - s), which verifies too, and counting only the reported signature would let each extra signature in a request through once. So the counter keys on a hash of the RFC 9421 signature base, and every verified signature is counted; a unit test, a planted bug and a live case pin each.
- **Bounded files.** One file per statement, named by its signature's own expiry and kept until then or until it has gone unused for `tx.wba_max_age` (an hour by default), whichever comes first; one per nonce until unused for as long; `wba-keysync/sweep.ts` removes the rest. Only key holders in the store add files, so the bound is their request rate times `tx.wba_max_age`; the README gives the sizing.
- **Per host.** Each host counts alone. A count shared between hosts needs a store this plugin does not have; the README says so where the setting is described.
- **Fail closed.** A configured directory that cannot be written makes every request that would have verified `unverified/replay-unavailable`, as an unreadable key store does.
- **Nonces counted, not matched to an issuer.** Draft 5.3 lets the origin request a nonce; no sentence requires checking that a returned nonce is one it issued (RFC 9421 7.2.2 leaves replay tracking to the verifier). Checking it would need either a channel from nginx to the rules, which ModSecurity-nginx lacks, or a store of every nonce issued to unsigned clients, which they could fill.
- **Status channel.** ModSecurity v3 cannot add a response header, so the rules signal with two unassigned statuses, 460 and 461, that nginx turns into 403 and 429 (nginx's error log still records 460 or 461; the audit log records the 403 or 429 sent, with the rule). Without the nginx file a client sees 460 or 461, still a refusal. The connector does not re-run ModSecurity for the error page: a 429 answer runs the Lua twice (verify, log) and writes one log line, live.

Tests: test_replay (counts, names with the expiry, refused names, unwritable directories, 40 concurrent processes), test_entry 14 (counted once at the final decision, verified only, URL-less too, both signatures of a two-signature request, ECDSA (r, n - s) and a re-sign as one statement, a required nonce, fail closed, malformed settings), test_log (`uses`, `nonce_uses`), sweep.test.ts (what the sweeper removes and never touches), 15 planted bugs; live: Accept-Signature on recipe A's 403 and its answer verifying, a second use getting 429 with Accept-Signature, 20 concurrent uses with exactly one passing, a second ECDSA signature over one base getting 429, the 429 path running the Lua twice, a reused nonce getting 429, and `replay-unavailable`.

## Agent types, identifiers and possession proofs

How each clause on `jwks_uri` and `cimd` members, IPv6 literal hosts and Appendix B proofs is met:

| Clause | Behaviour | Pinned by |
|---|---|---|
| WBA 5.2.1: a type names the mechanism, `directory` when absent; an unsupported type MUST be ignored, never inferred | `directory`, `jwks_uri` and `cimd` resolve; any other type, or a type sent as a String rather than a Token, is ignored (`unverified/unsupported-agent-type`) | test_verify §8; 3 planted bugs |
| WBA 5.5: the identifier is the URL resolved, query and fragment discarded | directory: the well-known URI; `jwks_uri`/`cimd`: the member value (`identifier.lua` / `identifier.ts`, one set of rules) | `fixtures/identifiers.tsv`, 100 vectors run by both languages; test_verify §14l; planted bugs |
| WBA 5.5: identifiers compared after RFC 3986 6.2.2 and 6.2.3 | scheme and host lowercased, percent-encoding hex uppercased and unreserved octets decoded, dot segments removed (linear time), empty path `/`, empty and default port removed | vectors; the 8 KiB cost check in test_verify §14l; 3 planted bugs |
| RFC 5952 4 and 5: IPv6 text | identifiers hold the canonical text (no leading zeros, `::` for the longest run of two or more zero groups, first when tied, lowercase; IPv4-mapped and -translated in dotted decimal) | vectors; test_verify §14m; 4 planted bugs |
| WBA 5.5 with RFC 6454 6.2: a directory member is an origin's ASCII serialization | IPv6 literals accepted; uppercase (DNS or hex) and an explicit `:443` are not a serialization and are ignored | test_verify §8, §14m; planted bug |
| RFC 9110 4.2.4: userinfo is an error | refused in every identifier | vectors; planted bug |
| WBA 5.5: at the well-known URI a `kid` MUST be the thumbprint; `jwks_uri`/`cimd` key sets serve other consumers, so "a verifier ... computes thumbprints instead" | the rule follows the URL, not the type: any key set served at the well-known path must label keys by thumbprint; elsewhere `kid` is ignored and every key is indexed by the thumbprint key-sync computes | keysync.test.ts; 2 planted bugs |
| WBA 5.5: each fetch MUST be 200 and MUST NOT follow redirects | every fetch, a CIMD's `jwks_uri` hop included | keysync.test.ts; planted bug |
| WBA 6.7: no fetches to private, loopback or link-local ranges | `guardAddress` before every fetch, the CIMD hop included; an IP literal (IPv6, and WHATWG forms such as `0x7f.1`) is checked as the URL parser reads it and never sent to DNS | keysync.test.ts; 2 planted bugs |
| WBA 5.5.1: all three types resolve to a JWKS, alg restricted to the registry; SHOULD reject malformed entries | the same key checks for every type. Away from the well-known URI the draft sets no media type, so any `Content-Type` is read, and the body must still parse as JSON and pass the key checks | keysync.test.ts; planted bug |
| CIMD 4: `client_id` MUST match the URL fetched | refused otherwise (a failed fetch: last-good keys kept, 6.10) | keysync.test.ts; planted bug |
| RFC 7591 2: `jwks` and `jwks_uri` MUST NOT both be present | refused | keysync.test.ts; planted bug |
| CIMD 4.1: no shared-secret client authentication | `client_secret`, `client_secret_expires_at` or a `client_secret_*` method refused | keysync.test.ts; planted bug |
| CIMD 3: a Client Identifier URL has a path, no dot segments, no fragment (SHOULD NOT have a query) | an agents.txt `cimd` line that breaks a MUST is refused; a query is a warning | keysync.test.ts |
| WBA B.1: MUST validate a proof with the key the directory provides and the Content-Digest against the body | `proof.ts`, per signature tagged `http-message-signatures-directory`: `keyid` names a key kept from that response, `"@authority";req` and `content-digest` covered (other covered response fields resolved; anything else cannot be), the algorithm chosen as for a request (RFC 9421 3.2 step 6; `algorithms.ts`): any of the five, an `alg` allowed and agreeing with the key's JWK `alg` or type, the exact signature length; every Active Content-Digest member matches the body (RFC 9530); WebCrypto verifies over the rebuilt base. Identity coding is requested; a content-coded response's digest cannot be checked, so its proof is invalid | the draft's E.2.3 vector, a failure matrix over hand-written bases, and every algorithm with its refusals pinned to their reasons (proof.test.ts); 15 planted bugs |
| WBA B.1: MUST reject a signature whose `created` is in the future | judged at the time the response is received; "in the future" read as more than 2 s ahead (`PROOF_CLOCK_SKEW`), a declared deviation ([above](#declared-deviations)) | keysync.test.ts, proof.test.ts; 3 planted bugs |
| WBA 5.5.3: valid only while its `expires` has not passed | recorded with the store entry; the verifier reports `expired` after it; key-sync refetches a directory no later than its earliest valid proof expires, never conditionally (a 304 carries no new proof) | test_verify §14n; keysync.test.ts; 4 planted bugs |
| WBA B.1: MAY use keys without proof | taken: every key is used; the proof is a fact (`tx.wba_agent_proof`, `agent_proof` in the log) | test_entry 12; test_log |

RFC 9651 parsing in key-sync (`sf.ts`) is checked against the same HTTP Working Group corpus as the Lua parser: all 1593 parse records, declining only `can_fail`'s extra base64 padding, as the Lua parser does.

**Interpretations, stated so they can be challenged:**

- **RFC 5952 text in identifiers.** The draft names RFC 3986 6.2.2 and 6.2.3, which lowercase an IPv6 literal but leave its zeros as sent, so `[2001:0db8::1]` and `[2001:db8::1]` would be two identifiers. Identifiers are text this verifier generates (store, logs, `tx.wba_agent`), and RFC 5952 4 says a system generating IPv6 text SHOULD use its canonical form. Effect: spellings of one address compare equal; two addresses never do.
- **Lookup is by (identifier, keyid), whatever the member's type** (5.4: the (URL, key) pair; 4.4: "a verifier that already holds the keys does not need to fetch it"). A `jwks_uri` member naming a listed directory's well-known URI is that same identifier and verifies with its keys.
- **Refused rather than given an identifier:** a port with a leading zero (RFC 3986 keeps `08443`, but `fetch()` connects to 8443, so the identifier would name a port other than the one fetched), and a host that is not a DNS name, IPv4 address or IPv6 literal (IPvFuture, zone identifiers, percent-encoded names). A refused member is ignored: `unverified/bad-agent-url`.
- **`@target-uri` uses the normalised authority** (RFC 9421 2.2.2). It is built from the same authority as `@authority` (2.2.3: lowercase, default port dropped; `components.lua`), the scheme, the path and the query. A signer that signs the URI with an uppercase host or an explicit `:443` does not verify.
- **Per-key proof status.** B.1 has one signature prove possession of one key, and 5.5.3 asks for a proof "for the key in question", so the store records each key's: `valid` (with its expires), `invalid` (a signature named this key and failed, or the signature fields do not parse), `none` (no signature named it). Appendix B applies to the directory type only; `jwks_uri` and `cimd` keys are `none`.

**Not taken from CIMD**, because it binds authorization servers, not a Web Bot Auth verifier: 8.6's refusal of every RFC 6890 special-use range (key-sync refuses WBA 6.7's private, loopback and link-local ranges, plus unspecified, "this network" and RFC 6598 shared space, but not documentation or benchmarking ranges), and 8.7's 5 KB read limit (key-sync applies its 64 KiB 6.7 cap to every response).

## The choices, resolved: follow the text

The audit's first pass left 13 choices open, each with a case for and against. Each was settled by following the specifications as written:

| # | Clause | Found by the audit | Behaviour | Pinned by |
|---|---|---|---|---|
| 1 | WBA 5.2.2: verifiers MUST validate each signature | over 3 signatures `invalid`, none validated; the first verified one ended the loop | every signature validated; `tx.wba_agents` lists every verified directory; no cap by default (150 small signatures in about 35 KiB of headers: 9 to 10 ms before the crypto; [DESIGN.md](DESIGN.md#several-signatures-on-one-request) has the costlier shapes); an optional `max_signatures` gives `unverified` | test_verify 11, 14i, 14j; two planted bugs |
| 2 | C.1 outcomes for capability limits | | unchanged: RFC 9421 2.5 makes an unresolvable component an error, and 3.2 step 6.1 makes an algorithm outside the allowed set a failure (`invalid`) | |
| 3a | WBA 5.5: a directory member MUST be the origin's ASCII serialization | `https://agent.example:443` normalized and verified | ignored: `unverified/bad-agent-url` (an empty path `/` is still accepted, as 5.5 allows) | test_verify 8; planted bug |
| 3b | WBA 5.2.1: scheme MUST be https | | unchanged (`invalid/agent-not-https`) | NV-16 |
| 4 | WBA 5.5.2, C.4, C.5: cache directories, refresh on expiry | operator timer, no cache semantics | RFC 9111 freshness per directory, conditional revalidation, backoff with `Retry-After`; a failure still evicts nothing (6.10) | keysync.test.ts; live: registry.sh (five ways a key server breaks, the held-back retry) |
| 5 | WBA 6.1: SHOULD refuse Signature headers over an unsecured channel | not checked | not met, a declared deviation ([above](#declared-deviations)): ModSecurity cannot see whether the client used TLS, and behind a load balancer that ends TLS nginx cannot either, so a signed request over plain HTTP is verified like any other. The README tells operators to serve signed traffic over HTTPS | live: cleartext-signed (`verified`) |
| 6 | WBA 6.7: SHOULD block private, loopback and link-local fetches | not checked | refused after resolution, before the fetch; DNS rebinding between the two is the residual, and TLS validation is what stops it. An operator can except an exact origin, its own bot on its own network, with `--allow-private-origin` (command line only, never from `agents.txt`; it covers the listed URLs, never a CIMD's `jwks_uri` hop; each such fetch reported) | keysync.test.ts; live: registry.sh |
| 7a | WBA 5.5: a kid MUST be the thumbprint; 5.5.1: reject malformed entries | warned and kept | rejected (the draft's own 5.5.1 example breaks its MUST; the normative text wins) | keysync.test.ts |
| 7b | WBA 5.5.1: alg restricted to the HTTP Signature Algorithms registry | `ed25519`, `Ed25519` and `EdDSA` accepted | a JWK `alg` may be the HTTP Signature Algorithms name or its exact JOSE twin (`EdDSA`, `Ed25519`, `ES256`, `ES384`, `PS512`, `RS256`), and the key is pinned to the HTTP name. The sentence has no BCP 14 keyword, and the JWK Set it describes names a JOSE algorithm in `alg` (RFC 7517 4.4; WG issue #136; the editor's PR #139 reads it the same way). Read strictly, it would drop every key of 7 live signers registered with Cloudflare (PayPal, ConsentCheck and five Cloudflare bots) | keysync.test.ts; 4 planted bugs |
| 8 | RFC 9421 2.2.4: @scheme is the request's scheme | configured `https`, wrong on a cleartext port | unchanged: the configured scheme (`CONFIG.scheme` in `modsecurity_entry.lua`, `https`), because ModSecurity does not tell the rules which scheme the client used. That is the request's scheme for every client that reaches an HTTPS site, through a load balancer that ends TLS too. A signature made over plain HTTP that covers `@scheme` or `@target-uri` does not verify (choice 5) | live: cleartext-scheme (`invalid/bad-signature`) |
| 9 | RFC 9421 2.2.8 step 2: the URL Standard's form encoding | spaces as `%20` only | both spellings. The steps give `+` (the URL Standard's serializer, 5.2, with spaceAsPlus); the RFC's own example prints `%20` (`"@query-param";name="bar": with%20plus%20whitespace`); no erratum covers 2.2.8. Both spell the same decoded parameters, so both verify: a name spelled with `%20` is the same name, and if the `+` base fails while a covered `@query-param` value has a space, the `%20` spelling is tried. That retry runs at most once per request, and only for a key you hold, so a hostile request cannot double the work | test_components; test_verify (both spellings); 2720 vectors equal URLSearchParams unchanged; 4 planted bugs |
| 10 | WBA 4.3: no Signature-Agent: the identifier is the thumbprint | `unverified/agent-absent` | a held key verifies: `verified/url-less`, `tx.wba_keyid` only; a key not held stays `unverified/agent-absent` | test_verify 14g, test_entry 8b, live; planted bug |
| 11 | RFC 9651 4.2: a parse failure means "ignore the field" or "the message is malformed" | `invalid/malformed-headers`, no HTTP effect | both branches, chosen with `tx.wba_malformed`. `ignore` (the default) takes the first: an unparsable Signature-Input or Signature is treated as absent (`not-signed/unparsable-field`), so a draft-cavage `Signature` header (ActivityPub) is not refused; an unparsable Signature-Agent leaves the signature that covers it unable to verify (`invalid/unparsable-agent`, or `invalid/missing-component` for a `;key=` member), with no 400. `reject` takes the second: `invalid/malformed-headers` and 400 (rule 9534107; draft 5.4 allows it). A covered body digest field always takes the second (`invalid/malformed-digest` and 400): only a good signature from a listed key reaches that check, and ignoring the field would leave the body unbound while the signature claims it. A field parsed only for `;sf` or `;key` is ignored (`invalid/missing-component`) | test_verify 4, 16, 17; live: malformed-input, malformed-reject, activitypub-cavage; planted bug |
| 12 | RFC 9421 4: a label in one field and not the other is an error | checked only for the signature being verified | checked for every label: `invalid/orphan-label`. Section 4 says "The presence of a label in one field but not the other is an error", so this holds for any label. A `Signature` sent as a trailer never reaches ModSecurity, so such a message is refused; 4.2 RECOMMENDS sending both as headers only. 7.2.6's denial-of-service point (one bad label fails the whole request) is accepted, because section 4 is normative | test_verify 12, 14i; NV-11; planted bug |
| 13 | RFC 9530 2, 6.7: local digest policy | | unchanged: the strongest covered Active algorithm and a 128 KiB SHA-256 cap; Unencoded-Digest is decoded within a budget ([below](#rfc-9530-and-the-unencoded-digest-draft)) | test_verify 14e |

## Operator decisions

Settings that limit what a verifier that follows the texts would still accept. None departs from a MUST; each uses room the texts leave to the verifier.

| Decision | Text that allows it | Setting, default | Pinned by |
|---|---|---|---|
| A signed request whose Host is not one of the site's names is `invalid/foreign-authority`; with none configured nothing verifies | No clause requires the check, but RFC 9421 3.2.1 lets a verifier impose application requirements, and every replay bound in draft 5.2 and 6.9 assumes the verifier is the covered origin | `tx.wba_site_names`, required | test_verify 17, test_entry 13; live: tampered-host, recipe-foreign; 3 planted bugs |
| A signature counts for at most an hour after `created` (`invalid/too-old`) | RFC 9421 3.2.1 lists "Enforcing a maximum signature age from the time of the created timestamp", and a verifier "can always reject a signature ahead of its expiration time" | `tx.wba_max_age`, 3600 | test_verify 1-2; planted bug |
| Expiry is exact; the 60 s clock tolerance applies to `created` only | RFC 9421 3.2.1 (expires) | `tx.wba_expiry_grace`, 0 (up to 60) | test_verify 1-2, 14a; planted bug |
| An unparsable `Signature-Input` or `Signature` is ignored (a covered body digest field is not: always `invalid/malformed-digest` and 400) | RFC 9651 4.2's first branch (choice 11) | `tx.wba_malformed`, ignore | as choice 11 |
| No cap on a signature's window while the maximum age is on; a day when it is off (`invalid/window-too-long`) | draft 5.2's 24 hours is RECOMMENDED for signers; RFC 9421 3.2.1 lets a verifier set its own requirements, and the maximum age already bounds how long a signature counts | `tx.wba_max_window`, unset (86400 with `tx.wba_max_age=0`) | test_verify; 3 planted bugs |
| A grant needs `@method` and `@path` covered (`@target-uri` counts as `@path`) | local policy on top of verification; draft 5.2: `@authority` alone "verifies against any method, path, or body" | `tx.wba_grant_require_components`, `@method @path` | test_entry 11; 3 planted bugs |

## RFC 9530 and the unencoded-digest draft

What a request verifier can check of RFC 9530 and the unencoded-digest draft, it checks; what it cannot is `unverified` with a reason that says which.

| Clause | Before | Behaviour | Pinned by |
|---|---|---|---|
| unencoded-digest-05 3, 5: Unencoded-Digest is over the representation with no content coding; a recipient "needs to decode all encodings in order" | a coded body: `unverified/digest-unsupported` | decoded: `gzip` and `x-gzip` (RFC 1952), `deflate` (RFC 1950), stacked last-applied first; not decodable here: `unverified/digest-coding-unsupported`; not valid data in its coding: `invalid/bad-content-coding` | test_verify 14e, test_coding, test_entry 9b; 28 planted bugs (with the two rows below) |
| unencoded-digest-05 3: unknown member parameters MUST be ignored | not tested | complies, tested | test_verify 14e |
| unencoded-digest-05 7: check the received bytes before decoding | n/a | Content-Digest and Repr-Digest are compared first; a failing body is never decoded | test_verify 14e; planted bug |
| RFC 9530 6.7: resource exhaustion | a SHA-256 cap | also a decoding budget, `min(max_decoded_body, max_decode_ratio x body length)` units counting output, deflate blocks and FHCRC headers (128 KiB and 200 by default); the SHA-256 cap applies after decoding | test_coding 6, test_verify 14e; planted bugs |
| RFC 9110 14.4: a server MUST ignore Content-Range on a method that does not define it | Repr-Digest with any `Content-Range`: unverified | ignored except on PUT; a PUT is checked when its range is the whole representation and the content has that length, else `unverified/digest-partial` | test_verify 14e; four planted bugs |
| RFC 9530 3 / unencoded-digest-05 3: over the whole representation | Unencoded-Digest on a partial PUT was compared with the partial body | `unverified/digest-partial` | test_verify 14e |
| RFC 9530 4: Want-Content-Digest and Want-Repr-Digest are hints | undocumented | an nginx recipe for origins (DESIGN.md, Asking bots for body digests); the verifier ignores them and checks the strongest covered Active algorithm | test_verify 14e |

Where the decoder meets formats that zlib-based tools treat more loosely than the RFC text, it follows the text: bytes after the last gzip member (RFC 1952 2.2) or after the zlib stream (RFC 1950) are an error. That is the format, not a deviation: such a body is not gzip or zlib data. A zlib preset dictionary (FDICT) is `invalid/bad-content-coding`: HTTP defines none, and RFC 1950 2.3 says that then "the compressor must not set the FDICT flag" and a decompressor "must give an error indication".
