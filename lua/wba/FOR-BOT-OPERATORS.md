# For bot operators: how to be verified

This page is for the operator of a bot or an AI agent that wants sites running this plugin to see its requests as `verified`. The plugin is a verifier: the program on the site's WAF that checks each request's signature against the public key you publish ([Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/), on [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)). What a site does with `verified` is its own choice ([README](README.md)).

## Publish your keys

At `https://<your-origin>/.well-known/http-message-signatures-directory`:

- Answer `200` with the media type `application/http-message-signatures-directory+json`. Do not redirect.
- The body is a JWK Set of Ed25519 (`OKP`/`Ed25519`), EC (`P-256`, `P-384`) or RSA (2048 to 16384 bits) public keys, with no private members. An RSA key's public exponent must be odd, at least 3 and at most 256 bits. Above 3072 bits it may be at most 64 bits, because OpenSSL verifies nothing with a wider one. The usual 65537 fits both.
- Set `kid` to the key's RFC 7638 thumbprint (draft 5.5).
- If your JWK has `alg`, use `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `rsa-pss-sha512` or `rsa-v1_5-sha256`; the JOSE names `EdDSA`, `Ed25519`, `ES256`, `ES384`, `PS512` and `RS256` also work. Any other value makes the key unusable here. Pinning an RSA key to `PS512` or `rsa-pss-sha512` stops anyone verifying a PKCS #1 v1.5 signature with it (RFC 9421 7.3.6).
- If you publish `nbf`/`exp`, use Unix seconds. The site's key sync reads a value of 10^12 or more as milliseconds, converts it and logs a warning, because at least one live directory publishes milliseconds.
- You may also sign the response (draft Appendix B): one signature per key, `keyid` its thumbprint, tag `http-message-signatures-directory`, covering `("@authority";req "content-digest")` with `created` and `expires`, and a `Content-Digest` of the body. Sites see it as `tx.wba_agent_proof=valid` ([DESIGN.md](DESIGN.md#possession-proofs)).

**Or publish them elsewhere** (draft 5.5): at a JWK Set URL (`Signature-Agent: sig1="https://your-origin.example/jwks.json";type=jwks_uri`), or in an OAuth Client ID Metadata Document whose `client_id` is its own URL and which carries `jwks` or `jwks_uri` (`;type=cimd`). Either way, use `https`, answer `200` and do not redirect. The draft sets no media type there, so any `Content-Type` is read, but the body must parse as JSON and its keys must pass the same checks. `kid` may be any label there; sites index keys by thumbprint.

## Sign every request

Under a label (for example `sig1`):

- Cover `"@authority"` and `"signature-agent";key="sig1"`. Also cover `"@method"` and `"@path"`: by default, sites grant only signatures that cover them, and the plugin's `Accept-Signature` asks for them. They also tie a signature to one request line, which narrows replay.
- Include `created`, `expires` (keep it short: the draft recommends at most 24 h, and by default a site counts a signature for only an hour after `created`), `keyid` (the thumbprint), `alg` (for example `alg="ed25519"`; required for an RSA key whose JWK has no `alg`) and `tag="web-bot-auth"`.
- ECDSA signatures are r ‖ s at fixed width (RFC 9421 3.3.4, 3.3.5), not the DER that most libraries return.

**Send `Signature-Agent` in dictionary form:** `Signature-Agent: sig1="https://your-origin.example"`. For a key directory, send the origin only: a member that is more than an origin (one with a path, say) is ignored (`unverified/bad-agent-url`), and an origin that is not `https` is `invalid/agent-not-https`. The legacy bare-string form is accepted, but the draft says signers MUST send the dictionary.

**Bodies:** cover `Content-Digest`, with `sha-512` (draft 5.2: "An Agent that needs one MUST send and cover Content-Digest"). `Unencoded-Digest` is checked over `gzip` and `deflate` bodies only: over any other coding (`br`, `zstd`, `compress`) it is `unverified/digest-coding-unsupported`.

## Get listed, and check your headers

- **Ask the site to add your origin** (or your `jwks_uri` / `cimd` URL, with its type) to its list of bots. Only keys from the bots a site lists can ever produce `verified`. Never sign with a published test key: the verifier refuses it (`invalid/test-key`).
- **Check your headers** against a known-good request: [`wba-keysync/sign.ts`](../../wba-keysync/sign.ts) `curl` prints one. The README's [Quick start](README.md#quick-start) runs this verifier on your machine in five minutes, so you can send your own requests to it and read the outcome in its log. Every outcome and reason is listed in [Outcomes and reasons](README.md#outcomes-and-reasons).
