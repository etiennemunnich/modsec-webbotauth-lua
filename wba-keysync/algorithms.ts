// algorithms.ts: which signature algorithms key-sync accepts, with which
// keys, and how one is chosen for a signature. The same rules as
// lua/wba/algorithms.lua, for the two places key-sync meets them: a JWK's
// alg (keysync.ts) and a directory response's possession proof (proof.ts,
// draft Appendix B), which is verified exactly as the request verifier
// verifies a request.
//
// The algorithms are RFC 9421 3.3's, less hmac-sha256 (draft 6.4:
// "Implementations MUST NOT use shared HMAC").

/** Key types, as the store names them. */
export type KeyType = "ed25519" | "ec-p256" | "ec-p384" | "rsa";

// Each allowed algorithm (HTTP Signature Algorithms names, the only names a
// signature's alg parameter may carry) and the key type it needs.
export const ALGORITHMS: Record<string, KeyType> = {
  "rsa-pss-sha512": "rsa", "rsa-v1_5-sha256": "rsa",
  "ecdsa-p256-sha256": "ec-p256", "ecdsa-p384-sha384": "ec-p384", "ed25519": "ed25519",
};

// A JWK's own alg member names a JOSE algorithm (RFC 7517 4.4), and draft
// -00 5.5.1 makes every key set a JWK Set, yet also says, with no RFC 2119
// keyword, that "the alg parameter is restricted to" HTTP Signature
// Algorithms names. No value satisfies both (WG issue #136); the editor's
// PR #139, merged on 2026-10-09 (no -01 is published yet), resolves it for
// RFC 7517 4.4. Live signers publish "EdDSA"
// (RFC 8037 3.1) or "Ed25519" (RFC 9864 2.2). So a JWK alg may be either
// kind of name: each JOSE name here is the same algorithm (scheme, hash,
// parameters, signature encoding) as its HTTP name, and the HTTP name is
// what the key is pinned to (RFC 9421 3.2 step 6.5, 7.3.6). JOSE names
// with no HTTP twin (PS256, RS384, ES512, Ed448 and others) pin nothing
// this verifier runs, so such a key is skipped.
const JOSE_ALGORITHMS: Record<string, string> = {
  EdDSA: "ed25519", //            RFC 8037 3.1 with crv Ed25519 = RFC 9421 3.3.6
  Ed25519: "ed25519", //          RFC 9864 2.2 = RFC 9421 3.3.6
  ES256: "ecdsa-p256-sha256", //  RFC 7518 3.4 = RFC 9421 3.3.4 (r || s)
  ES384: "ecdsa-p384-sha384", //  RFC 7518 3.4 = RFC 9421 3.3.5
  PS512: "rsa-pss-sha512", //     RFC 7518 3.5, salt the hash length = RFC 9421 3.3.1
  RS256: "rsa-v1_5-sha256", //    RFC 7518 3.3 = RFC 9421 3.3.2
};

/**
 * The algorithm a JWK's alg member pins its key to, as an ALGORITHMS name:
 * the name itself, or the HTTP twin of a JOSE name. Null when it names no
 * algorithm this verifier runs for this key type.
 */
export function jwkAlgorithm(alg: unknown, type: KeyType): string | null {
  if (typeof alg !== "string") return null;
  const name = Object.hasOwn(ALGORITHMS, alg) ? alg : Object.hasOwn(JOSE_ALGORITHMS, alg) ? JOSE_ALGORITHMS[alg] : null;
  return name !== null && ALGORITHMS[name] === type ? name : null;
}

// The one algorithm a key type allows, where it allows only one: the
// algorithm "determined from the keying material" (RFC 9421 3.2 step 6.3).
// An RSA key allows two, so its type alone determines none.
const ONLY: Partial<Record<KeyType, string>> = { ed25519: "ed25519", "ec-p256": "ecdsa-p256-sha256", "ec-p384": "ecdsa-p384-sha384" };

// RSA bounds, the same as algorithms.lua: a 2048-bit floor (RFC 7518 3.3
// and 3.5, "A key of size 2048 bits or larger MUST be used", for RS256 and
// PS512, the JOSE twins of rsa-v1_5-sha256 and rsa-pss-sha512; RFC 9421
// 3.2.1 names key size as an application requirement), OpenSSL's 16384-bit
// ceiling, and a public exponent that is odd, at least 3 (RFC 8017 3.1) and
// below 2^256 (FIPS 186-5's bound; verification cost grows with it).
export const RSA_MIN_BITS = 2048, RSA_MAX_BITS = 16384, RSA_MAX_E_BITS = 256;
// Above 3072 bits OpenSSL verifies only with e of at most 64 bits
// (OPENSSL_RSA_SMALL_MODULUS_BITS, OPENSSL_RSA_MAX_PUBEXP_BITS), so such a key
// with a wider e could never verify a request: it is skipped, and reported.
export const RSA_LARGE_BITS = 3072, RSA_LARGE_MAX_E_BITS = 64;

/** True when `alg` is an allowed algorithm (RFC 9421 3.2 step 6.1). */
export const allowed = (alg: string) => Object.hasOwn(ALGORITHMS, alg);

/**
 * RFC 9421 3.2 step 6 for one key: the algorithm, or why there is none.
 *   6.3 from the key: its JWK alg, else the one algorithm its type allows
 *   6.4 from the signature: `declared`, already checked with allowed()
 *   6.5 stated in both places: they MUST be the same
 * An algorithm for another key type fails too (step 8: only "if the key
 * material is appropriate for the algorithm").
 */
export function selectAlgorithm(declared: string | undefined, key: { type: KeyType; alg?: string }):
  { alg: string } | { error: "alg-mismatch" | "alg-undetermined" } {
  const fromKey = key.alg ?? ONLY[key.type];
  if (declared !== undefined) {
    if (ALGORITHMS[declared] !== key.type) return { error: "alg-mismatch" };
    if (fromKey !== undefined && fromKey !== declared) return { error: "alg-mismatch" };
    return { alg: declared };
  }
  return fromKey !== undefined ? { alg: fromKey } : { error: "alg-undetermined" };
}

/**
 * The exact signature length for `alg` with a key: 64 bytes for Ed25519 and
 * ECDSA P-256 (r || s), 96 for P-384, the modulus length for RSA (RFC 8017
 * 8.1.2 and 8.2.2 step 1). `publicKeyHex` is the store's encoding.
 */
export function signatureLength(alg: string, publicKeyHex: string): number {
  if (alg === "ecdsa-p384-sha384") return 96;
  if (ALGORITHMS[alg] === "rsa") return publicKeyHex.split(":")[0].length / 2;
  return 64;
}
