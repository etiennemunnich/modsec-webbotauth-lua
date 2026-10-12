// proof.ts: WBA draft Appendix B.1, the possession proof on a directory
// response. A directory server signs its own response once per key (RFC 9421,
// tag "http-message-signatures-directory"), covering "@authority";req and
// content-digest, so the key set cannot be re-served under another authority
// or swapped under a captured signature.
//
// B.1: "A verifier using a corresponding directory response signature as
// proof MUST validate it using the key provided by the directory and MUST
// validate the Content-Digest field against the response body. If either
// validation fails, the proof is invalid. A verifier MAY use a key obtained
// by resolving the directory itself whether or not it has valid proof. ...
// A verifier MUST reject a directory response signature whose created is in
// the future." 5.5.3: valid only while its expires has not passed. Appendix B
// applies to the directory type only.
//
// Every algorithm the request verifier accepts is accepted here, chosen and
// checked by the same rules (algorithms.ts, RFC 9421 3.2 step 6): the alg
// parameter must be allowed (6.1) and agree with the key's JWK alg or the one
// algorithm its type allows (6.5), an RSA key with neither fails, and the
// signature must be exactly the algorithm's length. WebCrypto then verifies:
// Ed25519; ECDSA P-256 and P-384, whose WebCrypto signature format is r || s,
// exactly RFC 9421 3.3.4 and 3.3.5's; RSA-PSS with SHA-512, MGF1 with
// SHA-512 (WebCrypto's MGF1 uses the key's hash) and a salt length of 64
// (3.3.1); RSASSA-PKCS1-v1_5 with SHA-256 (3.3.2).
//
// key-sync keeps using every key (the B.1 MAY) and records, per key:
//   valid    a signature with keyid = the key's thumbprint validated
//            (expires: the latest such signature's expires)
//   invalid  a signature named the key and none validated, or the response's
//            Signature / Signature-Input fields do not parse
//   none     no signature named the key
// and per directory: valid if any key's proof is, invalid if a proof was
// offered and none validated, none if none was offered.

import { parseDictionary, serializeItem, serializeMember, type Dictionary, type InnerList, type Item } from "./sf.ts";
import { allowed, selectAlgorithm, signatureLength, type KeyType } from "./algorithms.ts";

const PROOF_TAG = "http-message-signatures-directory";
/**
 * Seconds a proof's `created` may run ahead of this clock. B.1: "A verifier MUST
 * reject a directory response signature whose created is in the future", since
 * a future-dated proof would outrank every later fetch (4.4). Signers stamp
 * `created` with their current second, so a clock a fraction of a second behind
 * theirs reads a fresh proof as future-dated (12 of 25 fetches of chatgpt.com
 * on 2026-10-09). 2 s absorbs that and bounds the outranking B.1 guards
 * against to 2 s: a declared deviation (CONFORMANCE.md), for clock accuracy.
 */
const PROOF_CLOCK_SKEW = 2;
export type Proof = "valid" | "invalid" | "none";
interface KeyProof { proof: Proof; expires?: number }
export interface ProofResult { keys: Map<string, KeyProof>; summary: Proof; notes: string[] }
/** A key kept from the directory, in the store's encoding (keysync.ts StoreEntry). */
export interface ProofKey { keyid: string; type: KeyType; alg?: string; publicKeyHex: string }

// RFC 9530 5: the Active algorithms; Deprecated ones (md5, sha, ...) are
// never trusted where an attacker may be present, and unknown ones are ignored.
const ACTIVE: Record<string, string> = { "sha-256": "SHA-256", "sha-512": "SHA-512" };

const toBytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/**
 * RFC 9421 3.3's HTTP_VERIFY for `alg` (already selected for this key) over
 * WebCrypto. The key is rebuilt from the store's encoding: Ed25519 and EC
 * from their raw form (an EC point off its curve fails to import), RSA from
 * its (n, e) as a JWK.
 */
async function httpVerify(alg: string, key: ProofKey, sig: Uint8Array, base: Uint8Array): Promise<boolean> {
  let params: AlgorithmIdentifier | RsaPssParams | EcdsaParams, imp: CryptoKey;
  if (alg === "ed25519") {
    imp = await crypto.subtle.importKey("raw", toBytes(key.publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
    params = { name: "Ed25519" };
  } else if (alg === "ecdsa-p256-sha256" || alg === "ecdsa-p384-sha384") {
    const [curve, hash] = alg === "ecdsa-p256-sha256" ? ["P-256", "SHA-256"] : ["P-384", "SHA-384"];
    imp = await crypto.subtle.importKey("raw", toBytes(key.publicKeyHex), { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
    params = { name: "ECDSA", hash };
  } else {
    const [n, e] = key.publicKeyHex.split(":").map((h) => b64url(toBytes(h)));
    const name = alg === "rsa-pss-sha512" ? "RSA-PSS" : "RSASSA-PKCS1-v1_5";
    imp = await crypto.subtle.importKey("jwk", { kty: "RSA", n, e },
      { name, hash: alg === "rsa-pss-sha512" ? "SHA-512" : "SHA-256" }, false, ["verify"]);
    params = alg === "rsa-pss-sha512" ? { name, saltLength: 64 } : { name };
  }
  // Our byte arrays are never shared memory, which is what WebCrypto's type rules out.
  return crypto.subtle.verify(params, imp, sig as Uint8Array<ArrayBuffer>, base as Uint8Array<ArrayBuffer>);
}

/**
 * RFC 9530: every Active member of Content-Digest matches the body, and
 * there is at least one. Returns null when it holds, else why not.
 */
export async function contentDigestMismatch(field: string | null, body: Uint8Array): Promise<string | null> {
  if (field === null) return "no Content-Digest";
  let dict: Dictionary;
  try { dict = parseDictionary(field); } catch { return "Content-Digest does not parse (RFC 9651)"; }
  let checked = 0;
  for (const [alg, member] of dict) {
    if (!(alg in ACTIVE)) continue;
    if (member.kind !== "item" || member.value.type !== "binary") return `Content-Digest ${alg} is not a Byte Sequence`;
    const got = new Uint8Array(await crypto.subtle.digest(ACTIVE[alg], body as Uint8Array<ArrayBuffer>));
    if (!equal(got, member.value.value)) return `Content-Digest ${alg} does not match the body`;
    checked++;
  }
  return checked === 0 ? "Content-Digest has no Active algorithm (RFC 9530 5)" : null;
}

const intParam = (p: InnerList, k: string) => {
  const v = p.params.get(k);
  return v?.type === "integer" ? v.value : undefined;
};
const strParam = (p: InnerList, k: string) => {
  const v = p.params.get(k);
  return v?.type === "string" ? v.value : undefined;
};

/** Why one directory response signature fails, or null when it validates (RFC 9421 3.2 for a response). */
async function failure(
  label: string, input: InnerList, sig: Item | undefined, key: ProofKey,
  req: { authority: string }, headers: Headers, body: Uint8Array, now: number,
): Promise<string | null> {
  const created = intParam(input, "created"), expires = intParam(input, "expires");
  if (created === undefined || expires === undefined) return "created and expires are required (B.1)";
  // B.1: a proof created "in the future" MUST be rejected. Read with the request
  // path's clock-skew allowance (verify.lua clock_skew): a directory stamps its
  // response with its current second, so a verifier clock a fraction of a
  // second behind would otherwise call every fresh proof "in the future".
  if (created > now + PROOF_CLOCK_SKEW) return `created ${created} is in the future, beyond ${PROOF_CLOCK_SKEW} s of clock skew (B.1 MUST reject)`;
  if (expires <= now) return `expired at ${expires} (5.5.3)`;
  if (expires <= created) return "expires is not after created";
  // RFC 9421 3.2 step 6, as the request verifier applies it (algorithms.ts).
  const algParam = input.params.get("alg");
  let declared: string | undefined;
  if (algParam !== undefined) {
    if (!(algParam.type === "string" && allowed(algParam.value))) return "alg is not an allowed algorithm (RFC 9421 3.2 step 6.1; draft 6.4)";
    declared = algParam.value;
  }
  const chosen = selectAlgorithm(declared, key);
  if ("error" in chosen) {
    return chosen.error === "alg-mismatch"
      ? `alg ${declared} disagrees with the ${key.type} key${key.alg ? ` pinned to ${key.alg}` : ""} (RFC 9421 3.2 step 6.5, step 8)`
      : "no algorithm determined: an RSA key with no alg, and no alg parameter (RFC 9421 3.2 step 6)";
  }
  const want = signatureLength(chosen.alg, key.publicKeyHex);
  if (!sig || sig.value.type !== "binary" || sig.value.value.length !== want) {
    return `no ${want}-byte Signature member for the label (${chosen.alg})`;
  }

  // Covered components: B.1 requires "@authority";req and content-digest.
  // Response header fields may be covered too; nothing else is resolvable here.
  const lines: string[] = [];
  const seen = new Set<string>();
  for (const it of input.items) {
    if (it.value.type !== "string") return "a component identifier is not a String";
    const id = serializeItem(it);
    if (seen.has(id)) return `${id} covered twice (RFC 9421 2.5)`;
    seen.add(id);
    const name = it.value.value;
    if (name === "@authority" && it.params.size === 1 && it.params.get("req")?.value === true) {
      lines.push(`${id}: ${req.authority}`);
    } else if (/^[a-z0-9!#$%&'*+\-.^_`|~]+$/.test(name) && it.params.size === 0) {
      const v = headers.get(name);
      if (v === null) return `covered field ${name} is absent`;
      lines.push(`${id}: ${v.trim()}`);
    } else {
      return `${id} cannot be resolved for a directory response`;
    }
  }
  if (!seen.has('"@authority";req')) return '"@authority";req is not covered (B.1)';
  if (!seen.has('"content-digest"')) return "content-digest is not covered (B.1)";

  const coding = (headers.get("content-encoding") ?? "identity").trim().toLowerCase();
  if (coding !== "identity") return `content-coded (${coding}): Content-Digest cannot be checked against the decoded body`;
  const digest = await contentDigestMismatch(headers.get("content-digest"), body);
  if (digest) return digest;

  lines.push(`"@signature-params": ${serializeMember(input)}`);
  let ok: boolean;
  try {
    ok = await httpVerify(chosen.alg, key, sig.value.value, new TextEncoder().encode(lines.join("\n")));
  } catch (err) {
    return `${key.type} key not usable for ${chosen.alg}: ${(err as Error).message}`;
  }
  return ok ? null : `signature ${label} does not verify (${chosen.alg})`;
}

/**
 * Appendix B proofs in one directory response, for the keys key-sync keeps
 * from it (keyid = RFC 7638 thumbprint; type, alg and public key as the store holds them).
 * `authority` is the @authority of the request that fetched the directory.
 */
export async function directoryProofs(
  r: { authority: string; headers: Headers; body: Uint8Array; keys: ProofKey[]; now: number },
): Promise<ProofResult> {
  const out: ProofResult = { keys: new Map(), summary: "none", notes: [] };
  for (const k of r.keys) out.keys.set(k.keyid, { proof: "none" });
  const inputField = r.headers.get("signature-input"), sigField = r.headers.get("signature");
  if (inputField === null && sigField === null) return out;

  let inputs: Dictionary, sigs: Dictionary;
  try {
    inputs = parseDictionary(inputField ?? "");
    sigs = parseDictionary(sigField ?? "");
  } catch (err) {
    for (const k of out.keys.values()) k.proof = "invalid";
    out.summary = "invalid";
    out.notes.push(`Signature or Signature-Input does not parse: ${(err as Error).message}`);
    return out;
  }
  const byKeyid = new Map(r.keys.map((k) => [k.keyid, k]));
  let offered = false;
  for (const [label, member] of inputs) {
    if (member.kind !== "inner-list" || strParam(member, "tag") !== PROOF_TAG) continue;
    offered = true;
    const keyid = strParam(member, "keyid");
    const key = keyid !== undefined ? byKeyid.get(keyid) : undefined;
    if (!key || keyid === undefined) {
      out.notes.push(`signature ${label}: keyid ${JSON.stringify(keyid ?? null).slice(0, 60)} names no key kept from this directory`);
      continue;
    }
    const s = sigs.get(label);
    const why = await failure(label, member, s?.kind === "item" ? s : undefined, key,
      { authority: r.authority }, r.headers, r.body, r.now);
    const held = out.keys.get(keyid)!;
    if (why === null) {
      const expires = intParam(member, "expires")!;
      out.keys.set(keyid, { proof: "valid", expires: Math.max(expires, held.expires ?? 0) });
    } else {
      if (held.proof !== "valid") held.proof = "invalid";
      out.notes.push(`signature ${label} (${keyid}): ${why}`);
    }
  }
  const proofs = [...out.keys.values()].map((k) => k.proof);
  out.summary = proofs.includes("valid") ? "valid" : offered ? "invalid" : "none";
  return out;
}
