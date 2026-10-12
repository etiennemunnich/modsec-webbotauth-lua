// proof.test.ts: sf.ts against the HTTP Working Group's RFC 9651 corpus, and
// proof.ts (WBA draft Appendix B) against the draft's own E.2.3 vector and
// signature bases written out by hand below (never built by proof.ts), signed
// by the runtime's WebCrypto. Runs unchanged under `bun test` and `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDictionary, parseItem, parseList, serializeDictionary, serializeItem, serializeList } from "./sf.ts";
import { contentDigestMismatch, directoryProofs } from "./proof.ts";

const CORPUS = new URL("../lua/tests/sf-corpus/", import.meta.url);

test("sf.ts: every parse record of the RFC 9651 corpus (lua/tests/sf-corpus, pinned by its MANIFEST)", () => {
  const files = readFileSync(new URL("MANIFEST", CORPUS), "utf8").trim().split("\n").map((l) => l.split("  ")[1])
    .filter((f) => !f.startsWith("serialisation-tests/"));
  let records = 0, canFail = 0;
  const bad: string[] = [];
  for (const file of files) {
    for (const rec of JSON.parse(readFileSync(new URL(file, CORPUS), "utf8"))) {
      records++;
      const raw = (rec.raw as string[]).join(", ");
      const [parse, serialize] = rec.header_type === "dictionary" ? [parseDictionary, serializeDictionary]
        : rec.header_type === "list" ? [parseList, serializeList] : [parseItem, serializeItem];
      let out: string;
      try {
        out = (serialize as (v: unknown) => string)((parse as (s: string) => unknown)(raw));
      } catch (err) {
        if (rec.must_fail) continue;
        if (rec.can_fail) { canFail++; continue; }
        bad.push(`${file}: ${rec.name}: ${(err as Error).message}`);
        continue;
      }
      if (rec.must_fail) { bad.push(`${file}: ${rec.name}: parsed, but must fail`); continue; }
      const want = (rec.canonical ?? rec.raw)[0] ?? "";
      if (out !== want) bad.push(`${file}: ${rec.name}: serialized ${JSON.stringify(out)}, want ${JSON.stringify(want)}`);
    }
  }
  assert.deepEqual(bad, [], `${bad.length} of ${records} records`);
  assert.ok(records > 1500, `${records} records`);
  assert.equal(canFail, 1, "only extra base64 padding (RFC 4648 3.2) is declined, as in the Lua parser");
});

// --- Appendix B ----------------------------------------------------------------

const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const utf8 = (s: string) => new TextEncoder().encode(s);
const NOW = 1_800_000_000;

// Draft E.2.3: the RFC 9421 B.1.4 key signs its own directory response.
const E23_BODY = '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",'
  + '"x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}';
const E23_KEY = { keyid: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", type: "ed25519" as const, publicKeyHex: hex(b64("JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=")) };
const E23_HEADERS = {
  "content-type": "application/http-message-signatures-directory+json",
  "content-digest": "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:",
  "signature-input": 'binding=("@authority";req "content-digest");created=1735689600;expires=4889289600'
    + ';keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"',
  signature: "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:",
};
const e23 = (over: Record<string, string | null> = {}, o: { authority?: string; body?: string; now?: number } = {}) => {
  const h = new Headers();
  for (const [k, v] of Object.entries({ ...E23_HEADERS, ...over })) if (v !== null) h.set(k, v);
  return directoryProofs({ authority: o.authority ?? "signature-agent.test", headers: h, body: utf8(o.body ?? E23_BODY),
    keys: [E23_KEY], now: o.now ?? NOW });
};

test("Appendix B: the draft's E.2.3 signed directory response is a valid proof; changing what it binds is not", async () => {
  let r = await e23();
  assert.deepEqual([...r.keys], [[E23_KEY.keyid, { proof: "valid", expires: 4889289600 }]]);
  assert.equal(r.summary, "valid");
  assert.equal(await contentDigestMismatch(E23_HEADERS["content-digest"], utf8(E23_BODY)), null, "the draft's digest");
  for (const [why, p] of [
    ["re-served under another authority", e23({}, { authority: "evil.example" })],
    ["a body swapped under the signature", e23({}, { body: E23_BODY.replace("sig", "enc") })],
    ["created in the future, beyond the 2 s clock tolerance (B.1 MUST reject)", e23({}, { now: 1735689600 - 3 })],
    ["expired (5.5.3)", e23({}, { now: 4889289600 })],
    ["signature bytes changed", e23({ signature: "binding=:" + "A".repeat(86) + "==:" })],
    ["content-coded body", e23({ "content-encoding": "gzip" })],
  ] as const) {
    r = await p;
    assert.equal(r.keys.get(E23_KEY.keyid)!.proof, "invalid", why);
    assert.equal(r.summary, "invalid", why);
  }
  for (const behind of [1, 2]) {
    r = await e23({}, { now: 1735689600 - behind });
    assert.equal(r.summary, "valid", `this clock ${behind} s behind the directory's: within the skew, not "in the future"`);
  }
  r = await e23({ "signature-input": null, signature: null });
  assert.deepEqual([r.summary, r.keys.get(E23_KEY.keyid)!.proof], ["none", "none"], "no proof offered");
  r = await e23({ "signature-input": E23_HEADERS["signature-input"].replace("http-message-signatures-directory", "web-bot-auth") });
  assert.equal(r.summary, "none", "another tag is not a directory response signature");
  r = await e23({ signature: "binding=:not base64:" });
  assert.deepEqual([r.summary, r.keys.get(E23_KEY.keyid)!.proof], ["invalid", "invalid"], "an unparsable Signature (RFC 9651)");
});

// A fresh key and hand-written signature bases, for what E.2.3 does not show.
const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
const RAW = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
const KEY = { keyid: "k".repeat(43), type: "ed25519" as const, publicKeyHex: hex(RAW) }; // keyid is only matched, never recomputed here
const BODY = '{"keys":[]}';
const D256 = "sha-256=:" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(BODY))))) + ":";
const D512 = "sha-512=:" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-512", utf8(BODY))))) + ":";

/** A response signed over `lines` (hand-written) plus the @signature-params line. */
async function signed(o: { inner: string; lines: string[]; digest?: string; extra?: Record<string, string>; label?: string }) {
  const label = o.label ?? "b";
  const base = [...o.lines, `"@signature-params": ${o.inner}`].join("\n");
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, utf8(base)));
  const h = new Headers({ "content-digest": o.digest ?? D256, "signature-input": `${label}=${o.inner}`,
    signature: `${label}=:${btoa(String.fromCharCode(...sig))}:`, ...o.extra });
  return directoryProofs({ authority: "a.example:8443", headers: h, body: utf8(BODY), keys: [KEY], now: NOW });
}
const P = `;created=${NOW - 5};expires=${NOW + 600};keyid="${KEY.keyid}";alg="ed25519";tag="http-message-signatures-directory"`;
const AUTH = '"@authority";req: a.example:8443';

test("Appendix B: covered components, algorithms and digests (B.1; RFC 9421 2.4, 2.5, 3.2; RFC 9530)", async () => {
  const ok = await signed({ inner: `("@authority";req "content-digest")${P}`, lines: [AUTH, `"content-digest": ${D256}`] });
  assert.deepEqual(ok.keys.get(KEY.keyid), { proof: "valid", expires: NOW + 600 });
  const extra = await signed({ inner: `("content-type" "@authority";req "content-digest")${P}`,
    lines: ['"content-type": application/http-message-signatures-directory+json', AUTH, `"content-digest": ${D256}`],
    extra: { "content-type": "application/http-message-signatures-directory+json" } });
  assert.equal(extra.summary, "valid", "a response field may be covered too");
  const both = `${D256}, ${D512}`;
  assert.equal((await signed({ inner: `("@authority";req "content-digest")${P}`, lines: [AUTH, `"content-digest": ${both}`],
    digest: both })).summary, "valid", "sha-256 and sha-512 both match");
  const wrong512 = `${D256}, sha-512=:${"A".repeat(86)}==:`;
  const cases: [string, { inner: string; lines: string[]; digest?: string; extra?: Record<string, string> }][] = [
    ["@authority without req (a request component in a response)",
      { inner: `("@authority" "content-digest")${P}`, lines: ['"@authority": a.example:8443', `"content-digest": ${D256}`] }],
    ["@authority without req, beside the required @authority;req",
      { inner: `("@authority";req "@authority" "content-digest")${P}`,
        lines: [AUTH, '"@authority": a.example:8443', `"content-digest": ${D256}`] }],
    ["content-digest not covered (B.1)", { inner: `("@authority";req)${P}`, lines: [AUTH] }],
    ["@authority;req not covered (B.1)", { inner: `("content-digest")${P}`, lines: [`"content-digest": ${D256}`] }],
    ["a repeated component (RFC 9421 2.5)", { inner: `("@authority";req "content-digest" "content-digest")${P}`,
      lines: [AUTH, `"content-digest": ${D256}`, `"content-digest": ${D256}`] }],
    ["every Active digest must match the body", { inner: `("@authority";req "content-digest")${P}`,
      lines: [AUTH, `"content-digest": ${wrong512}`], digest: wrong512 }],
    ["no Active digest algorithm (RFC 9530 5)", { inner: `("@authority";req "content-digest")${P}`,
      lines: [AUTH, '"content-digest": md5=:AAAA:'], digest: "md5=:AAAA:" }],
    ["alg other than ed25519 (RFC 9421 3.2 step 6.5)", { inner: `("@authority";req "content-digest")${P.replace("ed25519", "rsa-pss-sha512")}`,
      lines: [AUTH, `"content-digest": ${D256}`] }],
    ["no created (B.1)", { inner: `("@authority";req "content-digest")${P.replace(/;created=\d+/, "")}`,
      lines: [AUTH, `"content-digest": ${D256}`] }],
    ["a covered field the response lacks", { inner: `("@authority";req "content-digest" "x-missing")${P}`,
      lines: [AUTH, `"content-digest": ${D256}`, '"x-missing": '] }],
  ];
  for (const [why, c] of cases) {
    const r = await signed(c);
    assert.equal(r.keys.get(KEY.keyid)!.proof, "invalid", why);
    assert.equal(r.notes.length, 1, why);
  }
});

test("Appendix B: proofs are per key; a signature naming no kept key proves nothing", async () => {
  const other = await signed({ inner: `("@authority";req "content-digest")${P.replace("k".repeat(43), "o".repeat(43))}`,
    lines: [AUTH, `"content-digest": ${D256}`] });
  assert.deepEqual([other.summary, other.keys.get(KEY.keyid)!.proof], ["invalid", "none"],
    "offered, but for no key kept: the directory's proof is invalid, this key's is none");
  assert.match(other.notes[0], /names no key kept/);
  // Two signatures for one key, one good: valid (B.1: each key SHOULD give one, a verifier takes a valid one).
  const inner = `("@authority";req "content-digest")${P}`;
  const base = [AUTH, `"content-digest": ${D256}`, `"@signature-params": ${inner}`].join("\n");
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, utf8(base)))));
  const h = new Headers({ "content-digest": D256, "signature-input": `x=${inner}, y=${inner}`, signature: `x=:${"A".repeat(86)}==:, y=:${sig}:` });
  const r = await directoryProofs({ authority: "a.example:8443", headers: h, body: utf8(BODY), keys: [KEY], now: NOW });
  assert.deepEqual(r.keys.get(KEY.keyid), { proof: "valid", expires: NOW + 600 });
});

// --- Every algorithm (algorithms.ts: the request verifier's rules) -----------
// Fresh keys from the runtime's WebCrypto, signing hand-written bases. A key
// is given to directoryProofs as the store holds it: type, JWK alg, hex.

type Signer = (base: Uint8Array, o?: { saltLength?: number }) => Promise<Uint8Array>;
const unb64url = (s: string) => b64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));

async function ecKey(curve: "P-256" | "P-384") {
  const p = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", p.publicKey)); // 04 || x || y
  const hash = curve === "P-256" ? "SHA-256" : "SHA-384";
  const sign: Signer = async (base) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash }, p.privateKey, base as Uint8Array<ArrayBuffer>));
  return { hex: hex(raw), sign };
}
const RSA_PAIR = await crypto.subtle.generateKey(
  { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-512" }, true, ["sign", "verify"],
) as CryptoKeyPair;
const RSA_JWK = await crypto.subtle.exportKey("jwk", RSA_PAIR.privateKey);
const RSA_HEX = `${hex(unb64url(RSA_JWK.n!))}:${hex(unb64url(RSA_JWK.e!))}`;
const { alg: _alg, key_ops: _ops, ...RSA_PRIV } = RSA_JWK; // the same key, for PKCS #1 v1.5 with SHA-256
const RSA_V15 = await crypto.subtle.importKey("jwk", RSA_PRIV, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
const P256 = await ecKey("P-256"), P384 = await ecKey("P-384");
const SIGNERS: Record<string, Signer> = {
  ed25519: async (base) => new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, base as Uint8Array<ArrayBuffer>)),
  "ecdsa-p256-sha256": P256.sign,
  "ecdsa-p384-sha384": P384.sign,
  "rsa-pss-sha512": async (base, o) =>
    new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: o?.saltLength ?? 64 }, RSA_PAIR.privateKey, base as Uint8Array<ArrayBuffer>)),
  "rsa-v1_5-sha256": async (base) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", RSA_V15, base as Uint8Array<ArrayBuffer>)),
};
type Held = { keyid: string; type: "ed25519" | "ec-p256" | "ec-p384" | "rsa"; alg?: string; publicKeyHex: string };
const KEYS: Record<string, Held> = {
  ed25519: { keyid: KEY.keyid, type: "ed25519", publicKeyHex: hex(RAW) },
  p256: { keyid: KEY.keyid, type: "ec-p256", publicKeyHex: P256.hex },
  p384: { keyid: KEY.keyid, type: "ec-p384", publicKeyHex: P384.hex },
  rsa: { keyid: KEY.keyid, type: "rsa", publicKeyHex: RSA_HEX },
};

/** r || s as a DER ECDSA-Sig-Value, the form most libraries return (never sent per RFC 9421). */
function derOf(s: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b[i] >= 0x80 ? [0, ...b.slice(i)] : Array.from(b.slice(i));
    return [2, v.length, ...v];
  };
  const body = [...int(s.slice(0, s.length / 2)), ...int(s.slice(s.length / 2))];
  return new Uint8Array([0x30, body.length, ...body]);
}

/** A response signed by `signAs` over the B.1 components, declaring `declared` (none: no alg parameter). */
async function proofBy(key: Held, signAs: string, declared?: string,
  o: { saltLength?: number; mangle?: (s: Uint8Array) => Uint8Array } = {}) {
  const inner = `("@authority";req "content-digest");created=${NOW - 5};expires=${NOW + 600};keyid="${key.keyid}"`
    + (declared ? `;alg="${declared}"` : "") + ';tag="http-message-signatures-directory"';
  const base = utf8([AUTH, `"content-digest": ${D256}`, `"@signature-params": ${inner}`].join("\n"));
  let sig = await SIGNERS[signAs](base, o);
  if (o.mangle) sig = o.mangle(sig);
  const h = new Headers({ "content-digest": D256, "signature-input": `b=${inner}`, signature: `b=:${btoa(String.fromCharCode(...sig))}:` });
  const r = await directoryProofs({ authority: "a.example:8443", headers: h, body: utf8(BODY), keys: [key], now: NOW });
  lastNote = r.notes.join("; ");
  return r.keys.get(key.keyid)!.proof;
}
let lastNote = "";

test("Appendix B: every algorithm the verifier accepts verifies a proof, alg declared or from the key (RFC 9421 3.3, 3.2 step 6)", async () => {
  for (const [key, alg] of [[KEYS.ed25519, "ed25519"], [KEYS.p256, "ecdsa-p256-sha256"], [KEYS.p384, "ecdsa-p384-sha384"],
    [KEYS.rsa, "rsa-pss-sha512"], [KEYS.rsa, "rsa-v1_5-sha256"]] as const) {
    assert.equal(await proofBy(key, alg, alg), "valid", `${alg}, alg declared`);
    assert.equal(await proofBy({ ...key, alg }, alg, alg), "valid", `${alg}, alg declared and pinned on the key`);
    assert.equal(await proofBy({ ...key, alg }, alg), "valid", `${alg}, alg from the key's JWK (6.3)`);
    if (key.type !== "rsa") assert.equal(await proofBy(key, alg), "valid", `${alg}, alg from the key type (6.3)`);
  }
});

test("Appendix B: the verifier's algorithm rules hold for proofs too (RFC 9421 3.2 step 6, 3.3.1, 3.3.4, 3.3.5; draft 6.4)", async () => {
  const swap = (s: Uint8Array) => new Uint8Array([...s.slice(s.length / 2), ...s.slice(0, s.length / 2)]);
  // Each refused, and for its own reason (the note proof.ts records).
  const bad: [string, () => Promise<string>, RegExp][] = [
    ["an RSA key with no alg, and no alg parameter", () => proofBy(KEYS.rsa, "rsa-pss-sha512"), /no algorithm determined/],
    ["a key pinned to RSA-PSS, a PKCS #1 v1.5 signature (6.5; 7.3.6)",
      () => proofBy({ ...KEYS.rsa, alg: "rsa-pss-sha512" }, "rsa-v1_5-sha256", "rsa-v1_5-sha256"), /disagrees with the rsa key pinned/],
    ["an alg for another key type (P-256 key, ecdsa-p384-sha384)",
      () => proofBy(KEYS.p256, "ecdsa-p256-sha256", "ecdsa-p384-sha384"), /disagrees with the ec-p256 key/],
    ["an alg for another key type (Ed25519 key, ecdsa-p256-sha256)",
      () => proofBy(KEYS.ed25519, "ed25519", "ecdsa-p256-sha256"), /disagrees with the ed25519 key/],
    ["an alg for another key type (unpinned RSA key, ed25519)", () => proofBy(KEYS.rsa, "ed25519", "ed25519"), /disagrees with the rsa key/],
    ["hmac-sha256 (draft 6.4)", () => proofBy(KEYS.ed25519, "ed25519", "hmac-sha256"), /not an allowed algorithm/],
    ["a JOSE name (ES256)", () => proofBy(KEYS.p256, "ecdsa-p256-sha256", "ES256"), /not an allowed algorithm/],
    ["RSA-PSS with a 32-byte salt", () => proofBy(KEYS.rsa, "rsa-pss-sha512", "rsa-pss-sha512", { saltLength: 32 }), /does not verify/],
    ["a PKCS #1 v1.5 signature presented as RSA-PSS", () => proofBy(KEYS.rsa, "rsa-v1_5-sha256", "rsa-pss-sha512"), /does not verify/],
    ["an RSA-PSS signature presented as PKCS #1 v1.5", () => proofBy(KEYS.rsa, "rsa-pss-sha512", "rsa-v1_5-sha256"), /does not verify/],
    ["an RSA signature one byte short",
      () => proofBy(KEYS.rsa, "rsa-pss-sha512", "rsa-pss-sha512", { mangle: (s) => s.slice(1) }), /no 256-byte Signature member/],
    ["ECDSA P-384 r || s one byte long",
      () => proofBy(KEYS.p384, "ecdsa-p384-sha384", undefined, { mangle: (s) => new Uint8Array([...s, 0]) }), /no 96-byte Signature member/],
    ["ECDSA P-256 as DER (3.3.4: r || s only)",
      () => proofBy(KEYS.p256, "ecdsa-p256-sha256", "ecdsa-p256-sha256", { mangle: derOf }), /no 64-byte Signature member/],
    ["ECDSA r and s swapped", () => proofBy(KEYS.p256, "ecdsa-p256-sha256", undefined, { mangle: swap }), /does not verify/],
  ];
  for (const [why, run, note] of bad) {
    assert.equal(await run(), "invalid", why);
    assert.match(lastNote, note, why);
  }
});
