// keysync.test.ts: runs unchanged under `bun test` and `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import {
  DEFAULT_LIMITS, HISTORY_HEADER, MAX_FRESHNESS, MEDIA_TYPE, WELL_KNOWN, allowedOrigin, appendHistory, fetchDirectory, historyLines, forbiddenAddress, format,
  freshnessLifetime, identifier, keysFromDirectory, parse, parseAgent, printable, sync, thumbprint, urlIdentifier, withDeadline, writeAtomic,
  type Cache, type FetchLike, type StoreEntry,
} from "./keysync.ts";
import { directoryIdentifier } from "./identifier.ts";
import { main as keysyncMain, readAgents } from "./cli.ts";

const FIXTURE = new URL("../lua/tests/fixtures/wba-keys.tsv", import.meta.url);
const VECTORS = new URL("../lua/tests/fixtures/identifiers.tsv", import.meta.url);

// RFC 8037 Appendix A.3 key and its published thumbprint: the oracle for
// thumbprint(). Its private half is published (it is RFC 8032 7.1 TEST 1),
// so it is also a test key every directory must have rejected.
const X_8037 = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const KID_8037 = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
// The valid agent key in every other test and in lua/tests/fixtures: generated
// for these fixtures, private half discarded; thumbprint computed by openssl.
const X_KEY = "zxCdg3SebLwIqmV8uI0V-H-jFYwleEZGPFRlD98KVKc";
const KID_KEY = "YIGq9u-ucksC9KcownKqCEJ082n_7gSkCozYsYaS7y8";
const HEX_KEY = "cf109d83749e6cbc08aa657cb88d15f87fa3158c257846463c54650fdf0a54a7";
// RFC 9421 Appendix B.1.4 key: the draft's E.2 keyid, and a published test key.
const X_9421 = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
const KID_9421 = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

const NOW = 1_700_000_000;
const ID = (host: string) => `https://${host}/.well-known/http-message-signatures-directory`;
const noWarn = (w: string) => assert.fail(`unexpected warning: ${w}`);

const okp = (x: string) => ({ kty: "OKP", crv: "Ed25519", x } as const);

// The EC and RSA fixture keys (lua/tests/fixtures/wba-keys.tsv): generated
// by openssl for the fixtures, private halves discarded; thumbprints computed
// by openssl in lua/tests/test_keys.lua, independently of thumbprint().
const P256 = { kty: "EC", crv: "P-256", x: "shbaYSof717UwNKUg_ZQtLQDECcYtJ4Zzveq5swkqbw",
  y: "ax9tz02-rTfeqK5JKj56UYw4UOfJZvx-5vBhHAfW1iE" } as const;
const KID_P256 = "k_68AQ2ZHOzotenLHvB06vit-mGArdHu98aNlur-mbY";
const HEX_P256 = "04b216da612a1fef5ed4c0d29483f650b4b403102718b49e19cef7aae6cc24a9bc6b1f6dcf4dbead37dea8ae492a3e7a518c3850e7c966fc7ee6f0611c07d6d621";
const P384 = { kty: "EC", crv: "P-384", x: "wnG7SiISMpelqkxl6dU0rDVuFxnt_Q5dT2XvzK_0Ch1p0sjhQO54Tg7xKQ9LzTII",
  y: "Saac8vs8hehDfuXr0a7BrPo136HhsHXnU32G2FPwSdEwzrcNPZvx93zEWmOFBbB4" } as const;
const KID_P384 = "Xs8ArbSNwEeH7d1mn0Lmfqeu-e4uuvg5yL1tLnilhWY";
const HEX_P384 = "04c271bb4a22123297a5aa4c65e9d534ac356e1719edfd0e5d4f65efccaff40a1d69d2c8e140ee784e0ef1290f4bcd320849a69cf2fb3c85e8437ee5ebd1aec1acfa35dfa1e1b075e7537d86d853f049d130ceb70d3d9bf1f77cc45a638505b078";
const RSA = { kty: "RSA", e: "AQAB", n: "lj4OMQjprZBFbr2RuTKqpxbWjf-9NXOPUpKp1sIOGj5fMxlYGhbRa1-U-cT_pbGvxV8hDJtuVZXoIXGkQy_oe2aV-FpioRQNohTbrxOQYeARs2NAW3VG5AD_C5sOjK5tIJS-waIVvGx8sHAodWA5e556RCC1P8d20l_j6jzFKvSAWjDSVRj8Dq_-UN_1mILZawCVYxJb8vrWwN-WX00b5djXdF055sb2VofcRKlLATGPCresCS2hDyEurTPpI4oUraxA8RJgAOSo6gqRzDp1yecqTgSS65Xpm8PWAGbXst06KMtGd-Pp0_Hgb1Mam2yKdeAVWET7cQXOeloZNOgvfw" } as const;
const KID_RSA = "SWbXVsyNhvdYgDdwSXlQMoeKmiEBegGW0OaFmYHIwEw";
const HEX_RSA = "963e0e3108e9ad90456ebd91b932aaa716d68dffbd35738f5292a9d6c20e1a3e5f3319581a16d16b5f94f9c4ffa5b1afc55f210c9b6e5595e82171a4432fe87b6695f85a62a1140da214dbaf139061e011b363405b7546e400ff0b9b0e8cae6d2094bec1a215bc6c7cb070287560397b9e7a4420b53fc776d25fe3ea3cc52af4805a30d25518fc0eaffe50dff59882d96b009563125bf2fad6c0df965f4d1be5d8d7745d39e6c6f65687dc44a94b01318f0ab7ac092da10f212ead33e9238a14adac40f1126000e4a8ea0a91cc3a75c9e72a4e0492eb95e99bc3d60066d7b2dd3a28cb4677e3e9d3f1e06f531a9b6c8a75e0155844fb7105ce7a5a1934e82f7f:010001";
// RFC 7638 3.1's worked example (RFC 7517 A.1's RSA key) and RFC 9421
// B.1.2's test-key-rsa-pss, whose thumbprint is the WBA draft's E.1 keyid.
const N_7638 = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const N_9421_PSS = "r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V2pnDOkFV6-U9nV5oyc6XI2w";

test("RFC 7638 thumbprints: RFC 8037 A.3, RFC 7638 3.1, the WBA draft E.1 and E.2 keyids, the openssl-computed fixtures", async () => {
  assert.equal(await thumbprint(okp(X_8037)), KID_8037);
  assert.equal(await thumbprint(okp(X_KEY)), KID_KEY);
  assert.equal(await thumbprint(okp(X_9421)), KID_9421);
  assert.equal(await thumbprint({ kty: "RSA", n: N_7638, e: "AQAB" }), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
  assert.equal(await thumbprint({ kty: "RSA", n: N_9421_PSS, e: "AQAB" }), "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA");
  assert.equal(await thumbprint(P256), KID_P256);
  assert.equal(await thumbprint(P384), KID_P384);
  assert.equal(await thumbprint(RSA), KID_RSA);
});

test("identifiers: every row of the vectors keys.lua runs (draft 5.5; RFC 3986 6.2.2/6.2.3, RFC 5952, RFC 6454)", () => {
  let rows = 0;
  for (const line of readFileSync(VECTORS, "utf8").split("\n")) {
    if (line === "" || line.startsWith("#") || line.startsWith("mode\t")) continue;
    const [mode, input, w] = line.split("\t");
    const want = w === "-" ? null : w.replace(/WK$/, WELL_KNOWN);
    const got = mode === "origin" ? directoryIdentifier(input, true)
      : mode === "lenient" ? identifier(input) : mode === "url" ? urlIdentifier(input) : assert.fail(`mode ${mode}`);
    assert.equal(got, want, `${mode} ${input}`);
    if (got !== null) assert.equal(urlIdentifier(got), got, `an identifier is its own normal form: ${got}`);
    rows++;
  }
  assert.ok(rows >= 100, `${rows} vectors`);
  assert.equal(identifier(""), null);
});

test("keysFromDirectory: indexed by computed thumbprint, bad keys skipped", async () => {
  const warnings: string[] = [];
  const keys = await keysFromDirectory({
    keys: [
      { kty: "OKP", crv: "Ed25519", x: X_KEY, kid: KID_KEY, use: "sig", nbf: 1712793600, exp: 1_800_000_000 },
      { kty: "RSA", n: "x", e: "AQAB" },                                   // malformed n
      { kty: "OKP", crv: "Ed25519", x: X_KEY.slice(1) },                  // malformed x
      { kty: "OKP", crv: "Ed25519", x: X_KEY.slice(0, 42) + "p" },       // non-zero pad bits
      { kty: "OKP", crv: "Ed25519", x: X_KEY, use: "enc" },               // not for signing
      { kty: "OKP", crv: "Ed25519", x: X_KEY, exp: NOW - 1 },             // expired
      { kty: "OKP", crv: "Ed25519", x: X_KEY, exp: "soon" },              // bad exp
      { kty: "OKP", crv: "Ed25519", x: X_9421 },                           // published test key
      { kty: "oct", k: "c2VjcmV0" },                                       // a shared secret: private (draft 6.4)
      "not an object",
    ],
  }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.deepEqual(keys, [{ keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY, nbf: 1712793600, exp: 1_800_000_000 }]);
  assert.equal(warnings.length, 6, warnings.join("; "));
  assert.ok(warnings.some((w) => w.includes("test key")));
  assert.ok(warnings.includes("skipped RSA key with malformed n or e"));
});

test("keysFromDirectory: EC P-256 and P-384 and RSA keys, each with its own thumbprint and alg pin (draft 5.2, 5.5.1)", async () => {
  const keys = await keysFromDirectory({ keys: [
    { ...P256, alg: "ecdsa-p256-sha256", kid: KID_P256 },
    { ...P384 },
    { ...RSA, alg: "rsa-pss-sha512", use: "sig", exp: 1_800_000_000 },
    { ...RSA, n: N_7638.replace(/^0/, "1"), alg: "rsa-v1_5-sha256" }, // a different 2048-bit modulus
  ] }, DEFAULT_LIMITS, NOW, noWarn);
  assert.deepEqual(keys.slice(0, 3), [
    { keyid: KID_P256, type: "ec-p256", alg: "ecdsa-p256-sha256", publicKeyHex: HEX_P256 },
    { keyid: KID_P384, type: "ec-p384", publicKeyHex: HEX_P384 },
    { keyid: KID_RSA, type: "rsa", alg: "rsa-pss-sha512", publicKeyHex: HEX_RSA, exp: 1_800_000_000 },
  ]);
  assert.equal(keys[3].type, "rsa");
  assert.equal(keys[3].alg, "rsa-v1_5-sha256");
});

test("keysFromDirectory: EC coordinates full size and on the curve; P-521 and X25519 ignored", async () => {
  const warnings: string[] = [];
  const flip = (s: string) => (s[5] === "A" ? s.slice(0, 5) + "B" + s.slice(6) : s.slice(0, 5) + "A" + s.slice(6));
  const keys = await keysFromDirectory({ keys: [
    { ...P256, y: flip(P256.y) },                       // not on the curve
    { ...P256, x: P256.x.slice(0, 42) },                // 31 bytes (RFC 7518 6.2.1.2: full size)
    { ...P384, crv: "P-256" },                          // P-384 coordinates under P-256
    { ...P256, y: undefined },                          // no y
    { kty: "EC", crv: "P-521", x: P256.x, y: P256.y },  // a curve RFC 9421 3.3 has no algorithm for
    { kty: "OKP", crv: "X25519", x: X_KEY },
  ] }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.deepEqual(keys, []);
  assert.deepEqual(warnings, ["skipped P-256 key with a point not on the curve", "skipped P-256 key with malformed x or y",
    "skipped P-256 key with malformed x or y", "skipped P-256 key with malformed x or y"]);
});

test("keysFromDirectory: RSA moduli of 2048 to 16384 bits, minimal, odd; e odd, 3 or more, at most 256 bits", async () => {
  const b64 = (hex: string) => Buffer.from(hex, "hex").toString("base64url");
  const n = (bits: number) => { // an odd modulus of exactly `bits` bits (not a real key: only its shape is checked here)
    const bytes = Math.ceil(bits / 8), top = 1 << ((bits - 1) % 8);
    return top.toString(16).padStart(2, "0") + "00".repeat(bytes - 2) + "01";
  };
  const cases: [string, string, string | null][] = [
    [n(2048), "010001", null], [n(16384), "03", null], [n(2048), "ff".repeat(32), null],
    [n(2047), "010001", "a 2047-bit modulus (2048 to 16384 allowed)"],
    [n(1024), "010001", "a 1024-bit modulus (2048 to 16384 allowed)"],
    [n(16385), "010001", "a 16385-bit modulus (2048 to 16384 allowed)"],
    [n(2048).slice(0, -2) + "02", "010001", "an even modulus"],
    [n(2048), "01", "a public exponent that is even, under 3 or over 256 bits"],
    [n(2048), "010000", "a public exponent that is even, under 3 or over 256 bits"],
    [n(2048), "01" + "00".repeat(31) + "01", "a public exponent that is even, under 3 or over 256 bits"],
    // OpenSSL verifies nothing above 3072 bits with an e over 64 bits; below, it may.
    [n(3072), "01" + "00".repeat(7) + "01", null], [n(4096), "ff".repeat(8), null],
    [n(4096), "01" + "00".repeat(7) + "01", "a public exponent over 64 bits with a 4096-bit modulus (OpenSSL verifies none)"],
    ["00" + n(2048), "010001", "malformed n or e"],      // not minimal (RFC 7518 2)
    [n(2048), "00010001", "malformed n or e"],
  ];
  for (const [nh, eh, want] of cases) {
    const warnings: string[] = [];
    const keys = await keysFromDirectory({ keys: [{ kty: "RSA", n: b64(nh), e: b64(eh) }] }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
    if (want === null) {
      assert.equal(keys.length, 1, `${nh.length * 4} bits, e ${eh}: ${warnings}`);
      assert.equal(keys[0].publicKeyHex, `${nh}:${eh}`);
      assert.deepEqual(parse(format([{ identifier: ID("a.example"), ...keys[0] }], new Date(0)))[0].publicKeyHex, `${nh}:${eh}`,
        "what keysFromDirectory keeps, parse() (and keys.lua) accepts");
    } else {
      assert.deepEqual(keys, [], want);
      assert.deepEqual(warnings, [`skipped RSA key with ${want}`]);
    }
  }
  // Base64url with non-zero pad bits has a second spelling: refused, so the
  // thumbprint over the spelling stays unique to the key.
  const loose = { kty: "RSA", n: RSA.n.slice(0, -1) + "x", e: "AQAB" };
  assert.deepEqual(await keysFromDirectory({ keys: [loose] }, DEFAULT_LIMITS, NOW, () => {}), []);
});

test("keysFromDirectory: a JWK alg names an algorithm for this key type, HTTP or JOSE, and the key is pinned to its HTTP name (RFC 7517 4.4; draft 5.5.1, #136; RFC 9421 3.2 step 6.5)", async () => {
  const pins = async (k: object) => (await keysFromDirectory({ keys: [k] }, DEFAULT_LIMITS, NOW, () => {})).map((e) => e.alg);
  // Exact JOSE twins (RFC 7518 3.3-3.5) are stored under the HTTP Signature Algorithms name.
  assert.deepEqual(await pins({ ...P256, alg: "ES256" }), ["ecdsa-p256-sha256"]);
  assert.deepEqual(await pins({ ...P384, alg: "ES384" }), ["ecdsa-p384-sha384"]);
  assert.deepEqual(await pins({ ...RSA, alg: "PS512" }), ["rsa-pss-sha512"]);
  assert.deepEqual(await pins({ ...RSA, alg: "RS256" }), ["rsa-v1_5-sha256"]);
  assert.deepEqual(await pins({ ...RSA, alg: "rsa-pss-sha512" }), ["rsa-pss-sha512"], "the HTTP name itself, as before");
  const warnings: string[] = [];
  const keys = await keysFromDirectory({ keys: [
    { ...P256, alg: "ecdsa-p384-sha384" }, { ...P256, alg: "ES384" }, { ...P384, alg: "ecdsa-p256-sha256" }, { ...P384, alg: "ES256" },
    { ...RSA, alg: "ed25519" }, { ...RSA, alg: "EdDSA" }, { ...RSA, alg: "ES256" }, { ...RSA, alg: "hmac-sha256" }, { ...RSA, alg: "HS256" },
    { ...RSA, alg: "PS256" }, { ...RSA, alg: "RS512" }, { ...RSA, alg: "ps512" }, { ...RSA, alg: "toString" }, { ...RSA, alg: "constructor" },
  ] }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.deepEqual(keys, [], "another key type's algorithm, a shared secret, a JOSE name with no HTTP twin, a wrong case, or no name at all");
  assert.equal(warnings.length, 14, warnings.join("; "));
  assert.deepEqual(warnings.slice(0, 2), ['skipped P-256 key with alg "ecdsa-p384-sha384"', 'skipped P-256 key with alg "ES384"']);
});

test("keysFromDirectory: RSA and EC keys with private members, the RFC 9421 and JOSE example keys, and a kid that is not the thumbprint are refused", async () => {
  const warnings: string[] = [];
  const keys = await keysFromDirectory({ keys: [
    { ...RSA, d: "AQAB" }, { ...RSA, p: "AQAB" }, { ...P256, d: "AQAB" },
    { kty: "RSA", n: N_9421_PSS, e: "AQAB" },                                   // RFC 9421 B.1.2
    { kty: "RSA", n: N_7638, e: "AQAB" },                                       // RFC 7517 A.2
    { kty: "EC", crv: "P-256", x: "qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA",  // RFC 9421 B.1.3
      y: "Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0" },
    { ...RSA, kid: KID_P256 },
  ] }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.deepEqual(keys, []);
  assert.deepEqual(warnings.slice(0, 6), [
    "rejected a key published with its private part", "rejected a key published with its private part",
    "rejected a key published with its private part", "rejected published test key oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA",
    "rejected published test key NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    "rejected published test key ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI"]);
  assert.match(warnings[6], /rejected key: kid .* is not its thumbprint/);
});

test("keysFromDirectory: a kid that is not the key's thumbprint is rejected (draft 5.5 MUST, 5.5.1)", async () => {
  // The draft's own 5.5.1 example kid is not its key's thumbprint; the
  // normative text wins over the example.
  const warnings: string[] = [];
  const keys = await keysFromDirectory({ keys: [
    { kty: "OKP", crv: "Ed25519", x: X_KEY, kid: "NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw" },
    { kty: "OKP", crv: "Ed25519", x: X_KEY, kid: KID_KEY },
  ] }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.deepEqual(keys.map((k) => k.keyid), [KID_KEY], "only the correctly labelled key is kept");
  assert.match(warnings[0], /rejected key: kid .* is not its thumbprint/);
});

test("keysFromDirectory: millisecond nbf (as Cloudflare's live example directory publishes) is normalized", async () => {
  // Shape observed 2026-09-29 at http-message-signatures-example.research.cloudflare.com,
  // with the fixture key substituted for its (rejected) test key.
  const warnings: string[] = [];
  const keys = await keysFromDirectory(
    { keys: [{ kid: KID_KEY, kty: "OKP", crv: "Ed25519", x: X_KEY, nbf: 1743465600000 }], purpose: "rag" },
    DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.equal(keys[0].nbf, 1743465600);
  assert.match(warnings[0], /milliseconds/);
  const expired = await keysFromDirectory(
    { keys: [{ kty: "OKP", crv: "Ed25519", x: X_KEY, exp: (NOW - 1) * 1000 }] }, DEFAULT_LIMITS, NOW, () => {});
  assert.deepEqual(expired, [], "millisecond exp in the past is expired");
});

test("keysFromDirectory: not a JWK Set, or too many keys, rejects the whole directory", async () => {
  await assert.rejects(keysFromDirectory({}, DEFAULT_LIMITS, NOW, noWarn), /no keys array/);
  await assert.rejects(keysFromDirectory([], DEFAULT_LIMITS, NOW, noWarn), /no keys array/);
  const many = { keys: Array.from({ length: 33 }, () => ({ kty: "OKP", crv: "Ed25519", x: X_KEY })) };
  await assert.rejects(keysFromDirectory(many, DEFAULT_LIMITS, NOW, noWarn), /exceeds maxKeys/);
});

// Every name resolves to a public address unless a test says otherwise.
const publicDns = async () => ["93.184.215.14"];

// A fake fetch that records the request and answers from a table.
function fakeFetch(routes: Record<string, () => Response | Promise<Response>>, seen: RequestInit[] = []): FetchLike {
  return async (url, init) => {
    seen.push(init);
    const route = routes[url];
    if (!route) throw new Error(`ENOTFOUND ${url}`);
    return route();
  };
}
const dir = (body: unknown, type = MEDIA_TYPE) =>
  () => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": type } });

test("fetchDirectory: 200 + media type only, redirects not followed, size and time bounded", async () => {
  const seen: RequestInit[] = [];
  const ok = await fetchDirectory(ID("a.example"), DEFAULT_LIMITS,
    fakeFetch({ [ID("a.example")]: dir({ keys: [] }, `${MEDIA_TYPE}; charset=utf-8`) }, seen));
  assert.deepEqual(ok, { keys: [] });
  assert.equal(seen[0].redirect, "manual", "redirects are never followed");
  assert.ok(seen[0].signal instanceof AbortSignal, "every fetch has a timeout signal");

  const f = (r: () => Response) => fetchDirectory(ID("a.example"), DEFAULT_LIMITS, fakeFetch({ [ID("a.example")]: r }));
  await assert.rejects(f(() => new Response(null, { status: 301, headers: { location: "https://evil.example/" } })), /HTTP 301/);
  await assert.rejects(f(() => new Response("{}", { status: 404, headers: { "content-type": MEDIA_TYPE } })), /HTTP 404/);
  await assert.rejects(f(dir({ keys: [] }, "application/json")), /content-type/);
  await assert.rejects(f(() => new Response("x".repeat(DEFAULT_LIMITS.maxBytes + 1),
    { status: 200, headers: { "content-type": MEDIA_TYPE } })), /exceeds maxBytes/);
  await assert.rejects(f(() => new Response("{not json", { status: 200, headers: { "content-type": MEDIA_TYPE } })));

  const hang: FetchLike = (_url, init) => new Promise((_, reject) =>
    init.signal?.addEventListener("abort", () => reject(new Error("aborted by timeout"))));
  await assert.rejects(fetchDirectory(ID("a.example"), { ...DEFAULT_LIMITS, timeoutMs: 30 }, hang), /timeout/);
});

test("sync: last-good kept on failure, evicted when a resolved directory drops the key, unlisted origins dropped", async () => {
  const prev: StoreEntry[] = [
    { identifier: ID("down.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY },
    { identifier: ID("rotated.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY },
    { identifier: ID("removed.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY },
  ];
  const seen: RequestInit[] = [];
  const r = await sync(
    ["https://down.example", "https://rotated.example", "https://new.example",
     "https://new.example:443/", "http://plain.example"],
    prev,
    { now: NOW, resolve: publicDns, fetchImpl: fakeFetch({
      [ID("down.example")]: () => new Response("", { status: 503 }),
      [ID("rotated.example")]: dir({ keys: [] }),
      [ID("new.example")]: dir({ keys: [{ kty: "OKP", crv: "Ed25519", x: X_KEY }] }),
    }, seen) },
  );
  assert.deepEqual(r.entries.map((e) => e.identifier), [ID("down.example"), ID("new.example")]);
  assert.deepEqual(r.failures.map((f) => f.origin).sort(), ["http://plain.example", "https://down.example"]);
  assert.equal(seen.length, 3, "two spellings of new.example fetched once");
});

test("format() emits the exact bytes of the shared fixture that keys.lua parses", () => {
  const text = format([
    { identifier: ID("agent.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY, nbf: 1712793600, exp: 1715385600,
      proof: "valid", proofExpires: 1715000000 },
    { identifier: ID("agent.example"), keyid: KID_P256, type: "ec-p256", alg: "ecdsa-p256-sha256", publicKeyHex: HEX_P256 },
    { identifier: ID("b.example:8443"), keyid: KID_9421, type: "ed25519", alg: "ed25519",
      publicKeyHex: "26b40b8f93fff3d897112f7ebc582b232dbd72517d082fe83cfb30ddce43d1bb" },
    { identifier: ID("b.example:8443"), keyid: KID_RSA, type: "rsa", alg: "rsa-pss-sha512", publicKeyHex: HEX_RSA, exp: 1_800_000_000,
      proof: "invalid" },
    { identifier: ID("c.example"), keyid: KID_P384, type: "ec-p384", publicKeyHex: HEX_P384, proof: "valid", proofExpires: 1716000000 },
    { identifier: "https://[2001:db8::1]:8443/jwks.json", keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY, proof: "invalid" },
  ], new Date("2026-01-01T00:00:00.000Z"));
  assert.equal(text, readFileSync(FIXTURE, "utf8"));
});

test("parse() round-trips format() and rejects what keys.lua rejects", () => {
  const entries = parse(readFileSync(FIXTURE, "utf8"));
  assert.equal(format(entries, new Date("2026-01-01T00:00:00.000Z")), readFileSync(FIXTURE, "utf8"));
  const row = (type: string, alg: string, hex: string, id = ID("a.example"), proof = "none\t-") =>
    `${id}\t${KID_KEY}\t${type}\t${alg}\t${hex}\t-\t-\t${proof}`;
  const v2 = (type: string, alg: string, hex: string, id?: string, proof?: string) => `# wba-keys v2\n${row(type, alg, hex, id, proof)}`;
  const line = row("ed25519", "-", HEX_KEY);
  const v1line = `${ID("a.example")}\t${KID_KEY}\t${HEX_KEY}\t-\t-`;
  const n = HEX_RSA.split(":")[0];
  for (const bad of [
    v1line, line, `# wba-keys v3\n${line}`, `# wba-keys v2\n${v1line}`, `# wba-keys v1\n${line}`, `# wba-keys v1\n${v1line}\n${v1line}`,
    `# wba-keys v1\n${v1line.replace(HEX_KEY, HEX_KEY.toUpperCase())}`,
    `# wba-keys v1\n${v1line.replace("https://a.example", "https://a.example:443")}`,
    `# wba-keys v2\n${line}\n${line}`, // duplicate
    v2("ed25519", "-", HEX_KEY.toUpperCase()),
    v2("ed25519", "-", HEX_KEY, "https://a.example:443/.well-known/http-message-signatures-directory"),
    v2("ed25519", "-", HEX_KEY, "https://a.example/jwks.json?v=1"), v2("ed25519", "-", HEX_KEY, "https://[2001:db8:0::1]/k"),
    v2("ed25519", "-", HEX_KEY, undefined, "yes\t-"), v2("ed25519", "-", HEX_KEY, undefined, "valid\t-"),
    v2("ed25519", "-", HEX_KEY, undefined, "none\t5"), v2("ed25519", "-", HEX_KEY, undefined, "invalid\t5"),
    v2("x25519", "-", HEX_KEY), v2("ed25519", "EdDSA", HEX_KEY), v2("ed25519", "hmac-sha256", HEX_KEY),
    v2("ec-p256", "ecdsa-p384-sha384", HEX_P256), v2("rsa", "ed25519", HEX_RSA), v2("ec-p384", "-", HEX_P256),
    v2("ec-p256", "-", "02" + HEX_P256.slice(2, 66)), v2("rsa", "-", "00" + HEX_RSA), v2("rsa", "-", HEX_RSA.slice(1)),
    v2("rsa", "-", n.slice(0, -1) + "e:010001"), v2("rsa", "-", `${n}:01`), v2("rsa", "-", `${n}:010000`),
    v2("rsa", "-", `${n}:0003`), v2("rsa", "-", `${n}:01${"00".repeat(31)}01`), v2("rsa", "-", `8${"0".repeat(4096)}1:010001`),
    v2("rsa", "-", n), v2("rsa", "-", `4${"0".repeat(510)}1:010001`), // 2047 bits
    v2("rsa", "-", `8${"0".repeat(1022)}1:01${"00".repeat(7)}01`), // 4096 bits, a 65-bit e: OpenSSL verifies none
  ]) assert.throws(() => parse(bad), Error, bad.slice(0, 120));
  assert.equal(parse(v2("rsa", "-", `8${"0".repeat(766)}1:01${"00".repeat(7)}01`)).length, 1, "3072 bits, a 65-bit e");
  assert.equal(parse(v2("rsa", "-", `8${"0".repeat(4094)}1:03`)).length, 1, "16384 bits, e = 3");
  assert.deepEqual(parse(v2("ec-p256", "ecdsa-p256-sha256", HEX_P256, "https://[2001:db8::1]/k", "valid\t9")), [{
    identifier: "https://[2001:db8::1]/k", keyid: KID_KEY, type: "ec-p256", alg: "ecdsa-p256-sha256", publicKeyHex: HEX_P256,
    proof: "valid", proofExpires: 9 }], "a jwks_uri identifier, an alg pin and a valid proof");
});

test("parse() reads a version 1 store as Ed25519 keys with no alg and proof none (format() writes version 2)", () => {
  const line = `${ID("a.example")}\t${KID_KEY}\t${HEX_KEY}\t-\t5`;
  assert.deepEqual(parse(`# wba-keys v1\n${line}\n`), [{ identifier: ID("a.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY, exp: 5 }]);
  assert.match(format(parse(`# wba-keys v1\n${line}\n`), new Date(0)), /^# wba-keys v2\n.*\ted25519\t-\t[0-9a-f]{64}\t-\t5\tnone\t-\n$/s);
});

test("parse() accepts exactly what keys.lua accepts at line ends (CRLF, final bare CR)", () => {
  const line = `${ID("a.example")}\t${KID_KEY}\ted25519\t-\t${HEX_KEY}\t-\t-\tnone\t-`;
  assert.equal(parse(`# wba-keys v2\r\n${line}\r\n`).length, 1);
  assert.equal(parse(`# wba-keys v2\n${line}\r`).length, 1);
});

test("keysFromDirectory: only crv Ed25519 (an X25519 key with a 43-char x is skipped)", async () => {
  assert.deepEqual(await keysFromDirectory({ keys: [{ kty: "OKP", crv: "X25519", x: X_KEY }] }, DEFAULT_LIMITS, NOW, noWarn), []);
});

test("warnings never carry raw bytes from a directory", async () => {
  const warnings: string[] = [];
  await keysFromDirectory({ keys: [{ kty: "OKP", crv: "Ed25519", x: X_KEY, kid: "x\n\u001b[31mforged" }] },
    DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.ok(!/[\n\u001b]/.test(warnings[0]), warnings[0]); // eslint-disable-line no-control-regex -- asserts no control character reaches the output
});

test("writeAtomic refuses to follow a planted temp-file symlink", () => {
  const d = mkdtempSync(join(tmpdir(), "wba-keysync-"));
  try {
    const p = join(d, "wba-keys.tsv");
    const victim = join(d, "victim");
    writeAtomic(victim, "untouched\n");
    symlinkSync(victim, `${p}.tmp-${process.pid}`);
    writeAtomic(p, "new\n");
    assert.equal(readFileSync(p, "utf8"), "new\n");
    assert.equal(readFileSync(victim, "utf8"), "untouched\n", "symlink target not overwritten");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("writeAtomic leaves the new file and no temp file behind", () => {
  const d = mkdtempSync(join(tmpdir(), "wba-keysync-"));
  try {
    const p = join(d, "wba-keys.tsv");
    writeAtomic(p, "old\n");
    writeAtomic(p, "new\n");
    assert.equal(readFileSync(p, "utf8"), "new\n");
    assert.deepEqual(readdirSync(d), ["wba-keys.tsv"]);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  assert.equal(existsSync(d), false);
});

test("keysFromDirectory: keys whose private half is public are rejected (draft 6.8)", async () => {
  const warnings: string[] = [];
  const rfc8032 = ["11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw",
    "_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU", "J4EX_BRMcjQPZ9DyMW6Dhs7_vyskKMnFH-98WX8dQm4",
    "7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8"]; // RFC 8032 7.1: TEST 1, 2, 3, 1024, SHA(abc)
  const keys = await keysFromDirectory({ keys: [
    ...rfc8032.map((x) => ({ kty: "OKP", crv: "Ed25519", x })),
    { kty: "OKP", crv: "Ed25519", x: X_KEY, d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A" }, // published with d
  ] }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.deepEqual(keys, []);
  assert.equal(warnings.filter((w) => w.startsWith("rejected published test key")).length, 5, warnings.join("; "));
  assert.equal(warnings.filter((w) => w === "rejected a key published with its private part").length, 1);
});

test("keysFromDirectory: an Ed25519 key's alg is absent, ed25519, or JOSE's EdDSA (RFC 8037 3.1) or Ed25519 (RFC 9864 2.2), all pinned to ed25519", async () => {
  for (const alg of ["ed25519", "Ed25519", "EdDSA"]) {
    const warnings: string[] = [];
    const keys = await keysFromDirectory({ keys: [{ kty: "OKP", crv: "Ed25519", x: X_KEY, alg }] }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
    assert.deepEqual([keys, warnings], [[{ keyid: KID_KEY, type: "ed25519", alg: "ed25519", publicKeyHex: HEX_KEY }], []], alg);
  }
  const warnings: string[] = [];
  const keys = await keysFromDirectory({ keys: ["RS256", "none", "eddsa", "Ed448", 7].map(
    (alg) => ({ kty: "OKP", crv: "Ed25519", x: X_KEY, alg })) }, DEFAULT_LIMITS, NOW, (w) => warnings.push(w));
  assert.deepEqual(keys, []);
  assert.deepEqual(warnings, ['skipped Ed25519 key with alg "RS256"', 'skipped Ed25519 key with alg "none"',
    'skipped Ed25519 key with alg "eddsa"', 'skipped Ed25519 key with alg "Ed448"', "skipped Ed25519 key with alg 7"]);
});

test("freshnessLifetime follows RFC 9111 4.2 for a private cache", () => {
  const h = (o: Record<string, string>) => new Headers(o);
  const T = 1_800_000_000, D = new Date(T * 1000).toUTCString();
  assert.equal(freshnessLifetime(h({ "cache-control": "max-age=300" }), T), 300);
  assert.equal(freshnessLifetime(h({ "cache-control": "public, max-age=300", age: "100" }), T), 200, "Age counts");
  assert.equal(freshnessLifetime(h({ "cache-control": "s-maxage=900" }), T), 0, "s-maxage is for shared caches");
  assert.equal(freshnessLifetime(h({ "cache-control": "max-age=300, no-cache" }), T), 0);
  assert.equal(freshnessLifetime(h({ "cache-control": "no-store" }), T), 0);
  assert.equal(freshnessLifetime(h({ date: D, expires: new Date((T + 600) * 1000).toUTCString() }), T), 600);
  assert.equal(freshnessLifetime(h({ date: D, expires: "0" }), T), 0, "an invalid Expires is in the past");
  assert.equal(freshnessLifetime(h({ date: D, "last-modified": new Date((T - 10000) * 1000).toUTCString() }), T), 1000,
    "the 10% heuristic");
  assert.equal(freshnessLifetime(h({}), T), 0);
  assert.equal(freshnessLifetime(h({ "cache-control": "max-age=31536000" }), T), MAX_FRESHNESS);
});

test("forbiddenAddress: private, loopback, link-local and their mapped forms (draft 6.7)", () => {
  for (const ip of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "169.254.169.254",
    "0.0.0.0", "100.64.0.1", "::1", "::", "fe80::1", "febf::1", "fc00::1", "fd12:3456::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:169.254.169.254", "::127.0.0.1", "not-an-ip",
    "fec0::1", "224.0.0.1", "255.255.255.255", "ff02::1", "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::1", "2002:7f00:1::1", "2002:a9fe:a9fe::1", "::ffff:0:7f00:1", "::ffff:0:a00:1"]) {
    assert.equal(forbiddenAddress(ip), true, ip);
  }
  for (const ip of ["93.184.215.14", "172.32.0.1", "192.169.0.1", "100.128.0.1", "2606:4700::6810:84e5",
    "::ffff:93.184.215.14", "64:ff9b::5db8:d70e", "2002:5db8:d70e::1", "::ffff:0:5db8:d70e"]) {
    assert.equal(forbiddenAddress(ip), false, ip);
  }
});

test("sync: a name resolving to a private address is never fetched, and keeps its last-good keys", async () => {
  const seen: RequestInit[] = [];
  const prev: StoreEntry[] = [{ identifier: ID("a.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY }];
  const r = await sync(["https://a.example", "https://localhost"], prev, {
    now: NOW, resolve: async (host) => (host === "localhost" ? ["127.0.0.1"] : ["93.184.215.14", "10.0.0.5"]),
    fetchImpl: fakeFetch({}, seen) });
  assert.equal(seen.length, 0, "no fetch");
  assert.deepEqual(r.entries.map((e) => e.identifier), [ID("a.example")], "last-good kept (draft 6.10)");
  assert.match(r.failures.find((f) => f.origin === "https://a.example")!.error, /10\.0\.0\.5, a private/);
  assert.match(r.failures.find((f) => f.origin === "https://localhost")!.error, /127\.0\.0\.1/);
});

const SRC_A = `directory ${ID("a.example")}`; // the cache records how a directory was resolved

test("sync: fresh directories are not fetched; stale ones are revalidated; failures back off (draft 5.5.2, C.4, C.5)", async () => {
  const held: StoreEntry[] = [{ identifier: ID("a.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY }];
  const key = { kty: "OKP", crv: "Ed25519", x: X_KEY };
  // 1. First fetch: 200 with max-age and an ETag.
  const seen: RequestInit[] = [];
  let r = await sync(["https://a.example"], [], { now: NOW, resolve: publicDns, fetchImpl: fakeFetch({
    [ID("a.example")]: () => new Response(JSON.stringify({ keys: [key] }),
      { status: 200, headers: { "content-type": MEDIA_TYPE, "cache-control": "max-age=600", etag: '"v1"' } }),
  }, seen) });
  assert.deepEqual(r.cache[ID("a.example")], { freshUntil: NOW + 600, keys: 1, source: SRC_A, etag: '"v1"' });
  const cache: Cache = r.cache;
  // 2. Still fresh: no request at all.
  r = await sync(["https://a.example"], held, { now: NOW + 599, cache, resolve: publicDns, fetchImpl: fakeFetch({}, seen) });
  assert.equal(seen.length, 1, "no request while fresh");
  assert.deepEqual(r.fresh, ["https://a.example"]);
  assert.equal(r.entries.length, 1);
  // 3. Stale: revalidated with If-None-Match; 304 keeps the keys and renews freshness.
  r = await sync(["https://a.example"], held, { now: NOW + 600, cache, resolve: publicDns, fetchImpl: fakeFetch({
    [ID("a.example")]: () => new Response(null, { status: 304, headers: { "cache-control": "max-age=60" } }),
  }, seen) });
  assert.equal((seen[1].headers as Record<string, string>)["if-none-match"], '"v1"');
  assert.deepEqual(r.entries.map((e) => e.keyid), [KID_KEY]);
  assert.deepEqual(r.cache[ID("a.example")], { freshUntil: NOW + 660, keys: 1, source: SRC_A, etag: '"v1"' });
  // 4. A store that no longer matches the cache is not trusted: plain refetch, no validators.
  r = await sync(["https://a.example"], [], { now: NOW + 10, cache, resolve: publicDns, fetchImpl: fakeFetch({
    [ID("a.example")]: () => new Response(JSON.stringify({ keys: [] }), { status: 200, headers: { "content-type": MEDIA_TYPE } }),
  }, seen) });
  assert.equal((seen[2].headers as Record<string, string>)["if-none-match"], undefined);
  assert.deepEqual(r.entries, [], "the directory now lists no key: removed (draft 6.10, evidence)");
  // 5. Failure: last-good kept, back off; Retry-After wins.
  r = await sync(["https://a.example"], held, { now: NOW + 700, cache, resolve: publicDns, fetchImpl: fakeFetch({
    [ID("a.example")]: () => new Response("", { status: 503, headers: { "retry-after": "120" } }),
  }, seen) });
  assert.equal(r.entries.length, 1, "an outage evicts nothing (draft 6.10)");
  assert.deepEqual(r.cache[ID("a.example")], { freshUntil: 0, keys: 1, failures: 1, retryAt: NOW + 820, source: SRC_A, etag: '"v1"' });
  const before = seen.length;
  r = await sync(["https://a.example"], held, { now: NOW + 800, cache: r.cache, resolve: publicDns, fetchImpl: fakeFetch({}, seen) });
  assert.equal(seen.length, before, "no retry before retryAt");
  assert.equal(r.failures.length, 1);
  r = await sync(["https://a.example"], held, { now: NOW + 900, cache: { [ID("a.example")]: { freshUntil: 0, keys: 1, failures: 3, retryAt: 0 } },
    resolve: publicDns, fetchImpl: fakeFetch({ [ID("a.example")]: () => new Response("", { status: 500 }) }, seen) });
  assert.equal(r.cache[ID("a.example")].retryAt, NOW + 900 + 240, "30 s doubling: the 4th failure waits 240 s");
});

test("sync: an origin that resolves to no usable key is reported (cli.ts exits 2)", async () => {
  const r = await sync(["https://jose.example", "https://good.example"], [], { now: NOW, resolve: publicDns,
    fetchImpl: fakeFetch({
      // Shaped like a live directory seen 2026-10-02 (agent.bot.goog): JOSE alg, now accepted,
      // and a short kid on every key, which the well-known URI forbids (draft 5.5 MUST).
      [ID("jose.example")]: dir({ keys: [{ kty: "OKP", crv: "Ed25519", x: X_KEY, alg: "EdDSA", kid: "mhxuPw" }] }),
      [ID("good.example")]: dir({ keys: [{ kty: "OKP", crv: "Ed25519", x: X_KEY }] }),
    }) });
  assert.deepEqual(r.empty, ["https://jose.example"]);
  assert.deepEqual(r.failures, [], "it resolved: an empty directory is not a fetch failure");
  assert.deepEqual(r.entries.map((e) => e.identifier), [ID("good.example")]);
});

test("historyLines: keys added and removed by directory and keyid; unchanged keys silent", () => {
  const a: StoreEntry = { identifier: ID("a.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY };
  const b: StoreEntry = { identifier: ID("b.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY };
  const at = new Date(NOW * 1000);
  assert.deepEqual(historyLines([a], [a, b], at), [`2023-11-14T22:13:20.000Z\tadded\t${ID("b.example")}\t${KID_KEY}`]);
  assert.deepEqual(historyLines([a, b], [b], at), [`2023-11-14T22:13:20.000Z\tremoved\t${ID("a.example")}\t${KID_KEY}`]);
  assert.deepEqual(historyLines([a], [a], at), []);
});

test("appendHistory: header once, appends, never follows a symlink", () => {
  const d = mkdtempSync(join(tmpdir(), "wba-history-"));
  try {
    const p = join(d, "keys.tsv.history");
    appendHistory(p, ["l1"]);
    appendHistory(p, []);
    appendHistory(p, ["l2", "l3"]);
    assert.equal(readFileSync(p, "utf8"), `${HISTORY_HEADER}\nl1\nl2\nl3\n`);
    const target = join(d, "elsewhere");
    const link = join(d, "linked.history");
    symlinkSync(target, link);
    assert.throws(() => appendHistory(link, ["x"]));
    assert.equal(existsSync(target), false, "the symlink target was never created");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// --- Agent types (draft 5.5), the fetch guard (6.7), CIMD, Appendix B ----------

/** A fake fetch that also records every URL requested, in order. */
function recFetch(routes: Record<string, () => Response | Promise<Response>>, urls: string[], seen: RequestInit[] = []): FetchLike {
  return async (url, init) => {
    urls.push(url);
    seen.push(init);
    const route = routes[url];
    if (!route) throw new Error(`ENOTFOUND ${url}`);
    return route();
  };
}
const json = (body: unknown, headers: Record<string, string> = {}, type = "application/json") =>
  () => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": type, ...headers } });
const OKP = { kty: "OKP", crv: "Ed25519", x: X_KEY };

test("parseAgent: agents.txt lines, a type per line (draft 5.5), CIMD 3's URL rules", () => {
  assert.deepEqual(parseAgent("https://a.example"), { line: "https://a.example", type: "directory", url: ID("a.example"), id: ID("a.example") });
  assert.deepEqual(parseAgent("https://a.example type=directory"),
    { line: "https://a.example type=directory", type: "directory", url: ID("a.example"), id: ID("a.example") });
  assert.deepEqual(parseAgent("https://a.example/jwks.json?v=2 type=jwks_uri"),
    { line: "https://a.example/jwks.json?v=2 type=jwks_uri", type: "jwks_uri", url: "https://a.example/jwks.json?v=2", id: "https://a.example/jwks.json" });
  assert.deepEqual(parseAgent("https://a.example/card type=cimd"),
    { line: "https://a.example/card type=cimd", type: "cimd", url: "https://a.example/card", id: "https://a.example/card" });
  for (const bad of ["https://a.example type=x509", "https://a.example/jwks.json type=jwks_uri extra", "https://a.example/jwks.json",
    "http://a.example/k type=jwks_uri", "https://u@a.example/k type=jwks_uri", "https://a.example/a%zz type=jwks_uri",
    "https://a.example type=cimd", "https://a.example/a/../card type=cimd", "https://a.example/%2E%2e/card type=cimd",
    "https://a.example/card#x type=cimd"]) {
    assert.equal(typeof parseAgent(bad), "string", bad);
  }
});

test("sync: type=jwks_uri is fetched as written and identified without its query; its kid is a label (draft 5.5)", async () => {
  const urls: string[] = [], seen: RequestInit[] = [];
  const r = await sync(["https://a.example/jwks.json?v=2 type=jwks_uri", "https://a.example/jwks.json?v=3 type=jwks_uri"], [], {
    now: NOW, resolve: publicDns, fetchImpl: recFetch({
      "https://a.example/jwks.json?v=2": json({ keys: [{ ...OKP, kid: "2026-10-key-1", use: "sig" }] }, {}, "application/jwk-set+json"),
    }, urls, seen) });
  assert.deepEqual(urls, ["https://a.example/jwks.json?v=2"], "one fetch per identifier, the first line's URL as written");
  assert.deepEqual(r.entries, [{ identifier: "https://a.example/jwks.json", keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY }],
    "kept under its computed thumbprint, whatever its kid; no proof (Appendix B is for directories)");
  assert.deepEqual(r.warnings, ["https://a.example/jwks.json?v=3 type=jwks_uri: the same identifier as "
    + "https://a.example/jwks.json?v=2 type=jwks_uri (draft 5.5); only that line is fetched"]);
  assert.deepEqual(r.proofs, []);
  const h = seen[0].headers as Record<string, string>;
  assert.equal(h.accept, "application/jwk-set+json, application/json");
  assert.equal(h["accept-encoding"], "identity");
  assert.equal(seen[0].redirect, "manual");

  const one = (route: () => Response, line = "https://b.example/k type=jwks_uri", url = "https://b.example/k") =>
    sync([line], [], { now: NOW, resolve: publicDns, fetchImpl: fakeFetch({ [url]: route }) });
  // Off the well-known URI the draft sets no media type (5.5, 5.5.1): any is read, and the body
  // must still be a JWK Set.
  for (const type of ["text/plain", "application/octet-stream", ""]) {
    const r = await one(() => new Response(JSON.stringify({ keys: [OKP] }), { status: 200, headers: type ? { "content-type": type } : {} }));
    assert.equal(r.failures.length, 0, `served as "${type}"`);
    assert.equal(r.entries.length, 1, `served as "${type}"`);
  }
  assert.match((await one(() => new Response("<html>", { status: 200, headers: { "content-type": "text/html" } }))).failures[0].error,
    /JSON/, "a body that is not JSON still fails");
  assert.match((await one(() => new Response(null, { status: 302, headers: { location: "https://b.example/k2" } }))).failures[0].error,
    /HTTP 302/, "5.5: each fetch MUST be 200, no redirect followed");
  // At the well-known URI the directory's rules hold whatever the type: its media type, and kid = thumbprint (5.5, 5.5.1).
  const wk = await one(dir({ keys: [{ ...OKP, kid: "label" }] }), `${ID("b.example")} type=jwks_uri`, ID("b.example"));
  assert.deepEqual([wk.entries, wk.empty], [[], [`${ID("b.example")} type=jwks_uri`]]);
  assert.match(wk.warnings[0], /is not its thumbprint/);
  assert.match((await one(json({ keys: [OKP] }), `${ID("b.example")} type=jwks_uri`, ID("b.example"))).failures[0].error,
    /expected application\/http-message-signatures-directory\+json/);
});

test("sync: every fetch is guarded (draft 6.7): IP literals checked as written, never resolved; names resolved first", async () => {
  const urls: string[] = [], resolved: string[] = [];
  const r = await sync(["https://[::1]", "https://[fe80::1]:8443", "https://[::ffff:10.0.0.1]", "https://[fd12::1]/k type=jwks_uri",
    "https://0x7f.1", "https://169.254.169.254/latest type=jwks_uri", "https://internal.example/k type=jwks_uri"], [], {
    now: NOW, resolve: async (h) => { resolved.push(h); return h === "internal.example" ? ["10.1.2.3"] : ["93.184.215.14"]; },
    fetchImpl: recFetch({}, urls) });
  assert.deepEqual(urls, [], "nothing fetched");
  assert.deepEqual(resolved, ["internal.example"], "a literal never reaches DNS");
  assert.equal(r.failures.length, 7);
  for (const f of r.failures) assert.match(f.error, /a private, loopback or link-local address \(draft 6\.7\)/, f.origin);
  // A public IPv6 literal: one canonical identifier (RFC 5952), fetched without DNS.
  const v6 = "https://[2001:db8::1]:8443" + WELL_KNOWN;
  const ok = await sync(["https://[2001:0db8:0:0::1]:8443"], [], { now: NOW, resolve: async () => assert.fail("resolved a literal"),
    fetchImpl: recFetch({ [v6]: dir({ keys: [OKP] }) }, urls) });
  assert.deepEqual([urls, ok.entries.map((e) => e.identifier)], [[v6], [v6]]);
});

test("sync: type=cimd: client_id is the URL fetched, then jwks or jwks_uri under the same rules (draft 5.5; CIMD 4, 4.1)", async () => {
  const CARD = "https://a.example/card", HOP = "https://keys.example/jwks.json";
  const key = { ...OKP, kid: "client-key-1" };
  let r = await sync([`${CARD} type=cimd`], [], { now: NOW, resolve: publicDns,
    fetchImpl: fakeFetch({ [CARD]: json({ client_id: CARD, jwks: { keys: [key] } }) }) });
  assert.deepEqual(r.entries, [{ identifier: CARD, keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY }], "inline jwks; kid a label");
  const urls: string[] = [], resolved: string[] = [];
  r = await sync([`${CARD} type=cimd`], [], { now: NOW, resolve: async (h) => { resolved.push(h); return ["93.184.215.14"]; },
    fetchImpl: recFetch({
      [CARD]: json({ client_id: CARD, jwks_uri: HOP, token_endpoint_auth_method: "private_key_jwt" }, { "cache-control": "max-age=600" }),
      [HOP]: json({ keys: [key] }, { "cache-control": "max-age=60" }, "application/jwk-set+json"),
    }, urls) });
  assert.deepEqual(urls, [CARD, HOP]);
  assert.deepEqual(resolved, ["a.example", "keys.example"], "the jwks_uri hop is guarded too");
  assert.deepEqual(r.entries.map((e) => e.identifier), [CARD], "identified by the CIMD URL, not the hop");
  assert.equal(r.cache[CARD].freshUntil, NOW + 60, "fresh only while both responses are");
  assert.equal(r.cache[CARD].etag, undefined, "never revalidated conditionally: two responses");

  const held: StoreEntry[] = [{ identifier: CARD, keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY }];
  for (const [doc, why] of [
    [{ client_id: "https://a.example/other", jwks: { keys: [key] } }, /CIMD 4: client_id/],
    [{ jwks: { keys: [key] } }, /CIMD 4: client_id null/],
    [{ client_id: CARD, jwks: { keys: [key] }, jwks_uri: HOP }, /MUST NOT both be present/],
    [{ client_id: CARD }, /no jwks or jwks_uri/],
    [{ client_id: CARD, client_secret: "s3cret", jwks: { keys: [key] } }, /CIMD 4\.1/],
    [{ client_id: CARD, token_endpoint_auth_method: "client_secret_basic", jwks: { keys: [key] } }, /CIMD 4\.1/],
    [{ client_id: CARD, jwks_uri: "http://keys.example/jwks.json" }, /not an https URL/],
    [{ client_id: CARD, jwks_uri: "https://keys.internal/jwks.json" }, /resolves to 192\.168\.1\.9/],
    [{ client_id: CARD, jwks_uri: "https://[::1]/jwks.json" }, /\[::1\] is a private/],
    [{ client_id: CARD, jwks_uri: "https://keys.example/moved" }, /HTTP 301/],
    [{ client_id: CARD, jwks: { keys: "none" } }, /not a JWK Set/],
    [[CARD], /not a JSON object/],
  ] as [unknown, RegExp][]) {
    const u: string[] = [];
    const r2 = await sync([`${CARD} type=cimd`], held, { now: NOW, resolve: async (h) => (h === "keys.internal" ? ["192.168.1.9"] : ["93.184.215.14"]),
      fetchImpl: recFetch({ [CARD]: json(doc),
        "https://keys.example/moved": () => new Response(null, { status: 301, headers: { location: HOP } }), [HOP]: json({ keys: [key] }) }, u) });
    assert.match(r2.failures[0]?.error ?? "(no failure)", why, JSON.stringify(doc));
    assert.deepEqual(r2.entries, held, "a CIMD that fails to resolve evicts nothing (draft 6.10)");
    assert.ok(!u.includes(HOP), "no redirect followed, nothing fetched past a refusal");
  }
});

/** A directory response signed by a fresh key over a hand-written Appendix B base. */
async function signedDirectory(host: string, created: number, expires: number) {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const x = btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const kid = await thumbprint(okp(x));
  const body = JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", kid, x, use: "sig" }] });
  const digest = "sha-256=:" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))))) + ":";
  const inner = `("@authority";req "content-digest");created=${created};expires=${expires};keyid="${kid}";tag="http-message-signatures-directory"`;
  const base = `"@authority";req: ${host}\n"content-digest": ${digest}\n"@signature-params": ${inner}`;
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, new TextEncoder().encode(base)))));
  const headers = { "content-type": MEDIA_TYPE, "content-digest": digest, "signature-input": `binding=${inner}`, signature: `binding=:${sig}:`,
    "cache-control": "max-age=86400", etag: '"d1"' };
  return { kid, response: () => new Response(body, { status: 200, headers }) };
}

test("sync: Appendix B proofs are recorded per key, refreshed before they expire, and never renewed by a 304", async () => {
  const d = await signedDirectory("a.example", NOW - 10, NOW + 3600);
  const seen: RequestInit[] = [];
  let r = await sync(["https://a.example"], [], { now: NOW, resolve: publicDns, fetchImpl: fakeFetch({ [ID("a.example")]: d.response }, seen) });
  assert.deepEqual(r.entries.map((e) => [e.keyid, e.proof, e.proofExpires]), [[d.kid, "valid", NOW + 3600]]);
  assert.deepEqual(r.proofs, [{ origin: "https://a.example", identifier: ID("a.example"), summary: "valid", valid: 1, keys: 1, notes: [] }]);
  assert.equal(r.cache[ID("a.example")].freshUntil, NOW + 3600, "max-age is a day; the proof expires in an hour");
  assert.match(format(r.entries, new Date(0)), new RegExp(`\\tvalid\\t${NOW + 3600}\\n$`));
  // Stale at the proof's expiry: fetched again, unconditionally (a 304 carries no new proof).
  r = await sync(["https://a.example"], r.entries, { now: NOW + 3600, cache: r.cache, resolve: publicDns,
    fetchImpl: fakeFetch({ [ID("a.example")]: d.response }, seen) });
  assert.equal(seen.length, 2);
  assert.equal((seen[1].headers as Record<string, string>)["if-none-match"], undefined);
  assert.equal(r.entries[0].proof, "invalid", "that response's own signature has now expired (5.5.3)");
  // The same signed response as a jwks_uri: Appendix B is not evaluated (it applies to the directory type).
  r = await sync([`${ID("a.example")} type=jwks_uri`], [], { now: NOW, resolve: publicDns, fetchImpl: fakeFetch({ [ID("a.example")]: d.response }) });
  assert.deepEqual([r.entries[0].proof, r.proofs], [undefined, []]);
  // Judged when the response arrives: a created signed during a slow fetch is
  // not "in the future" (100 s, beyond the clock skew, so only the receipt time
  // can make it valid).
  const late = await signedDirectory("a.example", NOW + 100, NOW + 600);
  r = await sync(["https://a.example"], [], { now: NOW, clock: () => NOW + 100, resolve: publicDns,
    fetchImpl: fakeFetch({ [ID("a.example")]: late.response }) });
  assert.equal(r.entries[0].proof, "valid");
  r = await sync(["https://a.example"], [], { now: NOW, resolve: publicDns, fetchImpl: fakeFetch({ [ID("a.example")]: late.response }) });
  assert.equal(r.entries[0].proof, "invalid", "created beyond the clock skew after the time of receipt: B.1 MUST reject");
  // A clock a little behind the directory's: within the skew (proof.ts PROOF_CLOCK_SKEW), so a
  // directory that stamps each response with its current second still proves (OpenAI's does).
  const close = await signedDirectory("a.example", NOW + 2, NOW + 600);
  r = await sync(["https://a.example"], [], { now: NOW, resolve: publicDns, fetchImpl: fakeFetch({ [ID("a.example")]: close.response }) });
  assert.equal(r.entries[0].proof, "valid", "2 s ahead: within the clock skew");
});

test("sync: an ECDSA P-256 directory's proof is checked with its own algorithm, and its pin holds (Appendix B; RFC 9421 3.2 step 6.5)", async () => {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const kid = await thumbprint({ kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! });
  const directory = async (keyAlg: string, sigAlg: string) => {
    const body = JSON.stringify({ keys: [{ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid, alg: keyAlg }] });
    const digest = "sha-256=:" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))))) + ":";
    const inner = `("@authority";req "content-digest");created=${NOW - 10};expires=${NOW + 600};keyid="${kid}";alg="${sigAlg}"`
      + ';tag="http-message-signatures-directory"';
    const base = `"@authority";req: a.example\n"content-digest": ${digest}\n"@signature-params": ${inner}`;
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, new TextEncoder().encode(base)));
    const headers = { "content-type": MEDIA_TYPE, "content-digest": digest, "signature-input": `b=${inner}`,
      signature: `b=:${btoa(String.fromCharCode(...sig))}:` };
    return sync(["https://a.example"], [], { now: NOW, resolve: publicDns,
      fetchImpl: fakeFetch({ [ID("a.example")]: () => new Response(body, { status: 200, headers }) }) });
  };
  let r = await directory("ecdsa-p256-sha256", "ecdsa-p256-sha256");
  assert.deepEqual(r.entries.map((e) => [e.type, e.alg, e.proof, e.proofExpires]), [["ec-p256", "ecdsa-p256-sha256", "valid", NOW + 600]]);
  r = await directory("ecdsa-p256-sha256", "ecdsa-p384-sha384");
  assert.deepEqual([r.entries[0].proof, r.proofs[0].notes.length], ["invalid", 1], "a proof declaring another algorithm");
});

test("sync: --allow-private-origin excepts exactly the origins named, and reports each fetch (draft 6.7)", async () => {
  const seen: RequestInit[] = [];
  const key = dir({ keys: [{ kty: "OKP", crv: "Ed25519", x: X_KEY }] });
  const r = await sync(["https://localhost:8443", "https://localhost", "https://inside.example"], [], {
    now: NOW, resolve: async (host) => (host === "localhost" ? ["127.0.0.1"] : ["10.0.0.5"]),
    allowPrivate: [allowedOrigin("https://localhost:8443")!],
    fetchImpl: fakeFetch({ [`https://localhost:8443${WELL_KNOWN}`]: key }, seen) });
  assert.deepEqual(r.entries.map((e) => e.identifier), [`https://localhost:8443${WELL_KNOWN}`]);
  assert.equal(seen.length, 1, "only the named origin was fetched");
  assert.match(r.failures.find((f) => f.origin === "https://localhost")!.error, /127\.0\.0\.1, a private/, "another port of the same host is not excepted");
  assert.match(r.failures.find((f) => f.origin === "https://inside.example")!.error, /10\.0\.0\.5, a private/);
  assert.deepEqual(r.warnings, ["https://localhost:8443: https://localhost:8443 fetched without the private-address check (--allow-private-origin)"]);
});

test("allowedOrigin: an https origin as agents.txt writes one, normalised; nothing else", () => {
  assert.equal(allowedOrigin("https://localhost:8443"), "https://localhost:8443");
  assert.equal(allowedOrigin("https://bot.example:443/"), "https://bot.example");
  assert.equal(allowedOrigin("https://[::1]:8443"), "https://[::1]:8443");
  for (const bad of ["http://localhost:8443", "https://localhost:8443/keys", "https://Bot.Example", "localhost", ""]) {
    assert.equal(allowedOrigin(bad), null, bad);
  }
});

// --- Review 2026-10-14: the private-address exception's scope, DNS time limit, output, config errors ---

test("--allow-private-origin covers only the URL an agents.txt line names, never the jwks_uri a CIMD document names", async () => {
  const PRIV = "https://localhost:8443", CARD = `${PRIV}/card`, HOP = `${PRIV}/jwks.json`, PUB = "https://card.example/card";
  const resolve = async (h: string) => (h === "localhost" ? ["127.0.0.1"] : ["93.184.215.14"]);
  const allowPrivate = [allowedOrigin(PRIV)!];
  const keys = json({ keys: [OKP] }, {}, "application/jwk-set+json");
  // The excepted origin's own CIMD document is fetched; the jwks_uri it names, on that same origin, is still checked.
  let urls: string[] = [];
  let r = await sync([`${CARD} type=cimd`], [], { now: NOW, resolve, allowPrivate,
    fetchImpl: recFetch({ [CARD]: json({ client_id: CARD, jwks_uri: HOP }), [HOP]: keys }, urls) });
  assert.deepEqual(urls, [CARD], "the hop was never fetched");
  assert.match(r.failures[0]?.error ?? "(no failure)", /^localhost resolves to 127\.0\.0\.1, a private, loopback or link-local address/);
  assert.deepEqual(r.warnings, [`${CARD} type=cimd: ${PRIV} fetched without the private-address check (--allow-private-origin)`]);
  // A public CIMD whose server points its jwks_uri at the excepted origin: refused, nothing fetched there.
  urls = [];
  r = await sync([`${PUB} type=cimd`], [], { now: NOW, resolve, allowPrivate,
    fetchImpl: recFetch({ [PUB]: json({ client_id: PUB, jwks_uri: HOP }), [HOP]: keys }, urls) });
  assert.deepEqual(urls, [PUB]);
  assert.match(r.failures[0]?.error ?? "(no failure)", /127\.0\.0\.1, a private/);
  assert.deepEqual(r.warnings, [], "no fetch went unchecked");
  // The same JWK Set, listed in agents.txt itself, is excepted.
  urls = [];
  r = await sync([`${HOP} type=jwks_uri`], [], { now: NOW, resolve, allowPrivate, fetchImpl: recFetch({ [HOP]: keys }, urls) });
  assert.deepEqual([urls, r.failures, r.entries.map((e) => e.identifier)], [[HOP], [], [HOP]]);
});

test("sync: a DNS lookup that never answers fails within --timeout-ms, as a fetch does, and keeps the last-good keys", async () => {
  const urls: string[] = [];
  const held: StoreEntry[] = [{ identifier: ID("a.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY }];
  const t0 = Date.now();
  const r = await sync(["https://a.example"], held, { now: NOW, limits: { ...DEFAULT_LIMITS, timeoutMs: 50 },
    resolve: () => new Promise<string[]>(() => {}), fetchImpl: recFetch({}, urls) });
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
  assert.deepEqual(urls, [], "nothing fetched");
  assert.equal(r.failures[0]?.error, "DNS lookup of a.example timed out after 50 ms");
  assert.deepEqual(r.entries, held, "an outage evicts nothing (draft 6.10)");
  await assert.rejects(withDeadline(() => new Promise<string[]>(() => {}), 20)("h.example"), /^Error: DNS lookup of h\.example timed out after 20 ms$/);
  assert.deepEqual(await withDeadline(async () => ["192.0.2.1"], 20)("h.example"), ["192.0.2.1"]);
});

test("withDeadline: the timer is cleared once the lookup answers, so a run exits at once", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-deadline-"));
  try {
    const probe = join(dir, "probe.mjs");
    writeFileSync(probe, `const { withDeadline } = await import(${JSON.stringify(new URL("./keysync.ts", import.meta.url).href)});\n`
      + `console.log((await withDeadline(async () => ["192.0.2.1"], 60000)("a.example")).join());\n`);
    const t0 = Date.now();
    const r = spawnSync(process.execPath, [probe], { encoding: "utf8", timeout: 20000 });
    assert.equal(r.status, 0, r.stderr || "killed: the 60 s timer kept the process alive");
    assert.equal(r.stdout.trim(), "192.0.2.1");
    assert.ok(Date.now() - t0 < 15000, `took ${Date.now() - t0} ms`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a body that is not JSON fails with a fixed message, so none of its bytes reach the output (Node quotes up to ten, Bun one)", async () => {
  const evil = "\u001b[2J\u001b]0;owned\u0007\u009b31m" + "x".repeat(20);
  const bytes = new TextEncoder().encode(evil).length;
  for (const [line, url, type] of [["https://a.example", ID("a.example"), MEDIA_TYPE], ["https://b.example/k type=jwks_uri", "https://b.example/k", "application/json"]]) {
    const r = await sync([line], [], { now: NOW, resolve: publicDns,
      fetchImpl: fakeFetch({ [url]: () => new Response(evil, { status: 200, headers: { "content-type": type } }) }) });
    assert.equal(r.failures[0]?.error, `the body (${bytes} bytes) is not UTF-8 JSON`, line);
  }
  const r = await sync(["https://b.example/k type=jwks_uri"], [], { now: NOW, resolve: publicDns,
    fetchImpl: fakeFetch({ "https://b.example/k": () => new Response(new Uint8Array([0x7b, 0xff, 0x7d]), { status: 200 }) }) });
  assert.equal(r.failures[0]?.error, "the body (3 bytes) is not UTF-8 JSON");
});

test("printable: every C0 and C1 control character and DEL becomes a space; other text is untouched", () => {
  assert.equal(printable("a\u001b[31mb\nc\u0007d\u009be\u007ff\u0000g"), "a [31mb c d e f g");
  assert.equal(printable("café, Ünïcode — and 🙂"), "café, Ünïcode — and 🙂");
});

/** A temporary directory holding agents.txt, for key sync's command line. */
function cliDir(agents: string): string {
  const d = mkdtempSync(join(tmpdir(), "wba-cli-"));
  writeFileSync(join(d, "agents.txt"), agents);
  return d;
}

test("readAgents: agent lines, and each line key sync cannot use by its line number", () => {
  assert.deepEqual(readAgents("# ours\r\nhttps://a.example\r\n\n  https://b.example/k type=jwks_uri  \nhttps://c.example type=x509\n"), {
    agents: ["https://a.example", "https://b.example/k type=jwks_uri"],
    errors: ['line 5: "https://c.example type=x509": expected <https URL> [type=directory|jwks_uri|cimd]'],
  });
});

test("cli: an agents.txt line that does not parse is a config error: exit 1, no fetch, the store untouched", async () => {
  const d = cliDir("# ours\nhttps://a.example\nhttps://b.example/keys type=jwk\n\nhttp://c.example\n");
  try {
    const store = join(d, "wba-keys.tsv");
    const before = format([{ identifier: ID("a.example"), keyid: KID_KEY, type: "ed25519", publicKeyHex: HEX_KEY }], new Date(0));
    writeFileSync(store, before);
    const urls: string[] = [], out: string[] = [];
    const code = await keysyncMain(["--origins", join(d, "agents.txt"), "--out", store],
      { fetchImpl: recFetch({}, urls), resolve: publicDns, log: (l) => out.push(l), error: (l) => out.push(l) });
    assert.equal(code, 1, out.join("\n"));
    assert.deepEqual(urls, [], "nothing fetched");
    assert.equal(readFileSync(store, "utf8"), before, "the store as it was: the keys of the agent on line 3 are not dropped");
    assert.ok(!existsSync(`${store}.cache.json`) && !existsSync(`${store}.history`));
    assert.match(out.join("\n"), /agents\.txt: line 3: "https:\/\/b\.example\/keys type=jwk": expected <https URL> \[type=directory\|jwks_uri\|cimd\]/);
    assert.match(out.join("\n"), /agents\.txt: line 5: "http:\/\/c\.example": not an https origin/);
    assert.match(out.at(-1)!, /agents\.txt: 2 line\(s\) key sync cannot use; fix them and run again\. The store was not touched$/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("cli: what it prints carries no control character, whatever a directory or the network sent", async () => {
  const d = cliDir("https://a.example\nhttps://b.example\nhttps://c.example/k type=jwks_uri\n");
  try {
    const out: string[] = [];
    const evil = "\u001b]0;owned\u0007\u001b[2J";
    const body = evil + "{";
    const code = await keysyncMain(["--origins", join(d, "agents.txt"), "--out", join(d, "wba-keys.tsv")], {
      resolve: publicDns, log: (l) => out.push(l), error: (l) => out.push(l),
      fetchImpl: fakeFetch({
        [ID("a.example")]: () => new Response(body, { status: 200, headers: { "content-type": MEDIA_TYPE } }),
        [ID("b.example")]: () => { throw new Error(`certificate names ${evil}evil.example`); },
        "https://c.example/k": json({ keys: [OKP] }),
      }) });
    assert.equal(code, 2, out.join("\n"));
    for (const l of out) assert.doesNotMatch(l, /[\u0000-\u001f\u007f-\u009f]/, JSON.stringify(l)); // eslint-disable-line no-control-regex -- asserts no control character reaches the output
    assert.ok(out.includes(`failed: https://a.example: the body (${new TextEncoder().encode(body).length} bytes) is not UTF-8 JSON`), out.join("\n"));
    assert.ok(out.includes("failed: https://b.example: certificate names  ]0;owned  [2Jevil.example"), out.join("\n"));
    assert.match(out.at(-1)!, /^wba-keysync: 1 keys from 1\/3 origins/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("cli: run as a script on this runtime, a bad agents.txt line exits 1 before any fetch", () => {
  const d = cliDir("https://a.example type=x509\n");
  try {
    const cli = new URL("./cli.ts", import.meta.url).pathname;
    const r = spawnSync(process.execPath, [cli, "--origins", join(d, "agents.txt"), "--out", join(d, "wba-keys.tsv")], { encoding: "utf8", timeout: 20000 });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /line 1: "https:\/\/a\.example type=x509": expected/);
    assert.ok(!existsSync(join(d, "wba-keys.tsv")));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
