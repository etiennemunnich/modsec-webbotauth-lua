// wba-keysync: resolves allowlisted Web Bot Auth agents into the key store
// that lua/wba/keys.lua reads (format "# wba-keys v2"): Ed25519, ECDSA P-256
// and P-384, and RSA keys, each indexed by its RFC 7638 thumbprint (draft
// 5.2: RFC 7638 3.2 for RSA and EC, RFC 8037 A.3 for Ed25519).
//
// Runs out of band (cron / systemd timer), never on the request path, so
// ModSecurity never makes a network call and the Signature-Agent header can
// never steer a fetch: only operator-listed URLs are fetched (agents.txt),
// whatever their type (draft 5.5: directory, jwks_uri, cimd). Their DNS is
// third-party, so a host that is, or resolves to, a private, loopback or
// link-local address is refused before every fetch, a CIMD's jwks_uri hop
// included (draft 6.7).
//
// Each directory is cached with HTTP's own rules (draft 5.5.2 and C.4, RFC
// 9111): it is fetched again when its freshness lifetime ends, with
// If-None-Match / If-Modified-Since, so a frequent timer costs almost nothing
// and a removed key stops verifying when the directory says it should.
//
// A directory response's Appendix B possession proofs are validated
// (proof.ts) and recorded per key in the store; every key is used either way
// (B.1: a verifier MAY use keys without proof).
//
// Written against web-standard APIs (fetch, WebCrypto, AbortSignal) plus
// node:fs, so the same file runs on Bun and on Node with native type
// stripping (tested: Bun 1.3.11, Node 26.10).

import { closeSync, constants, fstatSync, fsyncSync, openSync, renameSync, rmSync, unlinkSync, writeSync } from "node:fs";
import { lookup } from "node:dns/promises";
import { WELL_KNOWN, directoryIdentifier, urlIdentifier, validIdentifier } from "./identifier.ts";
import { directoryProofs, type Proof } from "./proof.ts";
import { ALGORITHMS, RSA_LARGE_BITS, RSA_LARGE_MAX_E_BITS, RSA_MAX_BITS, RSA_MAX_E_BITS, RSA_MIN_BITS, jwkAlgorithm, type KeyType } from "./algorithms.ts";

export { WELL_KNOWN, urlIdentifier };
export const MEDIA_TYPE = "application/http-message-signatures-directory+json";
const HEADER = "# wba-keys v2";
const HEADER_V1 = "# wba-keys v1"; // Ed25519 only, no alg, proof none; still read (parse), never written

// Draft section 6.8: verifiers SHOULD reject known test keys: keys whose
// private half is published, "including the example keys in [RFC 9421]".
// Same list as verify.lua.
const TEST_KEY_THUMBPRINTS = new Set([
  // RFC 9421 B.1.4 (Ed25519; the draft's E.2 examples), B.1.1 (RSA), B.1.2
  // (RSA-PSS; the draft's E.1 examples), B.1.3 (ECC P-256).
  "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", "BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo",
  "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA", "ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI",
  // RFC 8032 7.1's five Ed25519 keys (TEST 1 is also RFC 8037 Appendix A's).
  "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", "FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk",
  "FVV5umTuau890q59V-4Ga_R6qWb7ON_ivJc4EjvCwTM", "lZI1vM7tnlYapaF5-cy86ptx0tT_8Av721hhiNB5ti4",
  "iiDHHfFVNG6ICMUTsicgrWf1igtFYZEK73xlobt1ah4",
  // The JOSE examples: RFC 7517 A.2's RSA (RFC 7638 3.1's thumbprint
  // example) and P-256 keys, RFC 7515 A.2's RSA and A.3's P-256 keys.
  "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
  "IsUn6_e04MaShXFIISMp4kG62LWzMIPy_MvSA5pJgX8", "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
]);

// JWK members that carry private key material (RFC 7517 7.1, RFC 7518 6,
// RFC 8037 2). A directory that publishes one has published the key itself.
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

// The algorithms, key types and RSA bounds (algorithms.ts, the same rules as
// lua/wba/algorithms.lua), re-exported for callers and tests.

// EC curves by JWK crv: the key type, and the coordinate size in bytes
// (RFC 7518 6.2.1.2: x and y MUST be the full size of a coordinate).
const CURVES: Record<string, [KeyType, number]> = { "P-256": ["ec-p256", 32], "P-384": ["ec-p384", 48] };

export interface Limits {
  maxBytes: number; // directory size cap after content decoding (draft 6.7)
  maxKeys: number; // key count cap (draft 6.7)
  timeoutMs: number; // wall-clock fetch timeout (draft 6.7)
}
export const DEFAULT_LIMITS: Limits = { maxBytes: 65536, maxKeys: 32, timeoutMs: 5000 };

export interface StoreEntry {
  identifier: string;
  keyid: string;
  type: KeyType;
  alg?: string; // the algorithm the JWK alg pins the key to, as an ALGORITHMS name (jwkAlgorithm), when it has one
  // Lowercase hex: Ed25519 the 32-byte key; EC the SEC1 uncompressed point
  // 04 || x || y; RSA "<n>:<e>", each minimal big-endian (keys.lua).
  publicKeyHex: string;
  nbf?: number;
  exp?: number;
  proof?: Proof; // Appendix B possession proof for this key; absent = none
  proofExpires?: number; // the valid proof's expires (5.5.3)
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

/** The key-directory URL for an https origin, or null. Same rules as keys.lua identifier(). */
export function identifier(origin: string): string | null {
  return directoryIdentifier(origin);
}

type AgentType = "directory" | "jwks_uri" | "cimd";
/** One agents.txt entry: the line, its type, the URL to fetch, and its identifier (draft 5.5). */
export interface Agent { line: string; type: AgentType; url: string; id: string }

/**
 * CIMD 3 rules for a Client Identifier URL that urlIdentifier() does not
 * already enforce (https, no userinfo): a path, no dot segments, no fragment.
 */
function cimdUrlProblem(url: string): string | null {
  const rest = url.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/, "");
  const path = /^[^?#]*/.exec(rest)![0];
  if (path === "") return "CIMD 3: a Client Identifier URL MUST contain a path";
  if (path.split("/").some((s) => /^(?:\.|%2e){1,2}$/i.test(s))) return "CIMD 3: MUST NOT contain dot segments";
  if (rest.includes("#")) return "CIMD 3: MUST NOT contain a fragment";
  return null;
}

/**
 * One agents.txt line: "<https URL> [type=directory|jwks_uri|cimd]". The type
 * defaults to directory, as in Signature-Agent (draft 5.2.1). A directory is
 * an origin, fetched at its well-known URI; jwks_uri and cimd are fetched as
 * written, and identified by urlIdentifier() (query and fragment dropped).
 * Returns why the line is unusable instead of an Agent.
 */
export function parseAgent(line: string): Agent | string {
  const [url, typeArg, ...rest] = line.trim().split(/\s+/);
  let type: AgentType = "directory";
  if (typeArg !== undefined) {
    const m = /^type=(directory|jwks_uri|cimd)$/.exec(typeArg);
    if (!m || rest.length > 0) return "expected <https URL> [type=directory|jwks_uri|cimd]";
    type = m[1] as AgentType;
  }
  if (type === "directory") {
    const id = directoryIdentifier(url ?? "");
    return id ? { line, type, url: id, id } : "not an https origin (https://host[:port] only)";
  }
  const id = urlIdentifier(url ?? "");
  if (!id) return "not an https URL (RFC 3986; no userinfo)";
  const why = type === "cimd" ? cimdUrlProblem(url) : null;
  return why ?? { line, type, url, id };
}

function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Strict unpadded base64url (RFC 7515 2, RFC 4648 5): only the alphabet, no
 * padding, and zero pad bits, so each byte string has exactly one spelling
 * and the thumbprint over the spelling identifies the key.
 */
function decodeB64url(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(s.slice(-1));
  if ((s.length % 4 === 2 && last % 16 !== 0) || (s.length % 4 === 3 && last % 4 !== 0)) return null;
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const toHex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** Bits in a big-endian number whose first byte is not zero. */
const bitLength = (b: Uint8Array) => (b.length - 1) * 8 + (32 - Math.clz32(b[0]));

/** The JWK members RFC 7638 3.2 hashes, for the key types stored here. */
export type PublicJwk =
  | { kty: "OKP"; crv: "Ed25519"; x: string }
  | { kty: "EC"; crv: "P-256" | "P-384"; x: string; y: string }
  | { kty: "RSA"; n: string; e: string };

/**
 * RFC 7638 JWK thumbprint: SHA-256 over the required members in
 * lexicographic order, no whitespace (3.2, 3.3); RFC 8037 A.3 for Ed25519.
 * The values are base64url, which JSON never escapes.
 */
export async function thumbprint(jwk: PublicJwk): Promise<string> {
  const canonical = jwk.kty === "RSA" ? `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}`
    : jwk.kty === "EC" ? `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
    : `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64url(new Uint8Array(digest));
}

type Material = { type: KeyType; jwk: PublicJwk; hex: string };

/**
 * The public key of one JWK, validated, or why it is unusable. Unknown key
 * types and curves give null (ignored, as before: X25519, P-521, oct).
 */
async function material(k: Record<string, unknown>): Promise<Material | string | null> {
  if (k.kty === "OKP" && k.crv === "Ed25519") {
    const x = decodeB64url(k.x);
    if (!x || x.length !== 32) return "malformed x";
    return { type: "ed25519", jwk: { kty: "OKP", crv: "Ed25519", x: k.x as string }, hex: toHex(x) };
  }
  if (k.kty === "EC" && typeof k.crv === "string" && Object.hasOwn(CURVES, k.crv)) {
    const [type, size] = CURVES[k.crv];
    const x = decodeB64url(k.x), y = decodeB64url(k.y);
    if (!x || !y || x.length !== size || y.length !== size) return "malformed x or y";
    const jwk = { kty: "EC", crv: k.crv as "P-256" | "P-384", x: k.x as string, y: k.y as string } as const;
    try { // the point must be on the curve; WebCrypto's import checks it
      await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: k.crv }, false, ["verify"]);
    } catch {
      return "a point not on the curve";
    }
    return { type, jwk, hex: "04" + toHex(x) + toHex(y) };
  }
  if (k.kty === "RSA") {
    const n = decodeB64url(k.n), e = decodeB64url(k.e);
    // RFC 7518 2 (Base64urlUInt): "the minimum number of octets".
    if (!n || !e || n.length === 0 || e.length === 0 || n[0] === 0 || e[0] === 0) return "malformed n or e";
    const bits = bitLength(n);
    if (bits < RSA_MIN_BITS || bits > RSA_MAX_BITS) return `a ${bits}-bit modulus (${RSA_MIN_BITS} to ${RSA_MAX_BITS} allowed)`;
    if (n[n.length - 1] % 2 === 0) return "an even modulus";
    if (e[e.length - 1] % 2 === 0 || bitLength(e) > RSA_MAX_E_BITS || (e.length === 1 && e[0] < 3)) {
      return "a public exponent that is even, under 3 or over 256 bits";
    }
    if (bits > RSA_LARGE_BITS && bitLength(e) > RSA_LARGE_MAX_E_BITS) {
      return `a public exponent over ${RSA_LARGE_MAX_E_BITS} bits with a ${bits}-bit modulus (OpenSSL verifies none)`;
    }
    return { type: "rsa", jwk: { kty: "RSA", n: k.n as string, e: k.e as string }, hex: `${toHex(n)}:${toHex(e)}` };
  }
  return null;
}

const isTime = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/**
 * Usable public keys from a parsed JWK Set (draft 5.5.1; all three agent
 * types resolve to one): Ed25519, EC P-256 and P-384, and RSA. Keys are
 * always indexed by their computed thumbprint, never by `kid`.
 * kidIsThumbprint (a set served at the well-known URI, draft 5.5): a kid MUST
 * be the thumbprint, so a key labelled otherwise is rejected (5.5.1: reject
 * malformed entries). Elsewhere (jwks_uri, cimd) kid is an operator-chosen
 * label and is ignored: "a verifier that cannot match keyid against kid there
 * computes thumbprints instead" (5.5). Throws if the document is not a JWK
 * Set or exceeds maxKeys; individual unusable keys are skipped.
 */
export async function keysFromDirectory(
  doc: unknown, limits: Limits, now: number, warn: (msg: string) => void, kidIsThumbprint = true,
): Promise<Omit<StoreEntry, "identifier">[]> {
  if (typeof doc !== "object" || doc === null || !Array.isArray((doc as { keys?: unknown }).keys)) {
    throw new Error("not a JWK Set (no keys array)");
  }
  const jwks = (doc as { keys: unknown[] }).keys;
  if (jwks.length > limits.maxKeys) throw new Error(`${jwks.length} keys exceeds maxKeys ${limits.maxKeys}`);

  const out = new Map<string, Omit<StoreEntry, "identifier">>();
  for (const jwk of jwks) {
    if (typeof jwk !== "object" || jwk === null) continue;
    const k = jwk as Record<string, unknown>;
    if (k.use !== undefined && k.use !== "sig") continue;
    if (PRIVATE_MEMBERS.some((m) => m in k)) { warn("rejected a key published with its private part"); continue; }
    const m = await material(k);
    if (m === null) continue; // a key type or curve this verifier has no algorithm for
    const label = k.kty === "OKP" ? "Ed25519" : k.kty === "EC" ? String(k.crv) : "RSA"; // known by now
    if (typeof m === "string") { warn(`skipped ${label} key with ${m}`); continue; }
    const pin = k.alg === undefined ? undefined : jwkAlgorithm(k.alg, m.type);
    if (pin === null) { warn(`skipped ${label} key with alg ${JSON.stringify(k.alg).slice(0, 40)}`); continue; }
    if ((k.nbf !== undefined && !isTime(k.nbf)) || (k.exp !== undefined && !isTime(k.exp))) {
      warn("skipped key with non-integer nbf/exp"); continue;
    }
    // nbf/exp are not JWK members (RFC 7517); the draft's example uses Unix
    // seconds, but at least one live directory publishes milliseconds. A
    // value >= 1e12 cannot be a plausible date in seconds (year 33658), so it
    // is read as milliseconds. A misreading needs a time in milliseconds
    // before September 2001, or in seconds after year 33658; no current key
    // carries either.
    const seconds = (v: number, field: string) => {
      if (v < 1e12) return v;
      warn(`${field} ${v} looks like milliseconds; using ${Math.floor(v / 1000)}`);
      return Math.floor(v / 1000);
    };
    const nbf = isTime(k.nbf) ? seconds(k.nbf, "nbf") : undefined;
    const exp = isTime(k.exp) ? seconds(k.exp, "exp") : undefined;
    if (exp !== undefined && exp <= now) continue; // already expired
    const keyid = await thumbprint(m.jwk);
    if (TEST_KEY_THUMBPRINTS.has(keyid)) { warn(`rejected published test key ${keyid}`); continue; }
    if (kidIsThumbprint && k.kid !== undefined && k.kid !== keyid) {
      // Draft 5.5: a kid at the well-known URI MUST be the thumbprint, so a
      // verifier can check the directory's labelling; 5.5.1: reject
      // malformed entries. JSON-encoded and truncated: the directory is
      // remote input and must not write raw bytes to logs.
      warn(`rejected key: kid ${JSON.stringify(k.kid).slice(0, 80)} is not its thumbprint ${keyid}`);
      continue;
    }
    out.set(keyid, {
      keyid, type: m.type, ...(pin !== undefined ? { alg: pin } : {}), publicKeyHex: m.hex,
      ...(nbf !== undefined ? { nbf } : {}), ...(exp !== undefined ? { exp } : {}),
    });
  }
  return [...out.values()];
}

export async function readCapped(res: Response, maxBytes: number): Promise<Uint8Array> {
  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`directory exceeds maxBytes ${maxBytes}`);
      }
      chunks.push(value);
    }
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { body.set(c, offset); offset += c.byteLength; }
  return body;
}

export interface Validators { etag?: string; lastModified?: string }
export interface DirectoryResponse { notModified: boolean; doc?: unknown; headers: Headers; body?: Uint8Array }

/**
 * GET one resource of draft 5.5 (a directory, a JWK Set, a CIMD): 200 only,
 * never follow redirects, bounded size and time (5.5, 6.7). At the well-known
 * URI the media type is exactly the directory's (5.5.1); elsewhere the draft sets
 * none, so any type is read, and the body must still parse as JSON and pass
 * the key checks (5.5). Asks for no content coding, so a Content-Digest (Appendix B) can be
 * checked against the bytes received. With validators from an earlier
 * response it revalidates, and 304 means "still the same".
 */
export async function getDirectory(
  url: string, limits: Limits, fetchImpl: FetchLike = fetch, validators?: Validators, accept?: string,
): Promise<DirectoryResponse> {
  const atWellKnown = new URL(url).pathname === WELL_KNOWN;
  const headers: Record<string, string> = {
    accept: accept ?? (atWellKnown ? MEDIA_TYPE : "application/jwk-set+json, application/json"), "accept-encoding": "identity",
  };
  if (validators?.etag) headers["if-none-match"] = validators.etag;
  if (validators?.lastModified) headers["if-modified-since"] = validators.lastModified;
  const res = await fetchImpl(url, { redirect: "manual", signal: AbortSignal.timeout(limits.timeoutMs), headers });
  if (res.status === 304 && validators) return { notModified: true, headers: res.headers };
  if (res.status !== 200) throw new HttpError(res.status, res.headers);
  const type = (res.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (atWellKnown && type !== MEDIA_TYPE) throw new Error(`content-type "${type}", expected ${MEDIA_TYPE}`);
  const body = await readCapped(res, limits.maxBytes);
  return { notModified: false, doc: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)), headers: res.headers, body };
}

/** The parsed directory, or a throw (no caching): getDirectory without validators. */
export async function fetchDirectory(url: string, limits: Limits, fetchImpl: FetchLike = fetch): Promise<unknown> {
  return (await getDirectory(url, limits, fetchImpl)).doc;
}

export class HttpError extends Error {
  // Plain fields, not parameter properties: Node's type stripping rejects those.
  status: number;
  headers: Headers;
  constructor(status: number, headers: Headers) {
    super(`HTTP ${status} (only 200 is accepted; redirects are not followed)`);
    this.status = status;
    this.headers = headers;
  }
}

// --- Freshness (RFC 9111 4.2), for a private cache ---------------------------

/** Longest the store keeps a directory without asking again, whatever it says. */
export const MAX_FRESHNESS = 86400;

const httpDate = (v: string | null) => (v === null ? NaN : Date.parse(v) / 1000);

/**
 * Seconds a directory response stays fresh (RFC 9111 4.2.1-4.2.3): no-store
 * or no-cache 0; else max-age; else Expires minus Date; else the 10% heuristic
 * on Last-Modified (4.2.2); else 0. Age is subtracted; MAX_FRESHNESS caps it.
 * This store serves one verifier, so it is a private cache and s-maxage does
 * not apply.
 */
export function freshnessLifetime(h: Headers, receivedAt: number): number {
  const cc = (h.get("cache-control") ?? "").toLowerCase();
  let life: number;
  const date = Number.isNaN(httpDate(h.get("date"))) ? receivedAt : httpDate(h.get("date"));
  const maxAge = /(?:^|,)\s*max-age\s*=\s*"?(\d+)"?\s*(?:,|$)/.exec(cc);
  if (/(?:^|,)\s*(?:no-store|no-cache)\b/.test(cc)) life = 0;
  else if (maxAge) life = Number(maxAge[1]);
  else if (h.has("expires")) life = Number.isNaN(httpDate(h.get("expires"))) ? 0 : httpDate(h.get("expires")) - date;
  else if (h.has("last-modified") && !Number.isNaN(httpDate(h.get("last-modified")))) {
    life = (date - httpDate(h.get("last-modified"))) / 10;
  } else life = 0;
  const age = /^\d+$/.test(h.get("age") ?? "") ? Number(h.get("age")) : 0;
  return Math.max(0, Math.min(MAX_FRESHNESS, Math.floor(life - age)));
}

// --- Address ranges a directory fetch must not reach (draft 6.7) -------------

function v4(ip: string): number[] | null {
  const p = ip.split(".");
  if (p.length !== 4 || !p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255)) return null;
  return p.map(Number);
}

/** The eight 16-bit groups of an IPv6 address, or null. */
function v6(ip: string): number[] | null {
  let s = ip.toLowerCase().replace(/%.*$/, "");
  const tail = /:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const b = v4(tail[1]);
    if (!b) return null;
    s = s.slice(0, -tail[1].length) + ((b[0] << 8) | b[1]).toString(16) + ":" + ((b[2] << 8) | b[3]).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (x: string) => (x === "" ? [] : x.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)));
  const head = parse(halves[0]), rest = halves.length === 2 ? parse(halves[1]) : [];
  const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - rest.length).fill(0), ...rest] : head;
  return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff) ? groups : null;
}

/**
 * True for an address a directory fetch must not reach: private (RFC 1918,
 * IPv6 unique-local fc00::/7), loopback, link-local, plus the unspecified and
 * "this network" ranges, the RFC 6598 shared space, and IPv4-mapped or
 * -compatible forms of any of them. Anything unparsable is refused too.
 */
export function forbiddenAddress(ip: string): boolean {
  const a = v4(ip);
  if (a) {
    return a[0] === 0 || a[0] === 10 || a[0] === 127 || (a[0] === 169 && a[1] === 254)
      || (a[0] === 172 && a[1] >= 16 && a[1] <= 31) || (a[0] === 192 && a[1] === 168)
      || (a[0] === 100 && a[1] >= 64 && a[1] <= 127)
      || a[0] >= 224; // multicast 224/4, reserved 240/4, broadcast
  }
  const g = v6(ip);
  if (!g) return true;
  const embedded = (hi: number, lo: number) => forbiddenAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) { // ::ffff:a.b.c.d, ::a.b.c.d, ::, ::1
    if (g[5] === 0 && g[6] === 0 && g[7] <= 1) return true;
    return embedded(g[6], g[7]);
  }
  // IPv4 carried inside IPv6 reaches the IPv4 address: NAT64 64:ff9b::/96
  // (RFC 6052) and 6to4 2002::/16 (RFC 3056) are judged by that address;
  // local-use NAT64 64:ff9b:1::/48 (RFC 8215) is refused outright.
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return embedded(g[6], g[7]);
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;
  // SIIT's IPv4-translated ::ffff:0:a.b.c.d (RFC 2765 2.1), by its IPv4 address.
  if (g.slice(0, 4).every((x) => x === 0) && g[4] === 0xffff && g[5] === 0) return embedded(g[6], g[7]);
  if (g[0] === 0x2002) return embedded(g[1], g[2]);
  return (g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xffc0) === 0xfe80
    || (g[0] & 0xffc0) === 0xfec0 // deprecated site-local fec0::/10 (RFC 3879)
    || (g[0] & 0xff00) === 0xff00; // multicast ff00::/8
}

export type Resolver = (host: string) => Promise<string[]>;
export const resolveHost: Resolver = async (host) =>
  (await lookup(host, { all: true, verbatim: true })).map((r) => r.address);

/**
 * Refuse a fetch whose host is, or resolves to, a private, loopback or
 * link-local address (draft 6.7). An IP literal is checked as written (the
 * URL parser's form of it), never handed to DNS. Run before every fetch.
 */
export async function guardAddress(url: string, resolve: Resolver): Promise<void> {
  const host = new URL(url).hostname;
  const literal = host.startsWith("[") ? host.slice(1, -1) : v4(host) ? host : null;
  if (literal !== null) {
    if (forbiddenAddress(literal)) throw new Error(`${host} is a private, loopback or link-local address (draft 6.7)`);
    return;
  }
  const addrs = await resolve(host);
  if (addrs.length === 0) throw new Error(`${host} does not resolve`);
  const bad = addrs.find(forbiddenAddress);
  if (bad) throw new Error(`${host} resolves to ${bad}, a private, loopback or link-local address (draft 6.7)`);
}

/**
 * The origin named by --allow-private-origin, normalised (":443" and a
 * trailing "/" dropped), or null unless the value is an https origin with no
 * path, as an agents.txt key directory line is.
 */
export function allowedOrigin(value: string): string | null {
  return directoryIdentifier(value) === null ? null : new URL(value).origin;
}

/**
 * guardAddress, except for an origin the operator named on key sync's command
 * line with --allow-private-origin: its own bot on its own network, or a test
 * bot. Only that exact origin (scheme, host and port) skips the check, and
 * each such fetch is reported. agents.txt and bots files cannot name one, so a
 * list from elsewhere never can. Draft 6.7 is a SHOULD; this is the operator's
 * choice for its own hosts (CONFORMANCE.md).
 */
async function guardUnlessAllowed(url: string, resolve: Resolver, allow: ReadonlySet<string>, warn: (w: string) => void): Promise<void> {
  const origin = new URL(url).origin;
  if (allow.has(origin)) { warn(`${origin} fetched without the private-address check (--allow-private-origin)`); return; }
  await guardAddress(url, resolve);
}

interface ProofReport { origin: string; identifier: string; summary: Proof; valid: number; keys: number; notes: string[] }

export interface SyncResult {
  entries: StoreEntry[];
  failures: { origin: string; error: string }[];
  warnings: string[];
  cache: Cache;
  fresh: string[]; // origins whose cached directory was still fresh (not fetched)
  empty: string[]; // origins that resolved to no usable key: listed, yet nothing of theirs can verify
  proofs: ProofReport[]; // Appendix B, for each directory fetched with a 200 this run
}

/** Per-directory cache state, kept beside the store (cli.ts). */
interface CacheEntry {
  freshUntil: number; // Unix seconds; refetch at or after this
  keys: number; // keys the directory gave; a store holding another count is not trusted as fresh
  source?: string; // "<type> <url>" it was resolved from; another listing is not trusted as fresh
  etag?: string;
  lastModified?: string;
  failures?: number; // consecutive failed fetches
  retryAt?: number; // do not retry before this (draft C.5)
}
export type Cache = Record<string, CacheEntry>;

type Keys = Omit<StoreEntry, "identifier">[];
interface Resolution { keys: Keys; life: number; etag?: string; lastModified?: string; proof?: Omit<ProofReport, "origin" | "identifier"> }

// CIMD 4.1: no shared secrets in a Client ID Metadata Document.
const SHARED_SECRET_METHODS = new Set(["client_secret_post", "client_secret_basic", "client_secret_jwt"]);

/**
 * Resolve one listed agent to its keys (draft 5.5), guarding every fetch
 * (6.7). directory and jwks_uri: one JWK Set; a directory's Appendix B
 * proofs are validated and set on each key. cimd: the Client ID Metadata
 * Document, whose client_id must be the URL fetched (CIMD 4), then its jwks,
 * or its jwks_uri fetched under the same rules; freshness is the shorter of
 * the two responses'.
 */
async function resolveAgent(a: Agent, ctx: {
  limits: Limits; now: number; clock: () => number; fetchImpl?: FetchLike; resolve: Resolver; validators?: Validators;
  held: Keys; warn: (w: string) => void; allowPrivate: ReadonlySet<string>;
}): Promise<Resolution> {
  const { limits, now, fetchImpl, resolve, warn } = ctx;
  await guardUnlessAllowed(a.url, resolve, ctx.allowPrivate, warn);
  if (a.type !== "cimd") {
    const res = await getDirectory(a.url, limits, fetchImpl, ctx.validators);
    const life = freshnessLifetime(res.headers, now);
    const etag = res.headers.get("etag") ?? (res.notModified ? ctx.validators?.etag : undefined) ?? undefined;
    const lastModified = res.headers.get("last-modified") ?? (res.notModified ? ctx.validators?.lastModified : undefined) ?? undefined;
    if (res.notModified) return { keys: ctx.held, life, etag, lastModified };
    const keys = await keysFromDirectory(res.doc, limits, now, warn, new URL(a.url).pathname === WELL_KNOWN);
    if (a.type !== "directory") return { keys, life, etag, lastModified };
    // Judged at receipt: a created signed while the fetch was in flight is not "in the future" (B.1).
    const p = await directoryProofs({ authority: new URL(a.url).host, headers: res.headers, body: res.body!, keys, now: ctx.clock() });
    for (const k of keys) {
      const kp = p.keys.get(k.keyid)!;
      k.proof = kp.proof;
      if (kp.expires !== undefined) k.proofExpires = kp.expires;
    }
    const valid = keys.filter((k) => k.proof === "valid").length;
    return { keys, life, etag, lastModified, proof: { summary: p.summary, valid, keys: keys.length, notes: p.notes } };
  }
  const res = await getDirectory(a.url, limits, fetchImpl, undefined, "application/json");
  const doc = res.doc as Record<string, unknown>;
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new Error("CIMD 4: not a JSON object");
  if (doc.client_id !== a.url) {
    throw new Error(`CIMD 4: client_id ${JSON.stringify(doc.client_id ?? null).slice(0, 80)} is not the URL fetched`);
  }
  if ("client_secret" in doc || "client_secret_expires_at" in doc
    || SHARED_SECRET_METHODS.has(String(doc.token_endpoint_auth_method))) {
    throw new Error("CIMD 4.1: a shared secret MUST NOT be used");
  }
  if (doc.jwks !== undefined && doc.jwks_uri !== undefined) throw new Error("RFC 7591 2: jwks and jwks_uri MUST NOT both be present");
  const life = freshnessLifetime(res.headers, now);
  if (doc.jwks !== undefined) return { keys: await keysFromDirectory(doc.jwks, limits, now, warn, false), life };
  const jwksUri = doc.jwks_uri;
  if (jwksUri === undefined) throw new Error("CIMD has no jwks or jwks_uri: no key material (draft 5.5)");
  if (typeof jwksUri !== "string" || urlIdentifier(jwksUri) === null) throw new Error("CIMD jwks_uri is not an https URL");
  await guardUnlessAllowed(jwksUri, resolve, ctx.allowPrivate, warn);
  const res2 = await getDirectory(jwksUri, limits, fetchImpl);
  const keys = await keysFromDirectory(res2.doc, limits, now, warn, new URL(jwksUri).pathname === WELL_KNOWN);
  return { keys, life: Math.min(life, freshnessLifetime(res2.headers, now)) };
}

/**
 * Resolve every listed agent (agents.txt lines, parseAgent). A directory
 * that resolves replaces what was held for it, even if it now lacks a key
 * (that is how removal revokes). A fetch that fails keeps the previous
 * entries: an outage is not evidence (draft 6.10: it MUST NOT evict a cached
 * entry). Agents no longer listed are dropped.
 */
export async function sync(
  origins: string[], previous: StoreEntry[],
  opts: { limits?: Limits; now?: number; clock?: () => number; fetchImpl?: FetchLike; cache?: Cache; resolve?: Resolver; allowPrivate?: string[] } = {},
): Promise<SyncResult> {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  // The time a response is received (proofs are judged then); tests fix it.
  const clock = opts.clock ?? (opts.now !== undefined ? () => now : () => Math.floor(Date.now() / 1000));
  const resolve = opts.resolve ?? resolveHost;
  const allowPrivate = new Set(opts.allowPrivate ?? []);
  const oldCache = opts.cache ?? {};
  const result: SyncResult = { entries: [], failures: [], warnings: [], cache: {}, fresh: [], empty: [], proofs: [] };
  const byId = new Map<string, StoreEntry[]>();
  for (const e of previous) byId.set(e.identifier, [...(byId.get(e.identifier) ?? []), e]);

  // One fetch per identifier, however many spellings of it are listed (a
  // duplicate line in the store would make keys.lua reject all of it). Draft
  // 5.5: spellings that differ only in query are one identifier.
  const targets = new Map<string, Agent>();
  for (const origin of origins) {
    const a = parseAgent(origin);
    if (typeof a === "string") { result.failures.push({ origin, error: a }); continue; }
    const first = targets.get(a.id);
    if (!first) targets.set(a.id, a);
    else if (first.type !== a.type || first.url !== a.url) {
      result.warnings.push(`${origin}: the same identifier as ${first.line} (draft 5.5); only that line is fetched`);
    }
    if (a.type === "cimd" && a.url.includes("?")) result.warnings.push(`${origin}: CIMD 3: SHOULD NOT contain a query`);
  }

  type Outcome = { origin: string; id: string; keys?: Keys; error?: string; fresh?: boolean };
  const resolved = await Promise.all([...targets.values()].map(async (a): Promise<Outcome> => {
    const { id, line: origin } = a;
    const source = `${a.type} ${a.url}`;
    const held = byId.get(id) ?? [];
    const c = oldCache[id];
    // The store still holds what the cache describes, resolved the same way.
    const trusted = c !== undefined && c.keys === held.length && c.source === source;
    if (trusted && now < c.freshUntil) {
      result.cache[id] = c;
      return { origin, id, keys: held, fresh: true };
    }
    if (c?.retryAt !== undefined && now < c.retryAt) { // C.5: negative caching
      result.cache[id] = c;
      return { origin, id, error: `last fetch failed; next try after ${new Date(c.retryAt * 1000).toISOString()}` };
    }
    try {
      // A 304 cannot renew a possession proof, and a CIMD spans two
      // responses: either way the fetch is unconditional.
      const conditional = trusted && a.type !== "cimd" && !held.some((e) => e.proof === "valid");
      const r = await resolveAgent(a, { limits, now, clock, fetchImpl: opts.fetchImpl, resolve, held, allowPrivate,
        validators: conditional ? { etag: c.etag, lastModified: c.lastModified } : undefined,
        warn: (w) => result.warnings.push(`${origin}: ${w}`) });
      // Refetched no later than its earliest valid proof expires (5.5.3), so
      // the proof the store records stays current while the directory is up.
      const proofEnd = Math.min(...r.keys.filter((k) => k.proof === "valid").map((k) => k.proofExpires ?? 0));
      result.cache[id] = { freshUntil: Math.min(now + r.life, proofEnd), keys: r.keys.length, source,
        ...(r.etag ? { etag: r.etag } : {}), ...(r.lastModified ? { lastModified: r.lastModified } : {}) };
      if (r.proof) result.proofs.push({ origin, identifier: id, ...r.proof });
      return { origin, id, keys: r.keys };
    } catch (err) {
      // C.5: back off 30 s, doubling, at most five minutes; a Retry-After
      // (seconds or HTTP date) from the directory wins, capped at a day.
      const failures = (c?.failures ?? 0) + 1;
      let wait = Math.min(300, 30 * 2 ** (failures - 1));
      const ra = err instanceof HttpError ? err.headers.get("retry-after") : null;
      if (ra !== null) {
        const secs = /^\d+$/.test(ra) ? Number(ra) : httpDate(ra) - now;
        if (Number.isFinite(secs) && secs > 0) wait = Math.min(86400, Math.ceil(secs));
      }
      // Validators survive a failure: the held keys are still that response.
      result.cache[id] = { freshUntil: 0, keys: held.length, failures, retryAt: now + wait, ...(trusted ? { source } : {}),
        ...(trusted && c.etag ? { etag: c.etag } : {}), ...(trusted && c.lastModified ? { lastModified: c.lastModified } : {}) };
      return { origin, id, error: err instanceof Error ? err.message : String(err) };
    }
  }));

  for (const r of resolved) {
    if (r.keys) {
      for (const k of r.keys) result.entries.push({ identifier: r.id, ...k });
      if (r.fresh) result.fresh.push(r.origin);
      if (r.keys.length === 0) result.empty.push(r.origin);
    } else {
      result.failures.push({ origin: r.origin, error: r.error ?? "unknown error" });
      result.entries.push(...(byId.get(r.id) ?? [])); // last-good (draft 6.10)
    }
  }
  result.entries.sort((a, b) => (a.identifier + "\t" + a.keyid < b.identifier + "\t" + b.keyid ? -1 : 1));
  return result;
}

/** Serialize entries in keys.lua format v2 (keys.lua says what each column is). */
export function format(entries: StoreEntry[], generatedAt: Date): string {
  const lines = [HEADER, `# generated ${generatedAt.toISOString()} by wba-keysync`];
  for (const e of entries) {
    const valid = e.proof === "valid" && e.proofExpires !== undefined;
    const proof = valid ? "valid" : e.proof === "invalid" ? "invalid" : "none";
    lines.push([e.identifier, e.keyid, e.type, e.alg ?? "-", e.publicKeyHex, e.nbf ?? "-", e.exp ?? "-",
      proof, valid ? e.proofExpires : "-"].join("\t"));
  }
  return lines.join("\n") + "\n";
}

const hexBits = (h: string) => (h.length / 2 - 1) * 8 + (32 - Math.clz32(parseInt(h.slice(0, 2), 16)));
const minimalHex = (h: string) => /^(?:[0-9a-f]{2})+$/.test(h) && !h.startsWith("00");

/** True when `hex` is a valid public key column for `type`: keys.lua's rules exactly. */
function validPublicKey(type: string, hex: string): boolean {
  if (type === "ed25519") return /^[0-9a-f]{64}$/.test(hex);
  if (type === "ec-p256") return /^04[0-9a-f]{128}$/.test(hex);
  if (type === "ec-p384") return /^04[0-9a-f]{192}$/.test(hex);
  if (type !== "rsa") return false;
  const m = /^([0-9a-f]+):([0-9a-f]+)$/.exec(hex);
  if (!m || !minimalHex(m[1]) || !minimalHex(m[2])) return false;
  const [n, e] = [m[1], m[2]];
  return hexBits(n) >= RSA_MIN_BITS && hexBits(n) <= RSA_MAX_BITS && parseInt(n.slice(-1), 16) % 2 === 1
    && parseInt(e.slice(-1), 16) % 2 === 1 && hexBits(e) <= RSA_MAX_E_BITS && (e.length > 2 || parseInt(e, 16) >= 3)
    && (hexBits(n) <= RSA_LARGE_BITS || hexBits(e) <= RSA_LARGE_MAX_E_BITS);
}

const PROOFS = new Set(["valid", "invalid", "none"]);

/** Parse a store written by format() (or a version 1 store). Throws on anything keys.lua would reject. */
export function parse(text: string): StoreEntry[] {
  const lines = text.split("\n").map((l) => l.replace(/\r$/, "")); // same line rule as keys.lua
  const fields = lines[0] === HEADER ? 9 : lines[0] === HEADER_V1 ? 5 : 0;
  if (fields === 0) throw new Error("missing version header");
  const seen = new Set<string>();
  const out: StoreEntry[] = [];
  lines.slice(1).forEach((line, n) => {
    if (line === "" || line.startsWith("#")) return;
    const f = line.split("\t");
    const where = `line ${n + 2}`;
    if (f.length !== fields) throw new Error(`${where}: expected ${fields} tab-separated fields`);
    // Version 1: Ed25519 keys with no alg and proof none (keys.lua).
    const [id, keyid, type, alg, hex, nbf, exp, proof, proofExp] =
      fields === 5 ? [f[0], f[1], "ed25519", "-", f[2], f[3], f[4], "none", "-"] : f;
    if (!validIdentifier(id)) throw new Error(`${where}: bad identifier`);
    if (!/^[A-Za-z0-9_-]{43}$/.test(keyid)) throw new Error(`${where}: bad keyid`);
    if (alg !== "-" && !(Object.hasOwn(ALGORITHMS, alg) && ALGORITHMS[alg] === type)) {
      throw new Error(`${where}: bad alg for key type`);
    }
    if (!validPublicKey(type, hex)) throw new Error(`${where}: bad key type or public key`);
    const time = (s: string, what: string) => {
      if (s === "-") return undefined;
      if (!/^[0-9]{1,15}$/.test(s)) throw new Error(`${where}: bad ${what}`);
      return Number(s);
    };
    const nb = time(nbf, "nbf/exp"), ex = time(exp, "nbf/exp"), pe = time(proofExp, "proof");
    if (!PROOFS.has(proof) || (proof === "valid") !== (pe !== undefined)) throw new Error(`${where}: bad proof`);
    if (seen.has(id + "\t" + keyid)) throw new Error(`${where}: duplicate key`);
    seen.add(id + "\t" + keyid);
    const e: StoreEntry = { identifier: id, keyid, type: type as KeyType, ...(alg !== "-" ? { alg } : {}), publicKeyHex: hex };
    if (nb !== undefined) e.nbf = nb;
    if (ex !== undefined) e.exp = ex;
    if (proof !== "none") e.proof = proof as Proof;
    if (pe !== undefined) e.proofExpires = pe;
    out.push(e);
  });
  return out;
}

export const HISTORY_HEADER = "# wba-keys-history v1: time, added|removed, directory, keyid";

/**
 * What one run changed, as key-history lines (cli.ts appends them to
 * <out>.history). Kept so that "was this key listed under that directory at
 * that time?" is a lookup when a signature has to be attributed later. A
 * keyid is the key's own thumbprint, so the same keyid is the same key.
 */
export function historyLines(previous: StoreEntry[], next: StoreEntry[], at: Date): string[] {
  const id = (e: StoreEntry) => `${e.identifier}\t${e.keyid}`;
  const before = new Set(previous.map(id)), after = new Set(next.map(id));
  const t = at.toISOString();
  const lines: string[] = [];
  for (const k of [...after].sort()) if (!before.has(k)) lines.push(`${t}\tadded\t${k}`);
  for (const k of [...before].sort()) if (!after.has(k)) lines.push(`${t}\tremoved\t${k}`);
  return lines;
}

/** Append to the key history in one write, never through a symlink. */
export function appendHistory(path: string, lines: string[]): void {
  if (lines.length === 0) return;
  const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o644);
  try {
    const head = fstatSync(fd).size === 0 ? HISTORY_HEADER + "\n" : "";
    writeSync(fd, head + lines.join("\n") + "\n");
  } finally {
    closeSync(fd);
  }
}

/** Write via a temp file in the same directory, fsync, then rename: readers see old or new, never partial. */
export function writeAtomic(path: string, text: string): void {
  const tmp = `${path}.tmp-${process.pid}`;
  rmSync(tmp, { force: true }); // a stale temp from a crashed run
  const fd = openSync(tmp, "wx", 0o644); // O_EXCL: never follow a planted symlink
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, path);
  } catch (err) {
    unlinkSync(tmp);
    throw err;
  }
}
