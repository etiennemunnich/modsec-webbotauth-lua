// gen.ts: differential vectors for coding.lua (RFC 1950, 1951, 1952), with
// zlib as the oracle: every input's expected outcome is what the runtime's
// zlib (node:zlib) does with it, never what coding.lua does.
//
//   node --experimental-strip-types lua/tests/coding/gen.ts > lua/tests/coding/vectors.tsv
//   bun lua/tests/coding/gen.ts --check lua/tests/coding/vectors.tsv
//   node --experimental-strip-types lua/tests/coding/gen.ts --check lua/tests/coding/vectors.tsv
//
// Each line: name <TAB> raw|zlib|gzip <TAB> input hex <TAB> expected, where
// expected is "ok <length> <sha-256 hex>" or "err". --check decodes every
// committed input with this runtime's zlib and fails on any disagreement:
// Node bundles zlib 1.2.12 (Chromium's), Bun a different zlib build, so the
// file is checked by two decoders. Compressed bytes differ between those
// builds (and Chromium's by CPU), so the file is committed, not regenerated
// in CI.
//
// Inputs: zlib's own output over many parameters; hand-built streams that
// hit each RFC 1951 error path (and the edge cases zlib accepts); every
// truncation and every single-bit flip of small streams; random bytes.
// Not here, because zlib-based runtimes disagree with RFC 1952's text:
// trailing bytes after a gzip member (Node skips trailing zeros). Those
// expectations are written out in test_coding.lua with the clause.
import * as zlib from "node:zlib";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

type Kind = "raw" | "zlib" | "gzip";
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

function oracle(kind: Kind, input: Buffer): string {
  try {
    const out = kind === "raw" ? zlib.inflateRawSync(input) : kind === "zlib" ? zlib.inflateSync(input) : zlib.gunzipSync(input);
    return `ok ${out.length} ${sha(out)}`;
  } catch {
    return "err";
  }
}

if (process.argv[2] === "--check") {
  let n = 0, bad = 0;
  for (const line of readFileSync(process.argv[3], "utf8").split("\n")) {
    if (line === "" || line.startsWith("#")) continue;
    const [name, kind, hex, want] = line.split("\t");
    const got = oracle(kind as Kind, Buffer.from(hex, "hex"));
    n++;
    if (got !== want) { bad++; console.error(`disagree: ${name}: file ${want}, zlib ${got}`); }
  }
  console.log(`${n} vectors, ${bad} disagreements (${typeof (globalThis as any).Bun !== "undefined" ? "bun" : "node"} zlib)`);
  process.exit(bad === 0 && n > 0 ? 0 : 1);
}

// Deterministic PRNG (mulberry32).
let seed = 0x9530;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const randBytes = (n: number) => Buffer.from(Array.from({ length: n }, () => Math.floor(rand() * 256)));

const lines: string[] = [];
const names = new Set<string>();
function add(name: string, kind: Kind, input: Buffer) {
  if (names.has(name)) throw new Error("duplicate " + name);
  names.add(name);
  lines.push([name, kind, input.toString("hex"), oracle(kind, input)].join("\t"));
}

// 1. zlib's own output.
const words = ["GET", "POST", "agent", "signature", "{", "}", '"', ":", ",", "\n", "web-bot-auth", " ", "0", "1", "digest"];
const plain: [string, Buffer][] = [
  ["empty", Buffer.alloc(0)],
  ["one", Buffer.from("a")],
  ["hello-lf", Buffer.from('{"hello": "world"}\n')],
  ["words", Buffer.from(Array.from({ length: 4000 }, () => words[Math.floor(rand() * words.length)]).join(""))],
  ["random", randBytes(3000)],
  ["runs", Buffer.from(Array.from({ length: 12000 }, (_, i) => (Math.floor(i / 97) % 3 === 0 ? 0x41 : Math.floor(rand() * 4) + 0x61)))],
  ["zeros", Buffer.alloc(70000)], // past the 64 KiB ring, so output is flushed mid-stream
  ["long-distance", (() => { // zlib's longest distance is 32506 (MAX_DIST); craft-dist-32768 goes further
    const r = randBytes(300);
    const filler = Buffer.from(Array.from({ length: 12000 }, () => words[Math.floor(rand() * words.length)]).join("")).subarray(0, 32000);
    return Buffer.concat([r, filler, r]);
  })()],
];
const params: [string, zlib.ZlibOptions][] = [
  ["l0", { level: 0 }], ["l1", { level: 1 }], ["l6", { level: 6 }], ["l9", { level: 9 }],
  ["huffman", { strategy: zlib.constants.Z_HUFFMAN_ONLY }], ["rle", { strategy: zlib.constants.Z_RLE }],
  ["fixed", { strategy: zlib.constants.Z_FIXED }], ["filtered", { strategy: zlib.constants.Z_FILTERED }],
  ["w9", { windowBits: 9 }], ["w12m1", { windowBits: 12, memLevel: 1 }],
];
for (const [pn, p] of plain) {
  // Large inputs: the parameters that keep the vectors small (stored blocks are test_coding.lua's).
  const ps = p.length > 10000 ? params.filter(([qn]) => ["l1", "l6", "l9", "rle"].includes(qn)) : params;
  for (const [qn, q] of ps) add(`zlib-${pn}-${qn}-raw`, "raw", zlib.deflateRawSync(p, q));
  add(`zlib-${pn}-zlib`, "zlib", zlib.deflateSync(p));
  add(`zlib-${pn}-gzip`, "gzip", zlib.gzipSync(p));
}

// Many blocks: a stream flushed after every write (Z_SYNC_FLUSH puts an empty
// stored block after each), and one with Z_FULL_FLUSH.
async function flushed(kind: "raw" | "gzip", flush: number, parts: Buffer[]): Promise<Buffer> {
  const z = kind === "raw" ? zlib.createDeflateRaw() : zlib.createGzip();
  const out: Buffer[] = [];
  const ended = new Promise<void>((r) => z.on("end", () => r()));
  z.on("data", (d: Buffer) => out.push(d));
  for (const part of parts) {
    z.write(part);
    await new Promise<void>((r) => z.flush(flush, () => r()));
  }
  z.end();
  await ended;
  return Buffer.concat(out);
}
const parts = Array.from({ length: 40 }, (_, i) => Buffer.from(`part ${i}: ${"x".repeat(i * 7)} ${words.join("")}\n`));
add("flush-sync-raw", "raw", await flushed("raw", zlib.constants.Z_SYNC_FLUSH, parts));
add("flush-full-raw", "raw", await flushed("raw", zlib.constants.Z_FULL_FLUSH, parts));
add("flush-sync-gzip", "gzip", await flushed("gzip", zlib.constants.Z_SYNC_FLUSH, parts));

// 2. Hand-built RFC 1951 streams.
class Bits {
  bytes: number[] = []; acc = 0; n = 0;
  put(v: number, n: number) { // LSB first (RFC 1951 3.1.1)
    for (let i = 0; i < n; i++) {
      this.acc |= ((v >>> i) & 1) << this.n;
      if (++this.n === 8) { this.bytes.push(this.acc); this.acc = 0; this.n = 0; }
    }
  }
  code(c: number, len: number) { for (let i = len - 1; i >= 0; i--) this.put((c >>> i) & 1, 1); } // MSB first
  align() { if (this.n) { this.bytes.push(this.acc); this.acc = 0; this.n = 0; } }
  buf() { this.align(); return Buffer.from(this.bytes); }
}
// Canonical codes from lengths (RFC 1951 3.2.2).
function canon(lens: number[]): number[] {
  const count = new Array(16).fill(0), next = new Array(16).fill(0), codes = new Array(lens.length).fill(0);
  for (const l of lens) if (l) count[l]++;
  let code = 0;
  for (let b = 1; b <= 15; b++) { code = (code + count[b - 1]) << 1; next[b] = code; }
  lens.forEach((l, s) => { if (l) codes[s] = next[l]++; });
  return codes;
}
function fixedLit(b: Bits, s: number) {
  if (s < 144) b.code(0x30 + s, 8); else if (s < 256) b.code(0x190 + s - 144, 9);
  else if (s < 280) b.code(s - 256, 7); else b.code(0xc0 + s - 280, 8);
}
const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
function lenSym(len: number): [number, number, number] { // symbol, extra value, extra bits
  for (let i = 28; i >= 0; i--) if (len >= LBASE[i]) return [257 + i, len - LBASE[i], LEXT[i]];
  throw new Error("len");
}
function distSym(d: number): [number, number, number] {
  for (let i = 29; i >= 0; i--) if (d >= DBASE[i]) return [i, d - DBASE[i], DEXT[i]];
  throw new Error("dist");
}
type Op = number | [number, number]; // literal, or [length, distance]
function fixedBlock(b: Bits, ops: Op[], last = 1) {
  b.put(last, 1); b.put(1, 2);
  for (const op of ops) {
    if (typeof op === "number") { fixedLit(b, op); continue; }
    const [ls, lv, lx] = lenSym(op[0]); fixedLit(b, ls); b.put(lv, lx);
    const [ds, dv, dx] = distSym(op[1]); b.code(ds, 5); b.put(dv, dx);
  }
  fixedLit(b, 256);
}
const CLORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
// A complete code length code: 13 symbols of 4 bits, 6 of 5 bits.
const CL_OK = Array.from({ length: 19 }, (_, s) => (s >= 13 ? 5 : 4));
interface Dyn { lit: number[]; dist: number[]; cl?: number[]; clsyms?: [number, number?][]; nlen?: number; ndist?: number; ncode?: number; last?: number }
// A dynamic block header; clsyms overrides the code length symbols written
// (each [symbol, extra]); otherwise every length is written as is.
function dynHeader(b: Bits, d: Dyn) {
  const nlen = d.nlen ?? d.lit.length, ndist = d.ndist ?? d.dist.length, cl = d.cl ?? CL_OK;
  const ncode = d.ncode ?? 19;
  b.put(d.last ?? 1, 1); b.put(2, 2);
  b.put(nlen - 257, 5); b.put(ndist - 1, 5); b.put(ncode - 4, 4);
  for (let i = 0; i < ncode; i++) b.put(cl[CLORDER[i]], 3);
  const clc = canon(cl);
  const syms: [number, number?][] = d.clsyms ?? [...d.lit, ...d.dist].map((l) => [l]);
  for (const [s, x] of syms) {
    b.code(clc[s], cl[s]);
    if (s === 16) b.put(x!, 2); else if (s === 17) b.put(x!, 3); else if (s === 18) b.put(x!, 7);
  }
}
function dynData(b: Bits, d: Dyn, ops: Op[]) {
  const lc = canon(d.lit), dc = canon(d.dist);
  for (const op of ops) {
    if (typeof op === "number") { b.code(lc[op], d.lit[op]); continue; }
    const [ls, lv, lx] = lenSym(op[0]); b.code(lc[ls], d.lit[ls]); b.put(lv, lx);
    const [ds, dv, dx] = distSym(op[1]); b.code(dc[ds], d.dist[ds]); b.put(dv, dx);
  }
  b.code(lc[256], d.lit[256]);
}
function dyn(d: Dyn, ops: Op[]): Buffer { const b = new Bits(); dynHeader(b, d); dynData(b, d, ops); return b.buf(); }
// Complete codes over every symbol: literal/length 0..225 at 8 bits and
// 226..285 at 9 (226/256 + 60/512 = 1); distance 0..1 at 4 bits and 2..29
// at 5 (2/16 + 28/32 = 1).
const L = () => Array.from({ length: 286 }, (_, s) => (s < 226 ? 8 : 9));
const D = () => Array.from({ length: 30 }, (_, s) => (s < 2 ? 4 : 5));
const T = [...Buffer.from("web bot auth ")];
const rawCase = (name: string, buf: Buffer) => add(`craft-${name}`, "raw", buf);
{
  const b = new Bits(); fixedBlock(b, [...T, [13, 13], [258, 26]]); rawCase("fixed-ok", b.buf());
}
{ const b = new Bits(); fixedBlock(b, []); rawCase("fixed-empty", b.buf()); }
{ const b = new Bits(); fixedBlock(b, [65, [3, 1]]); rawCase("fixed-dist-eq-output", b.buf()); }
{ const b = new Bits(); fixedBlock(b, [65, [3, 2]]); rawCase("fixed-dist-too-far", b.buf()); }
{ const b = new Bits(); fixedBlock(b, [[3, 1]]); rawCase("fixed-dist-at-start", b.buf()); }
for (const s of [286, 287]) {
  const b = new Bits(); b.put(1, 1); b.put(1, 2); fixedLit(b, 65); fixedLit(b, s); b.code(0, 5); fixedLit(b, 256); rawCase(`fixed-lit-${s}`, b.buf());
}
for (const d of [30, 31]) {
  const b = new Bits(); b.put(1, 1); b.put(1, 2); fixedLit(b, 65); fixedLit(b, 257); b.code(d, 5); fixedLit(b, 256); rawCase(`fixed-dist-${d}`, b.buf());
}
{ // length 258 spelt 284 + 31 extra (RFC 1951 leaves it unused; zlib accepts it)
  const b = new Bits(); b.put(1, 1); b.put(1, 2); fixedLit(b, 66); fixedLit(b, 284); b.put(31, 5); b.code(0, 5); fixedLit(b, 256); rawCase("fixed-284-plus-31", b.buf());
}
{ // Distance 32768, the largest (RFC 1951 3.2.5), over a history with period
  // 251, so a window off by any multiple of 256 gives different bytes.
  const ops: Op[] = Array.from({ length: 251 }, (_, i) => i);
  for (let n = 251; n < 33000; n += 258) ops.push([258, 251]);
  ops.push([258, 32768], [3, 32768], [258, 32767]);
  const b = new Bits(); fixedBlock(b, ops); rawCase("dist-32768", b.buf());
  const c = new Bits(); fixedBlock(c, [0, 1, [258, 1], [258, 32768]]); rawCase("dist-32768-too-far", c.buf());
}
{ const b = new Bits(); b.put(1, 1); b.put(3, 2); rawCase("block-type-3", b.buf()); }
{ const b = new Bits(); b.put(0, 1); b.put(1, 2); fixedLit(b, 65); fixedLit(b, 256); rawCase("not-final-then-end", b.buf()); }
// Stored blocks (RFC 1951 3.2.4).
const stored = (data: Buffer, last = 1, nlenXor = 0) => {
  const b = new Bits(); b.put(last, 1); b.put(0, 2); b.align();
  return Buffer.concat([b.buf(), Buffer.from([data.length & 255, data.length >> 8, (~data.length & 255) ^ nlenXor, (~data.length >> 8) & 255]), data]);
};
rawCase("stored-ok", stored(Buffer.from("stored bytes")));
rawCase("stored-empty", stored(Buffer.alloc(0)));
rawCase("stored-nlen-mismatch", stored(Buffer.from("x"), 1, 1));
rawCase("stored-short", stored(Buffer.from("stored bytes")).subarray(0, 10));
rawCase("stored-then-fixed", (() => { const b = new Bits(); b.put(0, 1); b.put(0, 2); b.align(); const h = b.buf(); const s = Buffer.from("abcabc"); const f = new Bits(); fixedBlock(f, [[6, 6]]); return Buffer.concat([h, Buffer.from([6, 0, 0xf9, 0xff]), s, f.buf()]); })());
// Dynamic blocks (RFC 1951 3.2.7).
rawCase("dyn-ok", dyn({ lit: L(), dist: D() }, [...T, [20, 7], [258, 1]]));
rawCase("dyn-oversubscribed-lit", dyn({ lit: L().map((l, s) => (s === 0 ? 7 : l)), dist: D() }, [65]));
rawCase("dyn-incomplete-lit", dyn({ lit: L().map((l, s) => (s === 5 ? 0 : l)), dist: D() }, [65]));
rawCase("dyn-oversubscribed-dist", dyn({ lit: L(), dist: D().map((l, s) => (s === 3 ? 3 : l)) }, [65]));
rawCase("dyn-incomplete-dist", dyn({ lit: L(), dist: D().map((l, s) => (s === 3 ? 0 : l)) }, [65]));
{ // Only end-of-block, a single one-bit code: incomplete, which zlib allows.
  const lit = new Array(257).fill(0); lit[256] = 1;
  rawCase("dyn-single-eob", dyn({ lit, dist: [0] }, []));
  rawCase("dyn-single-eob-one-dist", dyn({ lit, dist: [1] }, []));
}
{ // One distance code of one bit: allowed; its unused pattern is not.
  const lit = L();
  rawCase("dyn-one-dist-code", dyn({ lit, dist: [1] }, [65, [3, 1]]));
  const b = new Bits(); dynHeader(b, { lit, dist: [1] });
  const lc = canon(lit); b.code(lc[65], lit[65]); const [ls] = lenSym(3); b.code(lc[ls], lit[ls]); b.put(1, 1); b.code(lc[256], lit[256]);
  rawCase("dyn-one-dist-code-unused-pattern", b.buf());
}
rawCase("dyn-no-dist-codes", dyn({ lit: L(), dist: [0] }, [...T]));
{ // No distance codes, and a match anyway.
  const lit = L(); const b = new Bits(); dynHeader(b, { lit, dist: [0] });
  const lc = canon(lit); b.code(lc[65], lit[65]); const [ls] = lenSym(3); b.code(lc[ls], lit[ls]); b.put(0, 15); b.code(lc[256], lit[256]);
  rawCase("dyn-no-dist-codes-match", b.buf());
}
rawCase("dyn-missing-eob", dyn({ lit: L().map((l, s) => (s === 256 ? 0 : s === 255 ? 8 : l)), dist: D() }, [65]));
rawCase("dyn-nlen-287", dyn({ lit: [...L(), 0], dist: D() }, [65]));
rawCase("dyn-nlen-288", dyn({ lit: [...L(), 0, 0], dist: D() }, [65]));
rawCase("dyn-ndist-31", dyn({ lit: L(), dist: [...D(), 0] }, [65]));
rawCase("dyn-ndist-32", dyn({ lit: L(), dist: [...D(), 0, 0] }, [65]));
{
  const lit = L(), dist = D();
  const each = (ls: number[]) => ls.map((l): [number, number?] => [l]);
  rawCase("dyn-repeat-16-first", dyn({ lit, dist, clsyms: [[16, 0], ...each([...lit, ...dist]).slice(3)] }, [65]));
  // 18 (11..138 zeros) running past nlen + ndist.
  rawCase("dyn-repeat-overflow", dyn({ lit, dist, clsyms: [...each([...lit, ...dist]).slice(0, 311), [18, 0]] }, [65]));
  // A repeat may run from the literal/length lengths into the distance ones
  // (RFC 1951 3.2.7: "one sequence of HLIT + HDIST + 258 values").
  const lit2 = Array.from({ length: 286 }, (_, s) => (s < 228 ? 8 : s < 284 ? 9 : 0)); // 228/256 + 56/512 = 1
  const dist2 = Array.from({ length: 30 }, (_, s) => (s === 3 || s === 4 ? 1 : 0));
  rawCase("dyn-repeat-crosses-into-dist", dyn({ lit: lit2, dist: dist2, clsyms: [...each(lit2.slice(0, 284)), [17, 2], [1], [1], [18, 14]] },
    [97, 98, 99, 100, [3, 4]]));
}
rawCase("dyn-cl-incomplete", dyn({ lit: L(), dist: D(), cl: CL_OK.map((l, s) => (s === 18 ? 0 : l)) }, [65]));
rawCase("dyn-cl-oversubscribed", dyn({ lit: L(), dist: D(), cl: CL_OK.map((l, s) => (s === 18 ? 3 : l)) }, [65]));
rawCase("dyn-cl-all-zero", (() => { const b = new Bits(); b.put(1, 1); b.put(2, 2); b.put(0, 5); b.put(0, 5); b.put(15, 4); for (let i = 0; i < 19; i++) b.put(0, 3); b.put(0, 32); return b.buf(); })());
rawCase("dyn-truncated-header", dyn({ lit: L(), dist: D() }, [65]).subarray(0, 20));
{ // Every used literal on a 15-bit code: decodes through the subtables.
  const lit = new Array(286).fill(0);
  // complete: lengths 1..14 for symbols 0..13, then two 15-bit codes (65 'A', 256 EOB)
  for (let s = 0; s < 14; s++) lit[s] = s + 1;
  lit[65] = 15; lit[256] = 15;
  rawCase("dyn-15-bit-literals", dyn({ lit, dist: [0] }, Array(300).fill(65)));
}
{ // Many empty blocks before the last: zlib accepts them.
  const b = new Bits();
  for (let i = 0; i < 50; i++) fixedBlock(b, [], 0);
  fixedBlock(b, [65]);
  rawCase("many-empty-fixed", b.buf());
  const s = new Bits(); for (let i = 0; i < 50; i++) { s.put(0, 1); s.put(0, 2); s.align(); s.put(0, 16); s.put(0xffff, 16); }
  fixedBlock(s, [65]);
  rawCase("many-empty-stored", s.buf());
  const d = new Bits(); for (let i = 0; i < 50; i++) { dynHeader(d, { lit: L(), dist: D(), last: 0 }); dynData(d, { lit: L(), dist: D() }, []); }
  fixedBlock(d, [65]);
  rawCase("many-empty-dynamic", d.buf());
}

// 3. Wrappers (RFC 1950, RFC 1952).
const hello = Buffer.from('{"hello": "world"}\n');
const deflated = zlib.deflateRawSync(hello);
const be32 = (n: number) => Buffer.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const le32 = (n: number) => Buffer.from([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]);
const adler = (b: Buffer) => { let a = 1, c = 0; for (const x of b) { a = (a + x) % 65521; c = (c + a) % 65521; } return ((c << 16) | a) >>> 0; };
const zhdr = (cmf: number, flg0: number) => { let flg = flg0 & 0xe0; flg |= 31 - (((cmf << 8) | flg) % 31); return Buffer.from([cmf, flg]); };
add("zlib-hdr-ok", "zlib", Buffer.concat([zhdr(0x78, 0), deflated, be32(adler(hello))]));
add("zlib-hdr-cinfo-0", "zlib", Buffer.concat([zhdr(0x08, 0), deflated, be32(adler(hello))]));
add("zlib-hdr-cinfo-8", "zlib", Buffer.concat([zhdr(0x88, 0), deflated, be32(adler(hello))]));
add("zlib-hdr-cm-7", "zlib", Buffer.concat([zhdr(0x77, 0), deflated, be32(adler(hello))]));
add("zlib-hdr-check-bad", "zlib", Buffer.concat([Buffer.from([0x78, 0x9d]), deflated, be32(adler(hello))]));
add("zlib-fdict", "zlib", Buffer.concat([zhdr(0x78, 0x20), be32(1), deflated, be32(adler(hello))]));
add("zlib-adler-bad", "zlib", Buffer.concat([zhdr(0x78, 0), deflated, be32(adler(hello) ^ 1)]));
add("zlib-adler-short", "zlib", Buffer.concat([zhdr(0x78, 0), deflated, be32(adler(hello)).subarray(0, 3)]));
add("zlib-raw-labelled-deflate", "zlib", deflated);
add("zlib-gzip-labelled-deflate", "zlib", zlib.gzipSync(hello));
add("gzip-zlib-labelled-gzip", "gzip", zlib.deflateSync(hello));
add("gzip-raw-labelled-gzip", "gzip", deflated);
const crc = (b: Buffer) => zlib.crc32(b) >>> 0;
function gz(flg: number, opts: { extra?: Buffer; name?: string; comment?: string; hcrcXor?: number; cm?: number; crcXor?: number; isizeAdd?: number; data?: Buffer } = {}) {
  const data = opts.data ?? hello;
  let h = Buffer.from([0x1f, 0x8b, opts.cm ?? 8, flg, 0, 0, 0, 0, 0, 255]);
  if (flg & 4) h = Buffer.concat([h, Buffer.from([opts.extra!.length & 255, opts.extra!.length >> 8]), opts.extra!]);
  if (flg & 8) h = Buffer.concat([h, Buffer.from(opts.name! + "\0", "latin1")]);
  if (flg & 16) h = Buffer.concat([h, Buffer.from(opts.comment! + "\0", "latin1")]);
  if (flg & 2) { const c = (crc(h) & 0xffff) ^ (opts.hcrcXor ?? 0); h = Buffer.concat([h, Buffer.from([c & 255, c >> 8])]); }
  return Buffer.concat([h, zlib.deflateRawSync(data), le32((crc(data) ^ (opts.crcXor ?? 0)) >>> 0), le32((data.length + (opts.isizeAdd ?? 0)) >>> 0)]);
}
add("gzip-plain", "gzip", gz(0));
add("gzip-fextra", "gzip", gz(4, { extra: Buffer.from("AB\x04\x00wxyz", "latin1") }));
add("gzip-fname", "gzip", gz(8, { name: "hello.json" }));
add("gzip-fcomment", "gzip", gz(16, { comment: "a=1&admin=true&" }));
add("gzip-fhcrc", "gzip", gz(2));
add("gzip-all-fields", "gzip", gz(2 | 4 | 8 | 16, { extra: Buffer.from("xy\x00\x00", "latin1"), name: "n", comment: "c" }));
add("gzip-fhcrc-bad", "gzip", gz(2, { hcrcXor: 1 }));
add("gzip-reserved-flag", "gzip", gz(0x20));
add("gzip-cm-7", "gzip", gz(0, { cm: 7 }));
add("gzip-bad-magic", "gzip", Buffer.concat([Buffer.from([0x1f, 0x8c]), gz(0).subarray(2)]));
add("gzip-crc-bad", "gzip", gz(0, { crcXor: 0x100 }));
add("gzip-isize-bad", "gzip", gz(0, { isizeAdd: 1 }));
add("gzip-fname-unterminated", "gzip", gz(8, { name: "x" }).subarray(0, 12));
add("gzip-fextra-short", "gzip", Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 255, 200, 0]), Buffer.from("ab")]));
add("gzip-two-members", "gzip", Buffer.concat([gz(0), gz(8, { name: "two", data: Buffer.from("second member\n") })]));
add("gzip-member-empty-then-data", "gzip", Buffer.concat([zlib.gzipSync(Buffer.alloc(0)), gz(0)]));
add("gzip-empty-input", "gzip", Buffer.alloc(0));
// RFC 9530 Appendix A, Figure 2: {"hello": "world"} + LF, gzip-coded.
add("rfc9530-figure-2", "gzip", Buffer.from("1F8B08008841376400FFAB56CA48CDC9C957B252502ACF2FCA4951AAE50200D9E431E713000000", "hex"));
// draft-ietf-httpbis-unencoded-digest-05 6, Figure 2: "An unexceptional string" + LF.
add("unencoded-digest-05-figure-2", "gzip", Buffer.from("1f8b0800791f086400ff73cc5328cd4bad484e2d28c9cccf4bcc51282e29cacc4be702007eaf074418000000", "hex"));

// 4. Every truncation, and every single-bit flip, of small streams.
const seeds: [string, Kind, Buffer][] = [
  ["fixed", "raw", zlib.deflateRawSync(Buffer.from("web bot auth web bot auth signature"), { strategy: zlib.constants.Z_FIXED })],
  ["dynamic", "raw", zlib.deflateRawSync(Buffer.from(Array.from({ length: 90 }, () => words[Math.floor(rand() * 8)]).join("")))],
  ["stored", "raw", zlib.deflateRawSync(Buffer.from("stored!"), { level: 0 })],
  ["zlib", "zlib", zlib.deflateSync(hello)],
  ["gzip", "gzip", gz(2 | 4 | 8, { extra: Buffer.from("ab\x00\x00", "latin1"), name: "n" })],
];
for (const [sn, kind, s] of seeds) {
  for (let i = 0; i < s.length; i++) add(`cut-${sn}-${i}`, kind, s.subarray(0, i));
  for (let i = 0; i < s.length * 8; i++) {
    const m = Buffer.from(s); m[i >> 3] ^= 1 << (i & 7);
    add(`flip-${sn}-${i}`, kind, m);
  }
}

// 5. Random bytes, and random bytes behind a valid block header.
for (let i = 0; i < 300; i++) add(`random-raw-${i}`, "raw", randBytes(1 + Math.floor(rand() * 48)));
for (let i = 0; i < 300; i++) {
  const r = randBytes(2 + Math.floor(rand() * 64)); r[0] = (r[0] & ~7) | 5; // BFINAL=1, BTYPE=2 (dynamic)
  add(`random-dyn-${i}`, "raw", r);
}
for (let i = 0; i < 100; i++) { const r = randBytes(12 + Math.floor(rand() * 40)); r[0] = 0x78; r[1] = 0x9c; add(`random-zlib-${i}`, "zlib", r); }

console.log("# coding.lua differential vectors; generated by gen.ts, oracle: node:zlib. Do not edit.");
console.log(lines.join("\n"));
