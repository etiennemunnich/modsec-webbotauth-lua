// sf.ts: RFC 9651 Structured Field Values, parsing (4.2) and serialization
// (4.1), step for step. key-sync reads a directory response's
// Signature-Input, Signature and Content-Digest with it, and rebuilds the RFC
// 9421 signature base (the @signature-params line is a serialization).
// Checked against the HTTP Working Group's corpus (lua/tests/sf-corpus) by
// proof.test.ts: every parse record, on Bun and Node.
//
// A Decimal keeps its exact value in thousandths (`milli`), since RFC 9651
// allows at most three fractional digits; serializing never goes through a
// binary float.

type Bare =
  | { type: "integer"; value: number }
  | { type: "decimal"; value: number; milli: number }
  | { type: "string" | "token" | "displaystring"; value: string }
  | { type: "binary"; value: Uint8Array }
  | { type: "boolean"; value: boolean }
  | { type: "date"; value: number };
type Params = Map<string, Bare>;
export interface Item { kind: "item"; value: Bare; params: Params }
export interface InnerList { kind: "inner-list"; items: Item[]; params: Params }
export type Member = Item | InnerList;
export type Dictionary = Map<string, Member>;

const DIGIT = /[0-9]/, LCALPHA = /[a-z]/, ALPHA = /[A-Za-z]/;
const KEY_CHAR = /[a-z0-9_\-.*]/;
const TCHAR = /[!#$%&'*+\-.^_`|~0-9A-Za-z:/]/; // RFC 9110 tchar, plus ":" and "/" (4.2.6)

class Parser {
  s: string;
  i = 0;
  constructor(s: string) {
    // 4.2 step 1: the input is ASCII, or parsing fails.
    if (/[^\x00-\x7f]/.test(s)) throw new SyntaxError("structured field: not ASCII"); // eslint-disable-line no-control-regex -- refuses a field that is not ASCII
    this.s = s;
  }
  fail(why: string): never { throw new SyntaxError(`structured field: ${why} at ${this.i}`); }
  c(): string | undefined { return this.s[this.i]; }
  sp() { while (this.c() === " ") this.i++; }
  ows() { while (this.c() === " " || this.c() === "\t") this.i++; }
  end() { this.sp(); if (this.i < this.s.length) this.fail("trailing characters"); }

  // 4.2.1
  list(): Member[] {
    const out: Member[] = [];
    while (this.i < this.s.length) {
      out.push(this.itemOrInnerList());
      this.ows();
      if (this.i >= this.s.length) return out;
      if (this.c() !== ",") this.fail("expected ','");
      this.i++;
      this.ows();
      if (this.i >= this.s.length) this.fail("trailing ','");
    }
    return out;
  }
  itemOrInnerList(): Member { return this.c() === "(" ? this.innerList() : this.item(); }
  // 4.2.1.2
  innerList(): InnerList {
    if (this.c() !== "(") this.fail("expected '('");
    this.i++;
    const items: Item[] = [];
    while (this.i < this.s.length) {
      this.sp();
      if (this.c() === ")") {
        this.i++;
        return { kind: "inner-list", items, params: this.params() };
      }
      items.push(this.item());
      if (this.c() !== " " && this.c() !== ")") this.fail("expected SP or ')'");
    }
    this.fail("unterminated inner list");
  }
  // 4.2.2
  dictionary(): Dictionary {
    const out: Dictionary = new Map();
    while (this.i < this.s.length) {
      const k = this.key();
      let member: Member;
      if (this.c() === "=") {
        this.i++;
        member = this.itemOrInnerList();
      } else {
        member = { kind: "item", value: { type: "boolean", value: true }, params: this.params() };
      }
      out.set(k, member); // a repeated key overwrites the value, in its first place
      this.ows();
      if (this.i >= this.s.length) return out;
      if (this.c() !== ",") this.fail("expected ','");
      this.i++;
      this.ows();
      if (this.i >= this.s.length) this.fail("trailing ','");
    }
    return out;
  }
  // 4.2.3
  item(): Item { const value = this.bare(); return { kind: "item", value, params: this.params() }; }
  // 4.2.3.1
  bare(): Bare {
    const c = this.c();
    if (c === undefined) this.fail("expected a bare item");
    if (c === "-" || DIGIT.test(c)) return this.number();
    if (c === '"') return { type: "string", value: this.string() };
    if (c === "*" || ALPHA.test(c)) return { type: "token", value: this.token() };
    if (c === ":") return { type: "binary", value: this.binary() };
    if (c === "?") return { type: "boolean", value: this.boolean() };
    if (c === "@") {
      this.i++;
      const n = this.number();
      if (n.type !== "integer") this.fail("a Date is an Integer");
      return { type: "date", value: n.value };
    }
    if (c === "%") return { type: "displaystring", value: this.displayString() };
    this.fail("unexpected character");
  }
  // 4.2.3.2
  params(): Params {
    const out: Params = new Map();
    while (this.c() === ";") {
      this.i++;
      this.sp();
      const k = this.key();
      let v: Bare = { type: "boolean", value: true };
      if (this.c() === "=") { this.i++; v = this.bare(); }
      out.set(k, v);
    }
    return out;
  }
  // 4.2.3.3
  key(): string {
    const start = this.i;
    if (this.c() === undefined || !(this.c() === "*" || LCALPHA.test(this.c() ?? ""))) this.fail("bad key");
    while (this.c() !== undefined && KEY_CHAR.test(this.c() ?? "")) this.i++;
    return this.s.slice(start, this.i);
  }
  // 4.2.4
  number(): Bare {
    let decimal = false, sign = 1, digits = "";
    if (this.c() === "-") { this.i++; sign = -1; }
    if (this.c() === undefined || !DIGIT.test(this.c() ?? "")) this.fail("expected a digit");
    while (this.c() !== undefined) {
      const c = this.c() ?? "";
      if (DIGIT.test(c)) digits += c;
      else if (!decimal && c === ".") {
        if (digits.length > 12) this.fail("too many integer digits");
        digits += c;
        decimal = true;
      } else break;
      this.i++;
      if (!decimal && digits.length > 15) this.fail("Integer too long");
      if (decimal && digits.length > 16) this.fail("Decimal too long");
    }
    if (!decimal) return { type: "integer", value: sign * Number(digits) };
    const [whole, frac] = digits.split(".");
    if (frac.length === 0 || frac.length > 3) this.fail("bad Decimal fraction");
    const milli = sign * (Number(whole) * 1000 + Number(frac.padEnd(3, "0")));
    return { type: "decimal", value: milli / 1000, milli };
  }
  // 4.2.5
  string(): string {
    this.i++; // '"'
    let out = "";
    while (this.i < this.s.length) {
      const c = this.s[this.i++];
      if (c === "\\") {
        const n = this.s[this.i++];
        if (n !== '"' && n !== "\\") this.fail("bad escape");
        out += n;
      } else if (c === '"') return out;
      else if (c < " " || c > "~") this.fail("bad String character");
      else out += c;
    }
    this.fail("unterminated String");
  }
  // 4.2.6
  token(): string {
    const start = this.i;
    this.i++;
    while (this.c() !== undefined && TCHAR.test(this.c() ?? "")) this.i++;
    return this.s.slice(start, this.i);
  }
  // 4.2.7: RFC 4648 base64; missing padding and non-zero pad bits tolerated, as 4.2.7 allows.
  binary(): Uint8Array {
    this.i++; // ':'
    const close = this.s.indexOf(":", this.i);
    if (close < 0) this.fail("unterminated Byte Sequence");
    const b64 = this.s.slice(this.i, close);
    this.i = close + 1;
    if (/[^A-Za-z0-9+/=]/.test(b64)) this.fail("bad Byte Sequence character");
    const data = b64.replace(/=+$/, "");
    // Missing or partial padding is synthesized; more "=" than the length
    // needs is not base64 (RFC 4648 3.2), nor is "=" inside the data.
    if (data.includes("=") || data.length % 4 === 1 || b64.length - data.length > (4 - (data.length % 4)) % 4) {
      this.fail("bad base64");
    }
    let bin: string;
    try { bin = atob(data); } catch { this.fail("bad base64"); }
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  }
  // 4.2.8
  boolean(): boolean {
    this.i++; // '?'
    const c = this.s[this.i++];
    if (c === "1") return true;
    if (c === "0") return false;
    this.fail("bad Boolean");
  }
  // 4.2.10
  displayString(): string {
    this.i++; // '%'
    if (this.s[this.i++] !== '"') this.fail("expected '\"'");
    const bytes: number[] = [];
    while (this.i < this.s.length) {
      const c = this.s[this.i++];
      if (c < " " || c > "~") this.fail("bad Display String character");
      if (c === "%") {
        const h = this.s.slice(this.i, this.i + 2);
        if (!/^[0-9a-f]{2}$/.test(h)) this.fail("bad percent-encoding");
        bytes.push(parseInt(h, 16));
        this.i += 2;
      } else if (c === '"') {
        try { return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes)); } catch { this.fail("not UTF-8"); }
      } else bytes.push(c.charCodeAt(0));
    }
    this.fail("unterminated Display String");
  }
}

function top<T>(input: string, f: (p: Parser) => T): T {
  const p = new Parser(input);
  p.sp();
  const out = f(p);
  p.end();
  return out;
}

export const parseDictionary = (input: string): Dictionary => top(input, (p) => p.dictionary());
export const parseList = (input: string): Member[] => top(input, (p) => p.list());
export const parseItem = (input: string): Item => top(input, (p) => p.item());

// --- Serialization (4.1) -------------------------------------------------------

function fail(why: string): never { throw new TypeError(`structured field: cannot serialize: ${why}`); }

function serializeKey(k: string): string {
  if (!/^[a-z*][a-z0-9_\-.*]*$/.test(k)) fail(`key ${JSON.stringify(k)}`);
  return k;
}

function serializeBare(b: Bare): string {
  switch (b.type) {
    case "integer":
      if (!Number.isSafeInteger(b.value) || Math.abs(b.value) > 999_999_999_999_999) fail("Integer out of range");
      return String(b.value);
    case "decimal": {
      const m = Math.abs(b.milli), whole = Math.trunc(m / 1000);
      if (whole > 999_999_999_999) fail("Decimal out of range");
      const frac = String(m % 1000).padStart(3, "0").replace(/0+$/, "") || "0";
      return `${b.milli < 0 ? "-" : ""}${whole}.${frac}`;
    }
    case "string":
      if (/[^\x20-\x7e]/.test(b.value)) fail("String character");
      return `"${b.value.replace(/[\\"]/g, (c) => "\\" + c)}"`;
    case "token":
      if (!/^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*$/.test(b.value)) fail("Token");
      return b.value;
    case "binary": {
      let s = "";
      for (const x of b.value) s += String.fromCharCode(x);
      return `:${btoa(s)}:`;
    }
    case "boolean": return b.value ? "?1" : "?0";
    case "date":
      if (!Number.isSafeInteger(b.value) || Math.abs(b.value) > 999_999_999_999_999) fail("Date out of range");
      return `@${b.value}`;
    case "displaystring": {
      let out = '%"';
      for (const x of new TextEncoder().encode(b.value)) {
        out += x === 0x25 || x === 0x22 || x < 0x20 || x > 0x7e ? "%" + x.toString(16).padStart(2, "0") : String.fromCharCode(x);
      }
      return out + '"';
    }
  }
}

function serializeParams(ps: Params): string {
  let out = "";
  for (const [k, v] of ps) out += ";" + serializeKey(k) + (v.type === "boolean" && v.value ? "" : "=" + serializeBare(v));
  return out;
}

export const serializeItem = (it: Item) => serializeBare(it.value) + serializeParams(it.params);

export function serializeMember(m: Member): string {
  if (m.kind === "item") return serializeItem(m);
  return `(${m.items.map(serializeItem).join(" ")})` + serializeParams(m.params);
}

export const serializeList = (l: Member[]) => l.map(serializeMember).join(", ");

export function serializeDictionary(d: Dictionary): string {
  return [...d].map(([k, m]) => serializeKey(k)
    + (m.kind === "item" && m.value.type === "boolean" && m.value.value ? serializeParams(m.params) : "=" + serializeMember(m))).join(", ");
}
