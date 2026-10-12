// gen.ts: differential vectors for @query-param (RFC 9421 2.2.8), with the
// runtime's WHATWG URLSearchParams as the independent oracle for the URL
// Standard's form parsing and percent-encode set.
//
//   bun lua/tests/query-param/gen.ts > lua/tests/query-param/vectors.tsv
//
// Each line: query <TAB> encoded name <TAB> expected component value, or
// "!" when the name occurs more than once (2.2.8: MUST NOT be included).
// URLSearchParams serializes with the URL Standard's form encoding, which is
// exactly RFC 9421 2.2.8 step 2 (spaces as "+"), so its output is used as is.
// Queries are ASCII: a request target cannot carry raw non-ASCII bytes.

// Deterministic PRNG (mulberry32) so the file regenerates byte for byte.
let seed = 0x9421;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T>(xs: T[]): T => xs[Math.floor(rand() * xs.length)];

const atoms = [
  "a", "b", "q", "Z", "0", "9", "*", "-", ".", "_", "~", "!", "'", "(", ")", "+", "=", "&",
  "%", "%2", "%2B", "%2b", "%20", "%25", "%3D", "%26", "%zz", "%0A", "%7F", "%80", "%FF",
  "%C3%A7", "%E2%82%AC", "%E2%82", "%C0%80", "%ED%A0%80", "%F0%9F%98%80", "%F4%90%80%80",
  "%EF%BB%BF", ",", ";", ":", "@", "/", "?", "$", "[", "]", "|", "^", "`", "{", "}", "\"", "<", ">", "#",
];

const lines = new Set<string>();
for (let n = 0; n < 3000; n++) {
  let query = "";
  const len = 1 + Math.floor(rand() * 12);
  for (let i = 0; i < len; i++) query += pick(atoms);
  if (query.includes("#")) continue; // never part of a request target
  // The constructor strips one leading "?" (URLSearchParams init); a leading
  // "&" is an empty sequence the form parser skips, so the parser sees `query`.
  const pairs = [...new URLSearchParams("&" + query)];
  const counts = new Map<string, number>();
  const encoded = pairs.map(([k, v]) => {
    const e = new URLSearchParams([[k, v]]).toString(); // "name=value", form set, "+" for space
    const i = e.indexOf("=");
    const name = e.slice(0, i);
    counts.set(name, (counts.get(name) ?? 0) + 1);
    return [name, e.slice(i + 1)];
  });
  for (const [name, value] of encoded) {
    lines.add(`${query}\t${name}\t${counts.get(name) === 1 ? value : "!"}`);
  }
}
process.stdout.write([...lines].join("\n") + "\n");
