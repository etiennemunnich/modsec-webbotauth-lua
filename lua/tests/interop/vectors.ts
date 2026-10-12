/**
 * vectors.ts: the request test vectors from the LATEST editor's copy of the
 * Web Bot Auth draft (github.com/webbotauth/draft-ietf-webbotauth-httpsig-protocol,
 * main branch), as JSON for vectors.lua. Prints {source, vectors: [...]} on
 * stdout; every vector found under "# Test Vectors" whose header block has a
 * Signature-Input is included, so a vector added upstream is tested without
 * a change here. The Signed Directory Response vector is a response, not a
 * request, and is reported as skipped.
 *
 *   bun vectors.ts                 (fetch main)
 *   bun vectors.ts <file.md>       (a local copy instead)
 */
const REPO = "webbotauth/draft-ietf-webbotauth-httpsig-protocol";
const FILE = "draft-ietf-webbotauth-httpsig-protocol.md";

async function source(): Promise<{ text: string; ref: string }> {
  const local = process.argv[2];
  if (local) return { text: await Bun.file(local).text(), ref: local };
  const headers: Record<string, string> = process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {};
  const commit = await fetch(`https://api.github.com/repos/${REPO}/commits/main`, { headers })
    .then((r) => (r.ok ? r.json() : null)).then((j) => (j as { sha?: string } | null)?.sha ?? "unknown")
    .catch(() => "unknown");
  const res = await fetch(`https://raw.githubusercontent.com/${REPO}/main/${FILE}`);
  if (!res.ok) throw new Error(`fetching the editor's copy: HTTP ${res.status}`);
  return { text: await res.text(), ref: `${REPO}@${commit}` };
}

/** RFC 8792 single-backslash unfolding: "\" at a line's end joins the next line, minus its indentation. */
const unfold = (block: string) => block.replace(/\\\n[ \t]*/g, "");

const { text, ref } = await source();
const start = text.search(/^# Test Vectors\s*$/m);
if (start < 0) throw new Error("no '# Test Vectors' section in the editor's copy");
const end = text.slice(start + 1).search(/^# (?!#)/m);
const section = end < 0 ? text.slice(start) : text.slice(start, start + 1 + end);

const vectors: { name: string; alg: string; agent: string; input: string; sig: string; created: number }[] = [];
const skipped: string[] = [];
let alg = "";
for (const part of section.split(/^(?=##+ )/m)) {
  const title = part.match(/^(##+) (.+?)(?:\s*\{#[^}]*\})?\s*$/m);
  if (!title) continue;
  if (title[1] === "##") { alg = /RSASSA-PSS/i.test(title[2]) ? "rsa-pss-sha512" : /EdDSA|ed25519/i.test(title[2]) ? "ed25519" : ""; continue; }
  const blocks = [...part.matchAll(/^~~~[^\n]*\n([\s\S]*?)^~~~/gm)].map((m) => unfold(m[1]));
  const hdr = blocks.find((b) => /^Signature-Input:/m.test(b));
  if (!hdr || !alg) { skipped.push(`${title[2]} (${alg ? "no request headers" : "unknown algorithm"})`); continue; }
  const field = (n: string) => hdr.match(new RegExp(`^${n}: (.*)$`, "m"))?.[1]?.trim() ?? "";
  const input = field("Signature-Input");
  // A response signature (a directory's Appendix B proof) covers request
  // components with ;req: not a request this verifier checks.
  if (/;req\b/.test(input)) { skipped.push(`${title[2]} (a response signature, ;req)`); continue; }
  vectors.push({
    name: `${alg}: ${title[2]}`, alg, agent: field("Signature-Agent"), input, sig: field("Signature"),
    created: Number(input.match(/;created=(\d+)/)?.[1] ?? 0),
  });
}
if (vectors.length === 0) throw new Error("no request vectors found: the section's layout changed");
console.log(JSON.stringify({ source: ref, vectors, skipped }, null, 1));

export {}; // a module, so the top-level await above is allowed
