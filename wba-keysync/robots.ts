// wba-robots: a suggested robots.txt from a bots file (bots.yaml): one group
// (RFC 9309 2.1) asking every bot whose policy is deny not to crawl. A
// robots.txt asks; it controls nothing. The rules lists.ts writes are what
// refuse. Merge the group into your own robots.txt as you see fit.
//
//   bun wba-keysync/robots.ts bots.yaml [--out robots.txt]
//
// A bot's product tokens are its `robots` field, or else its User-Agent
// tokens with a trailing "/" dropped. A token that is not one word (letters,
// digits, ".", "_", "-") is a User-Agent fragment, not a product token: it is
// left out and named in a comment. A bot named so that validate.ts would
// refuse it (a newline in its name would add a line of its own) fails the
// run.
//
// Bun only: YAML is read with Bun.YAML (robotsTxt itself runs anywhere).
// Exit codes: 0 written; 1 usage error, unreadable file or a bad name.

import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { writeAtomic } from "./keysync.ts";
import { nameProblem, show, type Bot } from "./validate.ts";

const asList = <T>(x: T | T[] | undefined): T[] => (x === undefined ? [] : Array.isArray(x) ? x : [x]);
const PRODUCT = /^[A-Za-z0-9._-]+$/;

/** The suggested robots.txt for the bots, from a file named source. */
export function robotsTxt(bots: Bot[], source: string, at = new Date()): string {
  const out = [
    `# Suggested by wba-keysync/robots.ts from ${source} on ${at.toISOString().slice(0, 10)}.`,
    "# robots.txt asks; it does not refuse anything. The WAF rules from lists.ts do.",
  ];
  const tokens: string[] = [], seen = new Set<string>(), skipped: string[] = [];
  for (const b of bots.filter((x) => x?.policy === "deny")) {
    const bad = nameProblem(b.name);
    if (bad) throw new Error(`${bad} (validate.ts checks every entry)`);
    const own = b.robots !== undefined ? asList(b.robots) : asList(b.user_agent).map((t) => (typeof t === "string" ? t.replace(/\/$/, "") : t));
    for (const t of own) {
      if (typeof t !== "string") { skipped.push(`${b.name}: ${show(t)}`); continue; }
      if (!PRODUCT.test(t)) { skipped.push(`${b.name}: ${show(t)}`); continue; }
      if (!seen.has(t.toLowerCase())) { seen.add(t.toLowerCase()); tokens.push(t); }
    }
  }
  if (skipped.length) out.push(`# Left out (not one word, so not a product token): ${skipped.join("; ")}`);
  if (!tokens.length) return [...out, `# No bot in ${source} has policy deny: nothing to ask.`].join("\n") + "\n";
  return [...out, "", ...tokens.map((t) => `User-agent: ${t}`), "Disallow: /"].join("\n") + "\n";
}

function main(argv: string[]): number {
  const file = argv.find((a) => !a.startsWith("--")), at = argv.indexOf("--out");
  const outPath = at >= 0 ? argv[at + 1] : undefined;
  if (!file || (at >= 0 && !outPath) || argv.some((a) => a.startsWith("--") && a !== "--out")) {
    console.error("usage: bun wba-keysync/robots.ts bots.yaml [--out robots.txt]");
    return 1;
  }
  const yaml = (globalThis as { Bun?: { YAML: { parse(s: string): unknown } } }).Bun?.YAML;
  if (!yaml) { console.error("robots.ts reads YAML with Bun: run it with bun"); return 1; }
  let bots: Bot[];
  try { bots = (yaml.parse(readFileSync(file, "utf8")) as { bots?: Bot[] } | null)?.bots ?? []; }
  catch (e) { console.error(`${file}: ${(e as Error).message}`); return 1; }
  let text: string;
  try { text = robotsTxt(bots, basename(file)); }
  catch (e) { console.error(`${file}: ${(e as Error).message}`); return 1; }
  if (outPath) writeAtomic(outPath, text); else process.stdout.write(text);
  return 0;
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
