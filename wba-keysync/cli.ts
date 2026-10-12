// wba-keysync CLI. Run on a schedule, never per request: every minute is
// cheap, because a directory is only fetched once its HTTP freshness lifetime
// has run out (draft 5.5.2, C.4), and then conditionally. The cache state
// lives in <out>.cache.json beside the store; keys.lua never reads it.
//
//   bun wba-keysync/cli.ts --origins agents.txt --out /etc/modsecurity.d/wba/keys/wba-keys.tsv
//   node wba-keysync/cli.ts ...        (tested on Node 26.10; needs native type stripping)
//
// agents.txt: one agent per line, "#" comments allowed: an https origin (a
// key directory, the default type), or a URL followed by type=jwks_uri or
// type=cimd (draft 5.5). Only these URLs are ever fetched.
//
// --allow-private-origin https://host[:port], repeatable: key sync never fetches
// from a private, loopback or link-local address (draft 6.7), except from an
// origin named here: your own bot on your own network, or a test bot. Only that
// exact origin is excepted, each such fetch is reported, and agents.txt cannot
// name one.
//
// Exit codes: 0 every origin resolved to at least one usable key; 2 some
// failed (store still written, their last-good keys kept) or resolved to no
// usable key; 1 usage or config error (store untouched).
//
// Every key added or removed is printed and appended to <out>.history
// (time, added|removed, directory, keyid), the record that says which keys a
// directory listed when. A run that finds no readable store records every
// key it writes as added.

import { existsSync, readFileSync } from "node:fs";
import {
  DEFAULT_LIMITS, allowedOrigin, appendHistory, format, historyLines, parse, sync, writeAtomic, type Cache, type Limits, type StoreEntry,
} from "./keysync.ts";

function usage(msg: string): never {
  console.error(`wba-keysync: ${msg}
usage: wba-keysync --origins <file> --out <path> [--max-bytes N] [--max-keys N] [--timeout-ms N]
                   [--allow-private-origin https://host[:port] ...]`);
  process.exit(1);
}

const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const num = (name: string, fallback: number) => {
  const v = opt(name);
  if (v === undefined) return fallback;
  if (!/^[1-9][0-9]*$/.test(v)) usage(`${name} must be a positive integer`);
  return Number(v);
};

const originsPath = opt("--origins") ?? usage("--origins is required");
const outPath = opt("--out") ?? usage("--out is required");
const limits: Limits = {
  maxBytes: num("--max-bytes", DEFAULT_LIMITS.maxBytes),
  maxKeys: num("--max-keys", DEFAULT_LIMITS.maxKeys),
  timeoutMs: num("--timeout-ms", DEFAULT_LIMITS.timeoutMs),
};

// Your own bots on your own network (draft 6.7 is a SHOULD): only these exact
// origins skip the private-address check, and every such fetch is reported.
const allowPrivate = args.flatMap((a, i) => (a === "--allow-private-origin" ? [args[i + 1] ?? ""] : []))
  .map((v) => allowedOrigin(v) ?? usage(`--allow-private-origin needs an https origin (https://host[:port], lower case, no path), not "${v}"`));

const origins = readFileSync(originsPath, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
if (origins.length === 0) usage(`no origins in ${originsPath}`);

let previous: StoreEntry[] = [];
let storeOk = !existsSync(outPath);
if (existsSync(outPath)) {
  try {
    previous = parse(readFileSync(outPath, "utf8"));
    storeOk = true;
  } catch (err) {
    console.error(`wba-keysync: ignoring unreadable previous store (${(err as Error).message}); no last-good fallback this run`);
  }
}
// The cache only describes the store it was written with: without a readable
// store, every directory is fetched again.
const cachePath = `${outPath}.cache.json`;
let cache: Cache = {};
if (storeOk && existsSync(cachePath)) {
  try {
    cache = JSON.parse(readFileSync(cachePath, "utf8")) as Cache;
  } catch {
    console.error("wba-keysync: ignoring unreadable cache state; fetching every directory");
  }
}

const result = await sync(origins, previous, { limits, cache, allowPrivate });
const now = new Date();
for (const w of result.warnings) console.error(`warning: ${w}`);
for (const f of result.failures) console.error(`failed: ${f.origin}: ${f.error}`);
for (const o of result.empty) console.error(`warning: ${o}: no usable key; nothing it signs can verify`);
// Draft Appendix B: informational. Keys are used with or without a proof (B.1).
for (const p of result.proofs) {
  console.log(`wba-keysync: proof ${p.origin}: ${p.summary} (${p.valid} of ${p.keys} keys)`
    + (p.notes.length > 0 ? `; ${p.notes.join("; ")}` : ""));
}
writeAtomic(outPath, format(result.entries, now));
writeAtomic(cachePath, JSON.stringify(result.cache, null, 1) + "\n");
const changes = historyLines(previous, result.entries, now);
appendHistory(`${outPath}.history`, changes);
for (const c of changes) console.log(`wba-keysync: ${c.split("\t").slice(1).join(" ")}`);
console.log(`wba-keysync: ${result.entries.length} keys from ${origins.length - result.failures.length}/${origins.length} origins`
  + ` (${result.fresh.length} still fresh, not fetched; ${result.empty.length} with no usable key) -> ${outPath}`);
process.exit(result.failures.length > 0 || result.empty.length > 0 ? 2 : 0);
