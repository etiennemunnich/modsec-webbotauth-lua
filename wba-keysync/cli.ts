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
// type=cimd (draft 5.5). These URLs are fetched, and so is the jwks_uri a
// listed CIMD document names (its server chooses that one). A line key sync
// cannot parse is a config error: the run stops before any fetch.
//
// --allow-private-origin https://host[:port], repeatable: key sync never fetches
// from a private, loopback or link-local address (draft 6.7), except from an
// origin named here: your own bot on your own network, or a test bot. Only that
// exact origin is excepted, only for the URLs agents.txt lists on it (never a
// jwks_uri a CIMD document names), each such fetch is reported, and agents.txt
// cannot name one.
//
// Exit codes: 0 every origin resolved to at least one usable key; 2 some
// failed (store still written, their last-good keys kept) or resolved to no
// usable key; 1 usage or config error, such as an agents.txt line that does
// not parse (store untouched).
//
// Every key added or removed is printed and appended to <out>.history
// (time, added|removed, directory, keyid), the record that says which keys a
// directory listed when. A run that finds no readable store records every
// key it writes as added. Every line printed has its control characters
// replaced: failures and warnings carry text from the network.

import { existsSync, readFileSync } from "node:fs";
import {
  DEFAULT_LIMITS, allowedOrigin, appendHistory, format, historyLines, parse, parseAgent, printable, sync, writeAtomic,
  type Cache, type FetchLike, type Limits, type Resolver, type StoreEntry,
} from "./keysync.ts";

const USAGE = [
  "usage: wba-keysync --origins <file> --out <path> [--max-bytes N] [--max-keys N] [--timeout-ms N]",
  "                   [--allow-private-origin https://host[:port] ...]",
];

/** A bad command line: printed with the usage text. */
class UsageError extends Error {}
/** A file key sync cannot use: printed as it is. Either way the exit is 1 and nothing is written. */
class ConfigError extends Error {}

const usage = (msg: string): never => { throw new UsageError(msg); };

/**
 * The agent lines of an agents.txt ("#" comments and blank lines skipped),
 * and why each line key sync cannot use is unusable, by line number.
 */
export function readAgents(text: string): { agents: string[]; errors: string[] } {
  const agents: string[] = [], errors: string[] = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;
    const a = parseAgent(line);
    if (typeof a === "string") errors.push(`line ${i + 1}: ${JSON.stringify(line).slice(0, 200)}: ${a}`);
    else agents.push(line);
  });
  return { agents, errors };
}

/** What main() talks to; tests replace the network and the output. */
interface Io { fetchImpl?: FetchLike; resolve?: Resolver; log?: (line: string) => void; error?: (line: string) => void }

/** One run; returns the exit code. */
export async function main(argv: string[], io: Io = {}): Promise<number> {
  const log = (l: string) => (io.log ?? console.log)(printable(l));
  const error = (l: string) => (io.error ?? console.error)(printable(l));
  try {
    return await run(argv, io, log, error);
  } catch (e) {
    if (e instanceof UsageError) { error(`wba-keysync: ${e.message}`); for (const l of USAGE) error(l); return 1; }
    if (e instanceof ConfigError) { error(`wba-keysync: ${e.message}`); return 1; }
    throw e;
  }
}

async function run(argv: string[], io: Io, log: (l: string) => void, error: (l: string) => void): Promise<number> {
  const opt = (name: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
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
  // origins skip the private-address check, only for URLs agents.txt lists on
  // them, and every such fetch is reported.
  const allowPrivate = argv.flatMap((a, i) => (a === "--allow-private-origin" ? [argv[i + 1] ?? ""] : []))
    .map((v) => allowedOrigin(v) ?? usage(`--allow-private-origin needs an https origin (https://host[:port], lower case, no path), not ${JSON.stringify(v)}`));

  let text: string;
  try {
    text = readFileSync(originsPath, "utf8");
  } catch (err) {
    throw new ConfigError(`cannot read ${originsPath}: ${(err as Error).message}; the store was not touched`);
  }
  // A line that does not parse names no agent, so a run without it would
  // drop that agent's keys as if the operator had removed it. Stop instead.
  const { agents: origins, errors } = readAgents(text);
  if (errors.length > 0) {
    for (const e of errors) error(`wba-keysync: ${originsPath}: ${e}`);
    throw new ConfigError(`${originsPath}: ${errors.length} line(s) key sync cannot use; fix them and run again. The store was not touched`);
  }
  if (origins.length === 0) usage(`no origins in ${originsPath}`);

  let previous: StoreEntry[] = [];
  let storeOk = !existsSync(outPath);
  if (existsSync(outPath)) {
    try {
      previous = parse(readFileSync(outPath, "utf8"));
      storeOk = true;
    } catch (err) {
      error(`wba-keysync: ignoring unreadable previous store (${(err as Error).message}); no last-good fallback this run`);
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
      error("wba-keysync: ignoring unreadable cache state; fetching every directory");
    }
  }

  const result = await sync(origins, previous, { limits, cache, allowPrivate, fetchImpl: io.fetchImpl, resolve: io.resolve });
  const now = new Date();
  for (const w of result.warnings) error(`warning: ${w}`);
  for (const f of result.failures) error(`failed: ${f.origin}: ${f.error}`);
  for (const o of result.empty) error(`warning: ${o}: no usable key; nothing it signs can verify`);
  // Draft Appendix B: informational. Keys are used with or without a proof (B.1).
  for (const p of result.proofs) {
    log(`wba-keysync: proof ${p.origin}: ${p.summary} (${p.valid} of ${p.keys} keys)`
      + (p.notes.length > 0 ? `; ${p.notes.join("; ")}` : ""));
  }
  writeAtomic(outPath, format(result.entries, now));
  writeAtomic(cachePath, JSON.stringify(result.cache, null, 1) + "\n");
  const changes = historyLines(previous, result.entries, now);
  appendHistory(`${outPath}.history`, changes);
  for (const c of changes) log(`wba-keysync: ${c.split("\t").slice(1).join(" ")}`);
  log(`wba-keysync: ${result.entries.length} keys from ${origins.length - result.failures.length}/${origins.length} origins`
    + ` (${result.fresh.length} still fresh, not fetched; ${result.empty.length} with no usable key) -> ${outPath}`);
  return result.failures.length > 0 || result.empty.length > 0 ? 2 : 0;
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
