// wba-agents: writes agents.txt, the list of agents key sync fetches, from a
// bots file (bots.yaml; bots.seed.yaml lists its fields). Run it after you
// edit bots.yaml and check it with validate.ts:
//
//   bun wba-keysync/agents.ts bots.yaml --out /srv/wba/agents.txt [--only name,name]
//
// One line per bot with a `wba` source: its HTTPS JWK Set URL (protocol-01).
// An origin-only `wba` is expanded to the well-known directory URL when
// writing agents.txt (local-registry shorthand; the wire Signature-Agent
// value is still the JWKS URI the bot sends). A bot without `wba` cannot
// sign, so it is left out and counted in the summary. Each line is checked
// with key sync's own parser (keysync.ts parseAgent), so key sync accepts
// every line written; a bad `wba` (one with a space in it included) or a bot
// name validate.ts would refuse fails the run and nothing is written. Bots
// that share a key source share one line (draft 5.5: an identifier is listed
// once). With --out the file is written under a new name and renamed into
// place, so key sync never reads half a file and a symlink there is replaced,
// never written through; without --out, agents.txt goes to stdout.
//
// Bun only: YAML is read with Bun.YAML (agentsFromBots itself runs anywhere).
// Exit codes: 0 written; 1 usage error, unreadable file or a bad entry.

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { directoryIdentifier } from "./identifier.ts";
import { parseAgent } from "./keysync.ts";
import { expandPreset, filterByPreset } from "./preset.ts";
import { nameProblem, type Bot } from "./validate.ts";

class UsageError extends Error {}

export interface AgentsResult { text: string; agents: number; withoutWba: string[] }

/**
 * Expand an origin-only wba to the well-known JWKS URL; leave path URLs as
 * written. An origin-shaped value that directoryIdentifier refuses (mixed-case
 * host, explicit :443, …) is not silently treated as JWKS-at-root.
 */
export function wbaFetchUrl(wba: string): string | { error: string } {
  const dir = directoryIdentifier(wba);
  if (dir) return dir;
  const path = wba.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/, "").replace(/[?#].*$/, "");
  if (path === "" || path === "/") {
    return { error: "not an https origin (https://host[:port] only; lowercase host)" };
  }
  return wba;
}

/** agents.txt for the bots (all, or those named in only), from a file named source. */
export function agentsFromBots(bots: Bot[], source: string, only?: Set<string>): AgentsResult {
  if (only) {
    const missing = [...only].filter((n) => !bots.some((b) => b.name === n));
    if (missing.length) throw new UsageError(`--only names bots not in ${source}: ${missing.join(", ")}`);
  }
  const byId = new Map<string, { line: string; names: string[] }>();
  const withoutWba: string[] = [];
  for (const bot of bots) {
    if (only && !only.has(bot.name)) continue;
    // A name goes into a comment line: one with a newline would add a line of its own.
    const bad = nameProblem(bot.name);
    if (bad) throw new Error(`${bad} (validate.ts checks every entry)`);
    if (!bot.wba) { withoutWba.push(bot.name); continue; }
    if (typeof bot.wba !== "string" || /\s/.test(bot.wba)) {
      throw new Error(`${bot.name}: wba must be one URL with no spaces`);
    }
    if (bot.wba_type !== undefined) {
      throw new Error(`${bot.name}: wba_type is removed under protocol-01; put the full JWKS URL in wba`);
    }
    const fetchUrl = wbaFetchUrl(bot.wba);
    if (typeof fetchUrl === "object") throw new Error(`${bot.name}: wba ${JSON.stringify(bot.wba)}: ${fetchUrl.error}`);
    const agent = parseAgent(fetchUrl);
    if (typeof agent === "string") throw new Error(`${bot.name}: wba ${JSON.stringify(bot.wba)}: ${agent}`);
    // Write the normalised identifier (query/fragment already dropped by parseAgent).
    const line = agent.id;
    const held = byId.get(agent.id);
    if (!held) byId.set(agent.id, { line, names: [bot.name] });
    else if (held.line === line) held.names.push(bot.name);
    else throw new Error(`${bot.name}: wba ${JSON.stringify(line)} has the same identifier as ${held.names.join(", ")} (${JSON.stringify(held.line)})`);
  }
  const out = [
    `# agents.txt: generated from ${source} by wba-keysync/agents.ts.`,
    `# Edit ${source} and run agents.ts again: changes made here are lost.`,
  ];
  for (const { line, names } of byId.values()) out.push(`# ${names.join(", ")}`, line);
  return { text: out.join("\n") + "\n", agents: byId.size, withoutWba };
}

function main(argv: string[]): number {
  try {
    const [file, ...rest] = argv;
    if (!file || file.startsWith("--")) throw new UsageError("a bots file is required");
    let out: string | undefined, only: Set<string> | undefined, preset: Set<string> | undefined;
    for (let i = 0; i < rest.length; i += 2) {
      const v = rest[i + 1];
      if (v === undefined) throw new UsageError(`${rest[i]} needs a value`);
      if (rest[i] === "--out") out = v;
      else if (rest[i] === "--only") only = new Set(v.split(",").filter(Boolean));
      else if (rest[i] === "--preset") preset = expandPreset(v);
      else throw new UsageError(`unknown option ${rest[i]}`);
    }
    const yaml = (globalThis as { Bun?: { YAML: { parse(s: string): unknown } } }).Bun?.YAML;
    if (!yaml) throw new Error("agents.ts reads YAML with Bun: run it with bun");
    const parsed = yaml.parse(readFileSync(file, "utf8")) as { bots?: Bot[] } | null;
    if (!Array.isArray(parsed?.bots)) throw new Error(`${file}: no "bots:" list`);
    let bots = parsed.bots;
    if (preset) {
      bots = filterByPreset(bots, preset);
      if (!bots.length) throw new UsageError(`--preset matched no bots in ${file}`);
    }
    const r = agentsFromBots(bots, basename(file), only);
    if (out) {
      const tmp = `${out}.${process.pid}.tmp`;
      writeFileSync(tmp, r.text, { flag: "wx" });
      renameSync(tmp, out);
    } else {
      process.stdout.write(r.text);
    }
    console.error(`wba-agents: ${r.agents} agents${out ? ` written to ${out}` : ""}; ${r.withoutWba.length} bots without wba left out`);
    return 0;
  } catch (e) {
    const usage = "\nusage: bun wba-keysync/agents.ts bots.yaml [--out agents.txt] [--only name,name] [--preset search,ai]";
    console.error(`wba-agents: ${(e as Error).message}${e instanceof UsageError ? usage : ""}`);
    return 1;
  }
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
