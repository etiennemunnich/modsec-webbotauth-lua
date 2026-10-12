// wba-agents: writes agents.txt, the list of agents key sync fetches, from a
// bots file (bots.yaml; bots.seed.yaml lists its fields). Run it after you
// edit bots.yaml and check it with validate.ts:
//
//   bun wba-keysync/agents.ts bots.yaml --out /srv/wba/agents.txt [--only name,name]
//
// One line per bot with a `wba` source: its origin (a key directory), or its
// URL with type=jwks_uri when wba_type says so. A bot without `wba` cannot
// sign, so it is left out and counted in the summary. Each line is checked
// with key sync's own parser (keysync.ts parseAgent), so key sync accepts
// every line written; a bad `wba` fails the run and nothing is written. Bots
// that share a key source share one line (draft 5.5: an identifier is listed
// once). With --out the file is written under a new name and renamed into
// place, so key sync never reads half a file and a symlink there is replaced,
// never written through; without --out, agents.txt goes to stdout.
//
// Bun only: YAML is read with Bun.YAML (agentsFromBots itself runs anywhere).
// Exit codes: 0 written; 1 usage error, unreadable file or a bad entry.

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { WELL_KNOWN } from "./identifier.ts";
import { parseAgent } from "./keysync.ts";
import type { Bot } from "./validate.ts";

class UsageError extends Error {}

export interface AgentsResult { text: string; agents: number; withoutWba: string[] }

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
    if (!bot.wba) { withoutWba.push(bot.name); continue; }
    const type = bot.wba_type ?? "directory";
    if (type !== "directory" && type !== "jwks_uri") throw new Error(`${bot.name}: wba_type must be directory or jwks_uri, not ${JSON.stringify(type)}`);
    const agent = parseAgent(type === "jwks_uri" ? `${bot.wba} type=jwks_uri` : bot.wba);
    if (typeof agent === "string") throw new Error(`${bot.name}: wba ${JSON.stringify(bot.wba)}: ${agent}`);
    // A directory is written as its normalised origin (its identifier less the
    // well-known path); a URL as written.
    const line = agent.type === "directory" ? agent.id.slice(0, -WELL_KNOWN.length) : `${agent.url} type=${agent.type}`;
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
    let out: string | undefined, only: Set<string> | undefined;
    for (let i = 0; i < rest.length; i += 2) {
      const v = rest[i + 1];
      if (v === undefined) throw new UsageError(`${rest[i]} needs a value`);
      if (rest[i] === "--out") out = v;
      else if (rest[i] === "--only") only = new Set(v.split(",").filter(Boolean));
      else throw new UsageError(`unknown option ${rest[i]}`);
    }
    const yaml = (globalThis as { Bun?: { YAML: { parse(s: string): unknown } } }).Bun?.YAML;
    if (!yaml) throw new Error("agents.ts reads YAML with Bun: run it with bun");
    const parsed = yaml.parse(readFileSync(file, "utf8")) as { bots?: Bot[] } | null;
    if (!Array.isArray(parsed?.bots)) throw new Error(`${file}: no "bots:" list`);
    const r = agentsFromBots(parsed.bots, basename(file), only);
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
    const usage = "\nusage: bun wba-keysync/agents.ts bots.yaml [--out agents.txt] [--only name,name]";
    console.error(`wba-agents: ${(e as Error).message}${e instanceof UsageError ? usage : ""}`);
    return 1;
  }
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
