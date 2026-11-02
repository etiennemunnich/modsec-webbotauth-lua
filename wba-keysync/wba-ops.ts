#!/usr/bin/env bun
// wba-ops: one day-2 entrypoint. Thin wrap over existing Bun tools.
// Fail-closed: no auto --allow-private-*, no auto-enroll, doctor read-only,
// sync-lists dry-run unless --write, debug-sig offline (sign.ts reuse).
import { copyFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { debugSigExplain, doctor, suggestUnknownAgents } from "./ops.ts";
import { signRequest, storeFor } from "./sign.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(HERE);
const SEED = join(HERE, "bots.seed.yaml");

const USAGE = `wba-ops — Web Bot Auth operator entrypoint (fail-closed)

  bun wba-keysync/wba-ops.ts <command> …

Commands:
  init-bots [path] [--force]     copy bots.seed.yaml → bots.yaml
  validate <bots.yaml> …         → validate.ts (--preset / --only ok)
  agents <bots.yaml> …           → agents.ts (--preset / --only / --out)
  sync-keys …                    → cli.ts (keysync); pass --allow-private-origin yourself
  sync-lists <bots.yaml> --out D [--write] […]
                                 dry-run by default; --write to write rules
  doctor [--store PATH] [--bots PATH] [--agents PATH] [--accept-signature PATH]
                                 read-only health; never mutates
  debug-sig curl <url> --dir D … dump signature base (sign.ts); offline
  debug-sig explain <status/reason>
  unknown-agent --audit FILE     suggest bots.yaml lines only; never writes

Day-2 card: lua/wba/DAY-2.md
Never auto-adds --allow-private-origin / --allow-private-url.
`;

function fail(msg: string, code = 1): never {
  console.error(`wba-ops: ${msg}`);
  process.exit(code);
}

function runTool(script: string, args: string[]): number {
  const r = spawnSync("bun", [join(HERE, script), ...args], { stdio: "inherit", cwd: REPO });
  if (r.error) fail(`cannot run ${script}: ${r.error.message}`);
  return r.status ?? 1;
}

function initBots(argv: string[]): number {
  const force = argv.includes("--force");
  const path = argv.find((a) => !a.startsWith("--")) ?? "bots.yaml";
  if (existsSync(path) && !force) {
    fail(`${path} exists; pass --force to overwrite`);
  }
  copyFileSync(SEED, path);
  console.log(`wba-ops: wrote ${path} from bots.seed.yaml`);
  console.log("Next: edit it, then `wba-ops validate` → `wba-ops agents` → `wba-ops sync-keys`.");
  return 0;
}

async function debugSig(argv: string[]): Promise<number> {
  const [sub, ...rest] = argv;
  if (sub === "explain" && rest[0]) {
    console.log(debugSigExplain(rest[0]));
    return 0;
  }
  if (sub !== "curl" || !rest[0]) fail("usage: wba-ops debug-sig curl <url> --dir DIR [--host NAME] [--method GET] [--agent URL] [--expires N]\n       wba-ops debug-sig explain <status/reason>");
  const url = rest[0];
  const opts = new Map<string, string>();
  for (let i = 1; i < rest.length; i += 2) {
    if (!rest[i]?.startsWith("--") || rest[i + 1] === undefined) fail(`bad option ${rest[i]}`);
    opts.set(rest[i], rest[i + 1]);
  }
  const dir = opts.get("--dir") ?? fail("--dir is required");
  let target: URL;
  try { target = new URL(url); } catch { fail(`not a URL: ${url}`); }
  const stored = JSON.parse(readFileSync(join(dir, "test-agent-key.json"), "utf8"));
  const agent = opts.get("--agent") ?? stored.agent ?? "https://test-agent.example";
  const { agent: _a, ...priv } = stored;
  const pub = { kty: priv.kty, crv: priv.crv, x: priv.x };
  const now = Math.floor(Date.now() / 1000);
  const { keyid } = await storeFor(pub, agent, now);
  const expires = Number(opts.get("--expires") ?? 300);
  const method = (opts.get("--method") ?? "GET").toUpperCase();
  const s = await signRequest({ priv, keyid, agent, url: target, method, host: opts.get("--host"), now, expires });
  console.log("== signature base (RFC 9421 §2.5; offline, from sign.ts)");
  console.log(s.base);
  console.log("== covered checklist: @method @authority @path signature-agent;key=sig1 + created/expires/keyid/alg/nonce/tag=web-bot-auth");
  console.log(`== clock: created=${now} expires=${now + expires} (sync NTP on WAF and keysync host)`);
  console.log(`== keyid ${keyid} present in test store under ${agent}`);
  console.log("== next: leave off | sh on sign.ts curl to inspect headers; validate directory; optional lab second opinion (DAY-2 links). Bun stdlib only on this path.");
  // Also print the curl line without executing (operator sends when ready).
  const q = (x: string) => `'${x.replaceAll("'", `'\\''`)}'`;
  const args = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}\\n", "-X", method];
  for (const [k, v] of Object.entries(s.headers)) args.push("-H", `${k}: ${v}`);
  args.push(target.origin + target.pathname + target.search);
  console.log("== curl (not executed):");
  console.log(args.map((a, i) => (i === 0 ? a : q(a))).join(" "));
  return 0;
}

function cmdDoctor(argv: string[]): number {
  const opt = (name: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const r = doctor({
    storePath: opt("--store"),
    botsPath: opt("--bots"),
    agentsPath: opt("--agents"),
    acceptSignaturePath: opt("--accept-signature"),
  });
  for (const l of r.lines) console.log(l);
  return r.ok ? 0 : 1;
}

function unknownAgent(argv: string[]): number {
  const i = argv.indexOf("--audit");
  const path = i >= 0 ? argv[i + 1] : undefined;
  if (!path) fail("usage: wba-ops unknown-agent --audit FILE");
  const text = readFileSync(path, "utf8");
  const s = suggestUnknownAgents(text);
  if (!s.suggestions.length) {
    console.log("wba-ops: no Signature-Agent found near rule 9534139");
  } else {
    console.log("wba-ops: suggested lines (NOT written):");
    for (const line of s.suggestions) console.log(line);
  }
  console.log(s.reminder);
  return 0;
}

function syncLists(argv: string[]): number {
  const write = argv.includes("--write");
  const args = argv.filter((a) => a !== "--write");
  if (!write) {
    if (!args.includes("--dry-run")) args.push("--dry-run");
    console.error("wba-ops: sync-lists dry-run (no write). Pass --write to write rules.");
  } else if (args.includes("--dry-run")) {
    fail("pass either --write or --dry-run, not both");
  }
  return runTool("lists.ts", args);
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "help" || cmd === "-h" || cmd === "--help") {
    process.stdout.write(USAGE);
    return 0;
  }
  switch (cmd) {
    case "init-bots": return initBots(rest);
    case "validate": return runTool("validate.ts", rest);
    case "agents": return runTool("agents.ts", rest);
    case "sync-keys": return runTool("cli.ts", rest);
    case "sync-lists": return syncLists(rest);
    case "doctor": return cmdDoctor(rest);
    case "debug-sig": return debugSig(rest);
    case "unknown-agent": return unknownAgent(rest);
    default: fail(`unknown command ${cmd}\n${USAGE}`);
  }
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
