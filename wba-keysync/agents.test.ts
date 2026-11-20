// agents.test.ts: wba-keysync/agents.ts, agents.txt from a bots file. Runs
// unchanged under `bun test` and `node --test`; the cases that read YAML run
// under Bun only, as the tool does.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { agentsFromBots } from "./agents.ts";
import { WELL_KNOWN } from "./identifier.ts";
import { parseAgent } from "./keysync.ts";
import type { Bot } from "./validate.ts";

const BUN = typeof (globalThis as { Bun?: unknown }).Bun !== "undefined";
const lines = (text: string) => text.split("\n").filter((l) => l && !l.startsWith("#"));
const WK = (origin: string) => origin.replace(/\/$/, "") + WELL_KNOWN;

const BOTS: Bot[] = [
  { name: "a-dir", wba: "https://bot.example:443/" },
  { name: "b-jwks", wba: "https://keys.example/jwks.json" },
  { name: "c-claim-only", user_agent: "ClaimBot" },
  { name: "d-same-dir", wba: "https://bot.example" },
];

test("one line per key source: origins expand to well-known, path JWKS kept, claim-only bots left out", () => {
  const r = agentsFromBots(BOTS, "bots.yaml");
  assert.deepEqual(lines(r.text), [WK("https://bot.example"), "https://keys.example/jwks.json"]);
  assert.equal(r.agents, 2);
  assert.deepEqual(r.withoutWba, ["c-claim-only"]);
  assert.match(r.text, /^# agents\.txt: generated from bots\.yaml by wba-keysync\/agents\.ts\.\n/);
  assert.match(r.text, /\n# a-dir, d-same-dir\nhttps:\/\/bot\.example\/\.well-known\/http-message-signatures-directory\n/,
    "bots sharing a source share one line");
  for (const l of lines(r.text)) assert.equal(typeof parseAgent(l), "object", `key sync parses ${l}`);
});

test("a bad wba or a leftover wba_type fails the run; query spellings of one JWKS share a line", () => {
  assert.throws(() => agentsFromBots([{ name: "x", wba: "http://plain.example" }], "f"), /x: wba "http:\/\/plain\.example": not an https/);
  assert.throws(() => agentsFromBots([{ name: "x", wba: "https://Bot.Example" }], "f"), /x: wba .*not an https origin/, "origin shorthand needs a lowercase host");
  assert.throws(() => agentsFromBots([{ name: "x", wba: "https://k.example/j", wba_type: "jwks_uri" }], "f"), /x: wba_type is removed under protocol-01/);
  const r = agentsFromBots([
    { name: "p", wba: "https://k.example/jwks.json?v=1" },
    { name: "q", wba: "https://k.example/jwks.json?v=2" },
  ], "f");
  assert.deepEqual(lines(r.text), ["https://k.example/jwks.json"]);
  assert.match(r.text, /\n# p, q\n/);
});

test("--only keeps the named bots, and names an unknown one", () => {
  assert.deepEqual(lines(agentsFromBots(BOTS, "f", new Set(["b-jwks"])).text), ["https://keys.example/jwks.json"]);
  assert.throws(() => agentsFromBots(BOTS, "f", new Set(["b-jwks", "nope"])), /--only names bots not in f: nope/);
});

test("the seed list gives an agents.txt key sync accepts", { skip: !BUN && "reads YAML with Bun" }, () => {
  const seed = (globalThis as unknown as { Bun: { YAML: { parse(s: string): { bots: Bot[] } } } }).Bun.YAML
    .parse(readFileSync(new URL("./bots.seed.yaml", import.meta.url), "utf8"));
  const r = agentsFromBots(seed.bots, "bots.seed.yaml");
  assert.equal(r.agents, seed.bots.filter((b) => b.wba).length);
  assert.ok(r.agents > 0);
  for (const l of lines(r.text)) assert.equal(typeof parseAgent(l), "object", l);
});

test("CLI: --out renames into place, replacing a symlink; usage errors exit 1", { skip: !BUN && "reads YAML with Bun" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-agents-"));
  try {
    const bots = join(dir, "bots.yaml"), out = join(dir, "agents.txt"), target = join(dir, "target");
    writeFileSync(bots, "bots:\n  - name: a-dir\n    wba: https://bot.example\n  - name: c\n    user_agent: C\n");
    writeFileSync(target, "keep me");
    symlinkSync(target, out);
    const tool = new URL("./agents.ts", import.meta.url).pathname;
    const run = (...args: string[]) => spawnSync(process.execPath, [tool, ...args], { encoding: "utf8" });
    const ok = run(bots, "--out", out);
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(ok.stderr, /1 agents written to .*; 1 bots without wba left out/);
    assert.deepEqual(lines(readFileSync(out, "utf8")), [WK("https://bot.example")]);
    assert.equal(readFileSync(target, "utf8"), "keep me", "the symlink's target is untouched");
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".tmp")), [], "no temporary file left");
    const bad = run(bots, "--bogus", "x");
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /unknown option --bogus\nusage: /);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a bot name validate.ts would refuse, or a wba with a space, fails the run: neither can add a line to agents.txt", () => {
  assert.throws(() => agentsFromBots([{ name: "a\nhttps://evil.example", wba: "https://bot.example" }], "f"),
    /^Error: name "a\\nhttps:\/\/evil\.example": lower-case letters, digits and hyphens \(validate\.ts checks every entry\)$/);
  assert.throws(() => agentsFromBots([{ name: 360 as unknown as string, wba: "https://bot.example" }], "f"), /name 360 is not a string: quote it/);
  assert.throws(() => agentsFromBots([{ name: "x", wba: "https://evil.example/client type=cimd" }], "f"), /^Error: x: wba must be one URL with no spaces$/);
  assert.throws(() => agentsFromBots([{ name: "x", wba: "https://evil.example/client\ttype=cimd" }], "f"), /x: wba must be one URL with no spaces/);
});
