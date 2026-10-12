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
import { parseAgent } from "./keysync.ts";
import type { Bot } from "./validate.ts";

const BUN = typeof (globalThis as { Bun?: unknown }).Bun !== "undefined";
const lines = (text: string) => text.split("\n").filter((l) => l && !l.startsWith("#"));

const BOTS: Bot[] = [
  { name: "a-dir", wba: "https://bot.example:443/" },
  { name: "b-jwks", wba: "https://keys.example/jwks.json", wba_type: "jwks_uri" },
  { name: "c-claim-only", user_agent: "ClaimBot" },
  { name: "d-same-dir", wba: "https://bot.example" },
];

test("one line per key source: directories normalised, JWK Sets typed, claim-only bots left out", () => {
  const r = agentsFromBots(BOTS, "bots.yaml");
  assert.deepEqual(lines(r.text), ["https://bot.example", "https://keys.example/jwks.json type=jwks_uri"]);
  assert.equal(r.agents, 2);
  assert.deepEqual(r.withoutWba, ["c-claim-only"]);
  assert.match(r.text, /^# agents\.txt: generated from bots\.yaml by wba-keysync\/agents\.ts\.\n/);
  assert.match(r.text, /\n# a-dir, d-same-dir\nhttps:\/\/bot\.example\n/, "bots sharing a source share one line");
  for (const l of lines(r.text)) assert.equal(typeof parseAgent(l), "object", `key sync parses ${l}`);
});

test("a bad wba, a bad wba_type or two sources for one identifier fail the run", () => {
  assert.throws(() => agentsFromBots([{ name: "x", wba: "http://plain.example" }], "f"), /^Error: x: wba "http:\/\/plain\.example": not an https origin/);
  assert.throws(() => agentsFromBots([{ name: "x", wba: "https://bot.example/path" }], "f"), /x: wba .*not an https origin/);
  assert.throws(() => agentsFromBots([{ name: "x", wba: "https://Bot.Example" }], "f"), /x: wba .*not an https origin/, "key sync takes lower-case hosts only");
  assert.throws(() => agentsFromBots([{ name: "x", wba: "https://k.example/j", wba_type: "cimd" as never }], "f"), /x: wba_type must be directory or jwks_uri/);
  assert.throws(() => agentsFromBots([
    { name: "p", wba: "https://k.example/jwks.json?v=1", wba_type: "jwks_uri" },
    { name: "q", wba: "https://k.example/jwks.json?v=2", wba_type: "jwks_uri" },
  ], "f"), /q: wba .* has the same identifier as p/);
});

test("--only keeps the named bots, and names an unknown one", () => {
  assert.deepEqual(lines(agentsFromBots(BOTS, "f", new Set(["b-jwks"])).text), ["https://keys.example/jwks.json type=jwks_uri"]);
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
    assert.deepEqual(lines(readFileSync(out, "utf8")), ["https://bot.example"]);
    assert.equal(readFileSync(target, "utf8"), "keep me", "the symlink's target is untouched");
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".tmp")), [], "no temporary file left");
    const bad = run(bots, "--bogus", "x");
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /unknown option --bogus\nusage: /);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
