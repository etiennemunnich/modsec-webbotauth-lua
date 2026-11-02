// ops.test.ts: wba-ops entrypoint, doctor (read-only), debug-sig (offline),
// lists --dry-run, --preset filter, unknown-agent (suggest-only). Fail-closed:
// never auto --allow-private-*, never auto-enroll. Runs under `bun test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { expandPreset, filterByPreset } from "./preset.ts";
import { policyImpact, runLists, type Mode } from "./lists.ts";
import { doctor, suggestUnknownAgents, debugSigExplain } from "./ops.ts";
import { signRequest, storeFor } from "./sign.ts";
import type { Bot } from "./validate.ts";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const OPS = fileURLToPath(new URL("./wba-ops.ts", import.meta.url));
const bun = (...args: string[]) =>
  spawnSync("bun", [OPS, ...args], { encoding: "utf8", cwd: REPO });

const BOTS: Bot[] = [
  { name: "googlebot", category: "search", user_agent: "Googlebot", ips: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json" },
  { name: "gptbot", category: "training", user_agent: "GPTBot", ips: "https://openai.com/gptbot.json" },
  { name: "youbot", category: "search", wba: "https://you.com", user_agent: "YouBot" },
  { name: "chatgpt-agent", category: "agent", wba: "https://chatgpt.com" },
  { name: "ccbot", category: "archive", user_agent: "CCBot" },
];

// --- preset -----------------------------------------------------------------

test("expandPreset: category names and the ai alias; unknown token fails closed", () => {
  assert.deepEqual([...expandPreset("search")].sort(), ["search"]);
  assert.deepEqual([...expandPreset("search,agent")].sort(), ["agent", "search"]);
  const ai = expandPreset("ai");
  assert.ok(ai.has("training") && ai.has("ai-search") && ai.has("user-fetch") && ai.has("agent") && ai.has("local-agent"));
  assert.ok(!ai.has("search") && !ai.has("archive"));
  assert.throws(() => expandPreset("search,not-a-category"), /unknown preset|unknown category/i);
  assert.throws(() => expandPreset(""), /empty|required/i);
});

test("filterByPreset: selection only; does not invent bots or skip validate", () => {
  const search = filterByPreset(BOTS, expandPreset("search"));
  assert.deepEqual(search.map((b) => b.name).sort(), ["googlebot", "youbot"]);
  const ai = filterByPreset(BOTS, expandPreset("ai"));
  assert.deepEqual(ai.map((b) => b.name).sort(), ["chatgpt-agent", "gptbot"]);
  assert.equal(filterByPreset(BOTS, expandPreset("archive")).length, 1);
});

test("wba-ops validate/agents accept --preset as a filter (still need validate before enroll)", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-ops-preset-"));
  try {
    const yaml = join(dir, "bots.yaml");
    writeFileSync(yaml, `bots:\n  - name: youbot\n    category: search\n    wba: https://you.com\n    user_agent: YouBot\n  - name: gptbot\n    category: training\n    user_agent: GPTBot\n  - name: ccbot\n    category: archive\n    user_agent: CCBot\n`);
    const agents = bun("agents", yaml, "--preset", "search", "--out", join(dir, "agents.txt"));
    assert.equal(agents.status, 0, agents.stderr + agents.stdout);
    const text = readFileSync(join(dir, "agents.txt"), "utf8");
    assert.match(text, /you\.com/);
    assert.doesNotMatch(text, /gptbot|ccbot|openai/i);
    const bad = bun("agents", yaml, "--preset", "nope");
    assert.notEqual(bad.status, 0);
    assert.match(bad.stderr + bad.stdout, /unknown/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- lists dry-run / policy impact ------------------------------------------

test("policyImpact: impostors refused only with allow+list (not claim_only, not no-list)", () => {
  assert.equal(policyImpact({ name: "a", policy: "allow" }, true, "enforce").impostorsRefused, true);
  assert.equal(policyImpact({ name: "a", policy: "allow" }, false, "enforce").impostorsRefused, false);
  assert.equal(policyImpact({ name: "a", policy: "allow", claim_only: true }, true, "enforce").impostorsRefused, false);
  assert.equal(policyImpact({ name: "a", policy: "deny" }, true, "enforce").botRefused, true);
  assert.equal(policyImpact({ name: "a", policy: "allow" }, true, "log").impostorsRefused, false);
  assert.match(policyImpact({ name: "a", policy: "allow" }, false, "enforce").note, /no-list|no list/i);
});

test("runLists dry-run: fetches and reports impact, never writes, never check/reload", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-dry-"));
  const lines: string[] = [];
  const url = "https://lists.example/bot.json";
  const body = JSON.stringify({ creationTime: "2026-01-01T00:00:00Z", prefixes: [{ ipv4Prefix: "192.0.2.0/24" }] });
  try {
    const code = await runLists({
      bots: [{ name: "gbot", user_agent: "GBot", ips: url, policy: "allow" }],
      mode: "log" as Mode,
      source: "bots.yaml",
      out: dir,
      dryRun: true,
      check: "false", // would fail if invoked
      reload: "false",
      log: (l) => lines.push(l),
      fetchImpl: async () => new Response(body, { status: 200, headers: { "content-type": "application/json" } }),
      resolve: async () => ["192.0.2.1"],
    });
    assert.equal(code, 0, lines.join("\n"));
    assert.ok(lines.some((l) => /gbot/i.test(l) && /fetched|list/i.test(l)));
    assert.ok(lines.some((l) => /impostor|policy|log mode|would/i.test(l)));
    assert.ok(!existsSync(join(dir, "web-bot-auth-bots-before.conf")), "dry-run must not write rules");
    assert.ok(!existsSync(join(dir, "status.json")), "dry-run must not write status");
    assert.ok(!lines.some((l) => /check:|reload:/i.test(l)), "dry-run must not run check/reload");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wba-ops sync-lists defaults to dry-run; --write is required to touch disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-ops-lists-"));
  try {
    const yaml = join(dir, "bots.yaml");
    writeFileSync(yaml, "policy_mode: log\nbots:\n  - name: lonely\n    user_agent: LonelyBot\n");
    const dry = bun("sync-lists", yaml, "--out", join(dir, "out"));
    assert.equal(dry.status, 0, dry.stderr + dry.stdout);
    assert.match(dry.stdout + dry.stderr, /dry-run|no write/i);
    assert.ok(!existsSync(join(dir, "out", "web-bot-auth-bots-before.conf")));
    const write = bun("sync-lists", yaml, "--out", join(dir, "out"), "--write");
    assert.equal(write.status, 0, write.stderr + write.stdout);
    assert.ok(existsSync(join(dir, "out", "web-bot-auth-bots-before.conf")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wba-ops never invents --allow-private-origin or --allow-private-url", () => {
  const help = bun("help");
  const text = (help.stdout + help.stderr).toLowerCase();
  assert.match(text, /never auto-adds --allow-private/);
  assert.doesNotMatch(text, /will (add|retry|enable).{0,40}allow-private/);
  // Passthrough still documents the exact flags; doctor must not add them.
  const doc = doctor({ storePath: "/nonexistent/wba-keys.tsv" });
  const joined = doc.lines.join("\n").toLowerCase();
  assert.doesNotMatch(joined, /run with --allow-private/);
  assert.ok(!doc.mutated);
});

// --- doctor (read-only) -----------------------------------------------------

test("doctor: read-only; reports Bun, store header, perms hints, exit-code table; never mutates", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-doctor-"));
  try {
    const keysDir = join(dir, "keys");
    mkdirSync(keysDir, { mode: 0o750 });
    const store = join(keysDir, "wba-keys.tsv");
    writeFileSync(store, "# wba-keys v2\n# generated\n", { mode: 0o640 });
    writeFileSync(`${store}.history`, "2026-11-01T00:00:00.000Z\tadded\thttps://you.com/.well-known/http-message-signatures-directory\tkid\n");
    const bots = join(dir, "bots.yaml");
    const agents = join(dir, "agents.txt");
    writeFileSync(bots, "bots: []\n");
    // agents older than bots → staleness hint
    writeFileSync(agents, "# agents\n");
    const older = new Date("2020-01-01").getTime() / 1000;
    spawnSync("touch", ["-d", "@" + older, agents]);
    const r = doctor({
      storePath: store,
      botsPath: bots,
      agentsPath: agents,
      bunPath: process.execPath.includes("bun") ? "bun" : undefined,
    });
    assert.equal(r.ok, true);
    assert.ok(!r.mutated);
    const text = r.lines.join("\n");
    assert.match(text, /wba-keys v2/);
    assert.match(text, /exit|keysync|lists/i);
    assert.match(text, /agents\.txt|stale|bots\.yaml/i);
    const before = readFileSync(store, "utf8");
    doctor({ storePath: store });
    assert.equal(readFileSync(store, "utf8"), before, "doctor must not rewrite the store");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("doctor: bad store header is a finding; missing Bun is a finding", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-doctor-bad-"));
  try {
    const store = join(dir, "wba-keys.tsv");
    writeFileSync(store, "# wrong header\n");
    const r = doctor({ storePath: store, requireBun: true, bunPath: "/nonexistent/bun-binary-for-test" });
    assert.equal(r.ok, false);
    assert.match(r.lines.join("\n"), /header|wba-keys v2/i);
    assert.match(r.lines.join("\n"), /bun/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wba-ops doctor exits 0 when healthy, non-zero when not; never writes", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-ops-doc-"));
  try {
    mkdirSync(join(dir, "keys"), { mode: 0o750 });
    writeFileSync(join(dir, "keys", "wba-keys.tsv"), "# wba-keys v2\n");
    const ok = bun("doctor", "--store", join(dir, "keys", "wba-keys.tsv"));
    assert.equal(ok.status, 0, ok.stderr + ok.stdout);
    const bad = bun("doctor", "--store", join(dir, "missing.tsv"));
    assert.notEqual(bad.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- debug-sig (offline, sign.ts reuse) -------------------------------------

test("debugSigExplain: maps common reasons to next steps without network", () => {
  assert.match(debugSigExplain("invalid/bad-signature"), /sign\.ts|signature base|covered/i);
  assert.match(debugSigExplain("unverified/unknown-agent"), /validate|agents|sync-keys|9534139/i);
  assert.match(debugSigExplain("unverified/unknown-key"), /sync-keys|keyid|thumbprint/i);
  assert.match(debugSigExplain("invalid/expired"), /clock|NTP|expires/i);
  const badSig = debugSigExplain("invalid/bad-signature");
  assert.doesNotMatch(badSig, /\bnpm install\b|\bnpx\b/i);
  assert.match(badSig, /do not upload prod signatures/i);
});

test("debug-sig dumps RFC 9421 signature base from signRequest (no private key in output)", async () => {
  const kp = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const now = Math.floor(Date.now() / 1000);
  const agent = "https://test-agent.example";
  const { keyid } = await storeFor({ kty: priv.kty, crv: priv.crv, x: priv.x }, agent, now);
  const s = await signRequest({
    priv, keyid, agent, url: new URL("https://localhost:8443/agents/hello"), method: "GET",
    host: "example.com", now, expires: 300,
  });
  assert.match(s.base, /"@method": GET/);
  assert.match(s.base, /"@authority": example\.com/);
  assert.match(s.base, /"@path": \/agents\/hello/);
  assert.match(s.base, /signature-agent/);
  assert.doesNotMatch(s.base, /"d":/);
});

test("wba-ops debug-sig curl dumps base offline and does not npm install", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-ops-debug-"));
  try {
    const init = spawnSync("bun", [fileURLToPath(new URL("./sign.ts", import.meta.url)), "init", dir], { encoding: "utf8" });
    assert.equal(init.status, 0, init.stderr);
    const out = bun("debug-sig", "curl", "https://localhost:8443/agents/hello", "--dir", dir, "--host", "example.com");
    assert.equal(out.status, 0, out.stderr + out.stdout);
    const text = out.stdout + out.stderr;
    assert.match(text, /@method|signature base|@authority/i);
    assert.doesNotMatch(text, /\bnpx\b|paste your request|npm i /i);
    assert.doesNotMatch(text, /"d":\s*"/); // private key material
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- unknown-agent (suggest-only) -------------------------------------------

test("suggestUnknownAgents: parses 9534139 audit for Signature-Agent; never returns write instructions as done", () => {
  const audit = `
---
ModSecurity: Warning. [id "9534139"] [msg "unknown-agent discovery"]
Signature-Agent: "https://crawler.exa.ai"
Signature: sig1=:AAAA:
---
ModSecurity: Warning. [id "9534139"]
Signature-Agent: sig1="https://ahrefs.com"
`;
  const s = suggestUnknownAgents(audit);
  assert.ok(s.suggestions.some((x) => x.includes("crawler.exa.ai")));
  assert.ok(s.suggestions.some((x) => x.includes("ahrefs.com")));
  assert.ok(!s.wrote);
  assert.match(s.reminder, /9534139|remove|validate/i);
  // Must not echo full Signature into suggested bots.yaml comments
  assert.ok(!s.suggestions.some((x) => /AAAA|sig1=:/.test(x)));
});

test("suggestUnknownAgents: ignores spoofable noise without 9534139 context when strict", () => {
  const noise = `Signature-Agent: "https://evil.example"\n`;
  const s = suggestUnknownAgents(noise, { requireRule: true });
  assert.equal(s.suggestions.length, 0);
});

test("wba-ops unknown-agent prints suggestions only; does not write bots.yaml", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-ops-ua-"));
  try {
    const audit = join(dir, "audit.log");
    const bots = join(dir, "bots.yaml");
    writeFileSync(bots, "bots: []\n");
    writeFileSync(audit, `ModSecurity: [id "9534139"] Signature-Agent: "https://www.browserbase.com"\n`);
    const before = readFileSync(bots, "utf8");
    const r = bun("unknown-agent", "--audit", audit);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout + r.stderr, /browserbase\.com/);
    assert.match(r.stdout + r.stderr, /suggest|validate|do not write|not written/i);
    assert.equal(readFileSync(bots, "utf8"), before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- init-bots + CLI surface ------------------------------------------------

test("wba-ops init-bots copies seed and refuses to overwrite without --force", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-ops-init-"));
  try {
    const dest = join(dir, "bots.yaml");
    const a = bun("init-bots", dest);
    assert.equal(a.status, 0, a.stderr + a.stdout);
    assert.ok(existsSync(dest));
    assert.match(readFileSync(dest, "utf8"), /youbot|bots:/);
    writeFileSync(dest, "keep\n");
    const b = bun("init-bots", dest);
    assert.notEqual(b.status, 0);
    assert.equal(readFileSync(dest, "utf8"), "keep\n");
    const c = bun("init-bots", dest, "--force");
    assert.equal(c.status, 0, c.stderr);
    assert.match(readFileSync(dest, "utf8"), /bots:/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wba-ops help lists the day-2 commands and points at DAY-2", () => {
  const r = bun("help");
  assert.equal(r.status, 0);
  const text = r.stdout + r.stderr;
  for (const cmd of ["init-bots", "validate", "agents", "sync-keys", "sync-lists", "doctor", "debug-sig", "unknown-agent"]) {
    assert.match(text, new RegExp(cmd));
  }
  assert.match(text, /DAY-2/);
});

// --- deploy templates (least privilege) -------------------------------------

test("deploy templates: User=wba, hardening, no private-allow, keysync ≠ nginx reload", () => {
  const deploy = join(REPO, "wba-keysync/deploy");
  const service = readFileSync(join(deploy, "wba-keysync.service"), "utf8");
  const timer = readFileSync(join(deploy, "wba-keysync.timer"), "utf8");
  const lists = readFileSync(join(deploy, "wba-lists.service"), "utf8");
  const cron = readFileSync(join(deploy, "wba-keysync.cron"), "utf8");
  for (const t of [service, lists]) {
    assert.match(t, /User=wba/);
    assert.match(t, /NoNewPrivileges=yes/);
    assert.match(t, /ProtectSystem=strict/);
    assert.match(t, /ReadWritePaths=/);
    assert.doesNotMatch(t, /CAP_SYS_ADMIN/);
    // ExecStart must not bake private exceptions (comments may document the opt-in).
    const exec = t.split("\n").filter((l) => l.startsWith("ExecStart=")).join("\n");
    assert.doesNotMatch(exec, /allow-private/);
  }
  const serviceExec = service.split("\n").filter((l) => l.startsWith("ExecStart=")).join("\n");
  assert.doesNotMatch(serviceExec, /nginx|reload/);
  assert.match(lists, /--write/); // explicit write; dry-run is the ops default
  const listsExec = lists.split("\n").filter((l) => l.startsWith("ExecStart=")).join("\n");
  assert.doesNotMatch(listsExec, /nginx -s reload/); // reload not in ExecStart
  assert.match(timer, /OnCalendar|OnUnitActiveSec/);
  assert.match(cron, /flock/);
  const cronExec = cron.split("\n").filter((l) => l && !l.startsWith("#")).join("\n");
  assert.doesNotMatch(cronExec, /allow-private/);
});
