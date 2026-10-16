// report.test.ts: what a bot can prove, signed traffic counted from WAF log
// lines, and the decisions block. Runs unchanged under `bun test` and `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { agentId, catalogue, evidence, render, status, traffic } from "./report.ts";
import { CATEGORIES, checkEntries } from "./validate.ts";
import type { Finding } from "./validate.ts";

const f = (bot: string, check: string, level: Finding["level"], detail = ""): Finding => ({ bot, check, level, detail });

test("evidence: proofs a bot supports, strongest first; failed sources do not count", () => {
  const signer = evidence({ name: "s", wba: "https://agent.example", user_agent: "SBot/" }, [f("s", "wba", "warn", "proof invalid")]);
  assert.deepEqual(signer.proofs, ["signature", "user-agent"]);
  assert.deepEqual(signer.notes, ["wba: proof invalid"]);
  const crawler = evidence({ name: "c", ips: "https://c.example/ips.json", rdns: ["c.example"], user_agent: "CBot" }, [f("c", "ips", "ok")]);
  assert.deepEqual(crawler.proofs, ["ip-list", "rdns", "user-agent"]);
  const claim = evidence({ name: "u", user_agent: "UBot/" }, [f("u", "user_agent", "warn", "User-Agent only")]);
  assert.deepEqual([claim.proofs, claim.notes], [["user-agent"], []], "the claim-only warning is shown as the proof, not as a note");
  const dead = evidence({ name: "d", ips: "https://d.example/ips.json", wba: "https://d.example" },
    [f("d", "ips", "fail", "HTTP 404"), f("d", "wba", "fail", "HTTP 404")]);
  assert.deepEqual(dead.proofs, []);
});

test("traffic: verified requests per agent, the rest by status/reason; only lines that are the plugin's JSON count", () => {
  const log = [
    'ts=1 nginx: {"event":"web-bot-auth","status":"verified","reason":"","agent":"https://chatgpt.com/.well-known/http-message-signatures-directory","granted":true}',
    '{"event":"web-bot-auth","status":"verified","reason":"","agent":"https://chatgpt.com/.well-known/http-message-signatures-directory","granted":false}',
    '{"event":"web-bot-auth","status":"invalid","reason":"bad-signature","agent":null,"granted":false}',
    '{"event":"web-bot-auth","status":"unverified","reason":"unknown-agent","agent":null,"granted":false}',
    '{"event":"web-bot-auth","status":"verified","reason":"url-less","agent":null,"granted":false}',
    "127.0.0.1 - - [09/Oct/2026] \"GET / HTTP/1.1\" 200",
    // A logged request header carrying the text is not the plugin's line.
    'X-Forged: {"event":"web-bot-auth","status":"verified","reason":"","agent":"https://chatgpt.com/.well-known/http-message-signatures-directory","granted":true}',
    '{"event":"web-bot-auth","status":"verif',
  ].join("\n");
  const t = traffic(log);
  assert.equal(t.total, 4, "the prefixed line and the forged header line are not counted");
  assert.deepEqual([...t.byAgent], [["https://chatgpt.com/.well-known/http-message-signatures-directory", { verified: 1, granted: 0 }]]);
  assert.deepEqual(Object.fromEntries(t.failures), { "invalid/bad-signature": 1, "unverified/unknown-agent": 1, "verified/url-less": 1 });
});

test("render: a row per bot, traffic mapped to bot names, and a decisions block, policy log until changed", () => {
  const evs = [
    evidence({ name: "chatgpt-agent", operator: "OpenAI", category: "agent", wba: "https://chatgpt.com" }, [f("chatgpt-agent", "wba", "ok")]),
    evidence({ name: "aider", category: "local-agent", user_agent: "Aider/" }, []),
  ];
  assert.equal(agentId(evs[0].bot), "https://chatgpt.com/.well-known/http-message-signatures-directory");
  const md = render(evs, traffic('{"event":"web-bot-auth","status":"verified","reason":"","agent":"https://chatgpt.com/.well-known/http-message-signatures-directory","granted":false}\n'
    + '{"event":"web-bot-auth","status":"verified","reason":"","agent":"https://other.example/.well-known/http-message-signatures-directory","granted":false}'));
  assert.match(md, /\| chatgpt-agent \| OpenAI \| agent \| signature \| signature \|/);
  assert.match(md, /\| aider \|  \| local-agent \| user-agent \| user-agent \(claim only\) \|/);
  assert.match(md, /\| chatgpt-agent \| 1 \| 0 \|/);
  assert.match(md, /\| https:\/\/other\.example\/\.well-known\/http-message-signatures-directory \(not in your list\) \| 1 \| 0 \|/);
  assert.match(md, /  chatgpt-agent: \{ policy: log \}  # can prove: signature/);
  assert.match(md, /  aider: \{ policy: log \}  # can prove: user-agent/);
});

test("status: verified from a signature or IP list, documented from reverse DNS alone, a claim from a User-Agent alone", () => {
  assert.equal(status(evidence({ name: "s", wba: "https://s.example" }, [f("s", "wba", "ok")])), "verified");
  assert.equal(status(evidence({ name: "i", ips: "https://i.example/ips.json" }, [f("i", "ips", "ok")])), "verified");
  assert.equal(status(evidence({ name: "r", rdns: ["r.example"], user_agent: "RBot" }, [])), "documented");
  assert.equal(status(evidence({ name: "u", user_agent: "UBot/" }, [])), "claim only");
  assert.equal(status(evidence({ name: "d", ips: "https://d.example/ips.json" }, [f("d", "ips", "fail", "HTTP 404")])), "unverified");
});

test("catalogue: every category defined, each bot with its operator's words, every source and its result", () => {
  const docs = "https://bot.example/about";
  const findings = [f("gb", "docs", "ok", `${docs}: 200`), f("gb", "ips", "ok", "https://bot.example/ips.json: 3 ranges (3 IPv4, 0 IPv6), 2026-10-01")];
  const evs = [evidence({ name: "gb", operator: "Example", category: "search", docs, description: "Crawls to index the web",
    ips: "https://bot.example/ips.json", rdns: ["bot.example"], user_agent: "GBot" }, findings)];
  const md = catalogue(evs, findings, new Date("2026-10-09T00:00:00Z"));
  for (const c of Object.keys(CATEGORIES)) assert.match(md, new RegExp(`^\\| ${c} \\| (crawler|fetcher) \\|`, "m"), c);
  assert.match(md, /^\| search \| crawler \| search \| .* \| 1 \|$/m);
  assert.match(md, /^\| \[gb\]\(#gb\) \| Example \| search \| ip-list \| verified \|$/m);
  assert.match(md, /- \*\*What its operator says:\*\* "Crawls to index the web"/);
  assert.match(md, /- \*\*Level:\*\* ip-list, rdns, user-agent; \*\*status:\*\* verified \(2026-10-09\)/);
  assert.match(md, /  - documentation <https:\/\/bot\.example\/about>: 200/);
  assert.match(md, /  - IP list <https:\/\/bot\.example\/ips\.json>: 3 ranges \\\(3 IPv4, 0 IPv6\\\), 2026-10-01/);
  assert.match(md, /  - reverse DNS bot\.example: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet \(planned: offline\)/);
  assert.match(md, /^## Reverse DNS$/m);
  assert.match(md, /Reverse DNS is not built\. When it is, it will run offline in the sync tool and be reviewed, never inside a request\./);
  assert.match(md, /  - User-Agent `GBot`: a claim on its own/);
});

test("evidence: an entry that fails its own checks supports nothing, so it is never verified", () => {
  const bad = { name: "a", ips: "http://not-https.example/ips.json", user_agent: "ABot", rdns: ["*.evil"] };
  const e = evidence(bad, checkEntries([bad]));
  assert.deepEqual([e.proofs, status(e)], [[], "unverified"]);
  const unfetched = evidence({ name: "b", ips: "https://b.example/ips.json" }, []);
  assert.deepEqual(unfetched.proofs, [], "an IP list counts only once it loaded");
});

test("catalogue and render: text from a bots file or the network stays inert Markdown", () => {
  const evil = { name: "x\n## Injected heading", operator: "![x](https://evil.example/p.png)", category: "search",
    description: "a | b\n\n# head", note: "<script>", purpose: "search" as unknown as string[], user_agent: "U`A" };
  const evs = [evidence(evil, []), evidence({ name: "ok-bot", category: "search", user_agent: "OkBot" }, [])];
  const md = catalogue(evs, [], new Date("2026-10-09T00:00:00Z")) + render(evs);
  assert.doesNotMatch(md, /^## Injected heading/m);
  assert.doesNotMatch(md, /!\[x\]\(https/);
  assert.doesNotMatch(md, /^# head/m);
  assert.doesNotMatch(md, /<script>/);
  assert.match(md, /purpose as documented: search/, "a purpose written as a string, not a list, does not crash");
  assert.doesNotMatch(md, /^  x/m, "a malformed name gets no decisions line");
  assert.match(md, /^  ok-bot: \{ policy: log \}/m);
});

test("agentId: a jwks_uri is normalised the way the verifier logs it", () => {
  assert.equal(agentId({ name: "j", wba: "https://Agent.Example:443/a/../jwks.json", wba_type: "jwks_uri" }), "https://agent.example/jwks.json");
});
