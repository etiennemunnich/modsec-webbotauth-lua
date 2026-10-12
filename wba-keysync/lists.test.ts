// lists.test.ts: wba-keysync/lists.ts, ModSecurity rules from the IP lists
// in a bots file. The rules' shape is checked here; lua/tests/live/
// bot-lists.sh runs them in ModSecurity. Runs unchanged under `bun test` and
// `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  assignSlots, checkRules, CLAIM_RULE, CONF, DATA, dataLine, generate, LOCAL_RANGES, MAX_SLOTS, normalise, OLD_CONF, overlaps, RULE_BASE,
  runLists, VER, versionOf, type ListVersion,
} from "./lists.ts";
import { forbiddenAddress } from "./keysync.ts";
import { formatCidr, parseCidr, type Bot } from "./validate.ts";

const VERX = `ver:'${VER.replace(/\./g, "\\.")}'`;
const c = (s: string) => parseCidr(s)!;
const cs = (xs: string[]) => xs.map(c);

test("normalise: canonical text, IPv4 then IPv6, duplicates dropped, a single address written bare", () => {
  assert.deepEqual(normalise(cs(["2001:DB8::/48", "198.51.100.200/32", "192.0.2.9/24", "192.0.2.0/24", "2001:db8:1::1/128", "198.51.100.0/25"])),
    ["192.0.2.0/24", "198.51.100.0/25", "198.51.100.200", "2001:db8::/48", "2001:db8:1::1"]);
  assert.equal(dataLine(c("2001:db8::1/128")), "2001:db8::1"); // libmodsecurity refuses an explicit /128
  assert.equal(dataLine(c("192.0.2.1/32")), "192.0.2.1");
});

test("normalise: a range inside another is dropped (ModSecurity #3588); equal ranges once; side by side and other families kept", () => {
  // Nested, in any order and at any depth: only the outer range is written.
  assert.deepEqual(normalise(cs(["192.0.2.8/29", "192.0.2.0/24", "192.0.2.9", "192.0.2.128/25"])), ["192.0.2.0/24"]);
  assert.deepEqual(normalise(cs(["2001:db8:5:1::/64", "2001:db8:5::/48", "2001:db8:5:1::9"])), ["2001:db8:5::/48"]);
  // Equal ranges, written two ways: once.
  assert.deepEqual(normalise(cs(["198.51.100.0/24", "198.51.100.77/24", "2001:DB8::/32", "2001:db8::/32"])), ["198.51.100.0/24", "2001:db8::/32"]);
  // Side by side (could make one /23, or not): each kept as it is, never merged.
  assert.deepEqual(normalise(cs(["198.51.101.0/24", "198.51.100.0/24"])), ["198.51.100.0/24", "198.51.101.0/24"]);
  assert.deepEqual(normalise(cs(["203.0.113.192/27", "203.0.113.128/26"])), ["203.0.113.128/26", "203.0.113.192/27"]);
  assert.deepEqual(normalise(cs(["2001:db8:6::/48", "2001:db8:5::/48"])), ["2001:db8:5::/48", "2001:db8:6::/48"]);
  // Close but apart: a range just past the outer one stays.
  assert.deepEqual(normalise(cs(["192.0.2.0/25", "192.0.2.128/32", "192.0.2.127/32"])), ["192.0.2.0/25", "192.0.2.128"]);
  // IPv4 and IPv6 never contain each other, whatever the bits say.
  assert.deepEqual(normalise(cs(["2001:db8::/32", "192.0.2.0/24", "2001:db8::c000:200/120"])), ["192.0.2.0/24", "2001:db8::/32"]);
  // Stable: the same output whatever order the operator wrote them in.
  const xs = ["203.0.113.0/24", "203.0.113.64/26", "2001:db8:7::/48", "198.51.100.0/24", "203.0.113.64/27", "2001:db8:7:8::/64"];
  const want = ["198.51.100.0/24", "203.0.113.0/24", "2001:db8:7::/48"];
  for (const order of [xs, [...xs].reverse(), [xs[4], xs[1], xs[5], xs[0], xs[3], xs[2]]]) assert.deepEqual(normalise(cs(order)), want);
});

test("normalise: a list is refused whole when it is empty, too broad, or touches your own network", () => {
  const why = (xs: string[]) => { try { normalise(cs(xs)); return "accepted"; } catch (e) { return (e as Error).message; } };
  assert.equal(why([]), "no IP ranges in it");
  assert.match(why(["192.0.2.0/24", "8.0.0.0/7"]), /wider than an IPv4 \/8/);
  assert.match(why(["2001::/15"]), /IPv6 \/16/);
  for (const local of ["10.1.0.0/16", "192.168.1.0/24", "172.0.0.0/8", "100.0.0.0/8", "127.0.0.1", "169.254.0.0/16", "224.0.0.0/8",
    "fe80::/64", "fd00::/16", "::ffff:a00:1", "2002:c0a8::/32", "64:ff9b::/96", "::1"]) {
    assert.match(why(["192.0.2.0/24", local]), /touches private, loopback, link-local or multicast space/, local);
  }
  for (const ok of ["11.0.0.0/8", "172.32.0.0/16", "100.128.0.0/10", "192.0.2.0/24", "2001:db8::/32", "2600:1f00::/24"]) assert.equal(why([ok]), "accepted", ok);
});

test("LOCAL_RANGES: every range starts and ends in space key sync refuses to fetch from", () => {
  const W = { 4: 32, 6: 128 } as const;
  for (const r of LOCAL_RANGES) {
    const last = { ...r, net: r.net | ((1n << BigInt(W[r.v] - r.bits)) - 1n), bits: W[r.v] };
    for (const a of [{ ...r, bits: W[r.v] }, last]) assert.ok(forbiddenAddress(dataLine(a)), `${formatCidr(r)}: ${dataLine(a)}`);
  }
  assert.ok(overlaps(c("172.0.0.0/8"), c("172.16.0.0/12")) && overlaps(c("172.16.5.0/24"), c("172.16.0.0/12")));
  assert.ok(!overlaps(c("172.32.0.0/16"), c("172.16.0.0/12")) && !overlaps(c("10.0.0.0/8"), c("::/96")));
});

test("versionOf: the operator's latest creationTime and our hash; changed only when the ranges change", () => {
  const at1 = new Date("2026-10-01T00:00:00Z"), at2 = new Date("2026-10-02T00:00:00Z");
  const v1 = versionOf(["192.0.2.0/24"], ["2026-09-01T00:00:00Z", "2026-09-30T00:00:00Z", null], ["https://b.example/1.json", "https://b.example/2.json"], at1);
  assert.match(v1.version, /^2026-09-30T00:00:00Z#[0-9a-f]{8}$/);
  assert.equal(v1.version.slice(-8), v1.sha256.slice(0, 8));
  assert.deepEqual([v1.ranges, v1.ipv4, v1.ipv6, v1.fetched, v1.changed], [1, 1, 0, at1.toISOString(), at1.toISOString()]);
  const same = versionOf(["192.0.2.0/24"], ["2026-09-30T00:00:00Z"], [], at2, v1);
  assert.equal(same.sha256, v1.sha256);
  assert.equal(same.changed, at1.toISOString(), "same ranges: still changed at the first fetch");
  assert.equal(same.fetched, at2.toISOString());
  const moved = versionOf(["192.0.2.0/25"], ["2026-09-30T00:00:00Z"], [], at2, v1);
  assert.notEqual(moved.version, v1.version, "same creationTime, different ranges: a different version");
  assert.equal(moved.changed, at2.toISOString());
  assert.match(versionOf(["192.0.2.0/24"], ["x' y", null], [], at1).version, /^undated#/, "a creationTime that could break a rule is not used");
});

test("assignSlots: a bot keeps its slot; a new bot takes the lowest never used; a removed bot's slot is not reused", () => {
  const first = assignSlots(["a", "b", "c"], {});
  assert.deepEqual(first, { a: 0, b: 1, c: 2 });
  const second = assignSlots(["c", "d", "a"], first);
  assert.deepEqual(second, { a: 0, b: 1, c: 2, d: 3 }, "b removed: its slot stays reserved");
  assert.deepEqual(assignSlots(["x"], { a: 0, b: 2 }), { a: 0, b: 2, x: 1 });
  const full = Object.fromEntries(Array.from({ length: MAX_SLOTS }, (_, i) => [`b${i}`, i]));
  assert.throws(() => assignSlots(["new"], full), /more than 175 bots/);
});

test("checkRules: the policy mode, tokens that can go into a rule, a key source key sync accepts", () => {
  assert.deepEqual(checkRules([{ name: "a", user_agent: ["ABot", "Better Stack Bot", "WhatsApp/", "archive.org_bot"] }], "log"), []);
  assert.deepEqual(checkRules([], "enforce"), []);
  assert.match(checkRules([], "block").join(), /policy_mode: "block": one of log, enforce/);
  for (const bad of ['A"Bot', "ABot ", " ABot", "A\\Bot", "A(Bot)", "A|B"]) assert.equal(checkRules([{ name: "a", user_agent: bad }], "log").length, 1, bad);
  assert.match(checkRules([{ name: "a", wba: "https://bot.example/a/path" }], "log").join(), /not a key directory origin or JWK Set URL/);
});

test("CONF: a before file that CRS loads after the verifier's own before file", () => {
  // CRS includes plugins/*-before.conf, then its rules, then plugins/*-after.conf;
  // each wildcard loads in name order (byte order, or a UTF-8 locale's order).
  assert.equal(CONF, "web-bot-auth-bots-before.conf");
  assert.ok(CONF.endsWith("-before.conf"), "runs before CRS's rules and every *-after.conf, such as site-wba-rules-after.conf");
  for (const order of [(a: string, b: string) => (a < b ? -1 : 1), (a: string, b: string) => a.localeCompare(b, "en")]) {
    assert.ok(order("web-bot-auth-before.conf", CONF) < 0, "the verifier's phase-2 results are final before these rules read them");
  }
});

const V = (version: string): ListVersion => ({ version, creationTime: null, sha256: "0".repeat(64), ranges: 1, ipv4: 1, ipv6: 0, urls: [], fetched: "", changed: "" });

test("generate: the claim, then per bot its claim, address check, signature and policy, each at its own ids", () => {
  const bots: Bot[] = [
    { name: "gbot", user_agent: ["GBot", "GBot-Image"], ips: "https://g.example/ips.json", policy: "allow" },
    { name: "never", user_agent: "NeverBot", ips: "https://n.example/ips.json", policy: "allow" },
    { name: "signer", wba: "https://agent.example", user_agent: "SignBot", policy: "deny", claim_only: true },
    { name: "twin", wba: "https://agent.example:443/" },
    { name: "logged", user_agent: "archive.org_bot", policy: "log" },
    { name: "shared", user_agent: "Shared-User", ips: "https://s.example/ips.json", policy: "allow", claim_only: true },
    { name: "rdns-only", rdns: ["r.example"] },
  ];
  const lists = new Map([["gbot", V("2026-10-01#aaaaaaaa")], ["shared", V("undated#bbbbbbbb")]]);
  const slots = assignSlots(bots.map((b) => b.name), {});
  const { conf, tokens } = generate({ bots, mode: "log", slots, lists, source: "bots.yaml" });
  assert.equal(tokens, "archive.org_bot\ngbot\ngbot-image\nneverbot\nshared-user\nsignbot\n");
  assert.match(conf, /^# web-bot-auth-bots-before\.conf: written by wba-keysync\/lists\.ts from bots\.yaml \(versions\.json says when\)\./);
  assert.match(conf, new RegExp(`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile ${DATA}/tokens\\.data" \\\\\n    "id:${CLAIM_RULE},phase:1,pass,nolog,t:none,t:lowercase,capture,${VERX},setvar:'tx\\.bot_claimed=%\\{TX\\.0\\}'"`));
  const id = (bot: string, n: number) => RULE_BASE + 4 * slots[bot] + n;
  const rule = (n: number) => conf.split("\n").filter((l) => l.includes(`"id:${n},`) || l.includes(`id:${n},`));
  // gbot: a list, so a claim starts as not-in-list and its address can make it verified.
  assert.match(conf, new RegExp(`SecRule TX:bot_claimed "@rx \\^\\(\\?:gbot\\|gbot-image\\)\\$" \\\\\n    "id:${id("gbot", 0)},phase:1,pass,nolog,t:none,${VERX},setvar:tx\\.bot_name=gbot,setvar:tx\\.bot_status=claimed,setvar:tx\\.bot_reason=not-in-list,setvar:'tx\\.bot_list_version=2026-10-01#aaaaaaaa'"`));
  assert.match(conf, new RegExp(`SecRule TX:bot_name "@streq gbot" "id:${id("gbot", 1)},phase:1,pass,nolog,t:none,${VERX},chain"\n    SecRule REMOTE_ADDR "@ipMatchFromFile ${DATA}/gbot\\.data" "t:none,setvar:tx\\.bot_status=verified,setvar:tx\\.bot_reason=ip-list"`));
  assert.match(conf, new RegExp(`id:${id("gbot", 3)},phase:2,.*,pass,log,msg:'Bot policy: \\(log mode, would refuse\\) claims to be gbot from an address not on its list',chain"\n    SecRule TX:bot_reason "@streq not-in-list"`));
  // never: a list URL that has never been fetched: no-list, no address check, no impostor rule.
  assert.match(conf, /# never: list never fetched; policy allow\n/);
  assert.match(conf, /setvar:tx\.bot_name=never,setvar:tx\.bot_status=claimed,setvar:tx\.bot_reason=no-list,setvar:'tx\.bot_list_version=none'/);
  assert.deepEqual([rule(id("never", 1)), rule(id("never", 3))], [[], []]);
  assert.match(conf, /# never: allow, but there is no list to check a claim against/);
  // signer: verified by its signature in phase 2; denied only when verified (claim only).
  assert.match(conf, new RegExp(`SecRule TX:wba_status "@streq verified" "id:${id("signer", 2)},phase:2,pass,nolog,t:none,${VERX},chain"\n    SecRule TX:wba_agent "@streq https://agent\\.example/\\.well-known/http-message-signatures-directory" "t:none,setvar:tx\\.bot_name=signer,setvar:tx\\.bot_status=verified,setvar:tx\\.bot_reason=signature,setvar:tx\\.bot_list_version=none"`));
  assert.match(conf, new RegExp(`id:${id("signer", 3)},phase:2,.*,pass,log,msg:'Bot policy: \\(log mode, would refuse\\) signer is refused',chain"\n    SecRule TX:bot_status "@streq verified"`));
  // twin: the same key source as signer, so a signature names signer.
  assert.match(conf, /# twin signs with signer's key source, so its signatures name signer/);
  assert.deepEqual(rule(id("twin", 2)), []);
  // logged: a token with a dot is escaped; a log policy only logs.
  assert.match(conf, /"@rx \^\(\?:archive\\\.org_bot\)\$"/);
  assert.match(conf, new RegExp(`id:${id("logged", 3)},phase:2,t:none,tag:'web-bot-auth-bots',${VERX},severity:'NOTICE',logdata:'%\\{tx\\.bot_status\\} by %\\{tx\\.bot_reason\\}, list %\\{tx\\.bot_list_version\\}',pass,log,msg:'Bot: logged'"`));
  // shared: a token others send too, so a claim from outside its list is not refused.
  assert.match(conf, /# shared: claim only, so a claim from outside its list is not refused/);
  assert.deepEqual(rule(id("shared", 3)), []);
  // rdns-only: nothing a rule can check yet.
  assert.doesNotMatch(conf, /rdns-only/);
  // Every id is in the block and used once.
  const ids = [...conf.matchAll(/id:(\d+)/g)].map((m) => Number(m[1]));
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.every((n) => n >= 9534150 && n <= 9534899));
  // Every rule names the release; every rule that logs carries a severity
  // (without one, ModSecurity v3 logs severity 0, "emergency"), and nothing else does.
  const starters = conf.split("\n").filter((l) => /"id:\d+,/.test(l));
  assert.equal(starters.length, ids.length);
  for (const l of starters) {
    assert.ok(l.includes(`ver:'${VER}'`), l);
    assert.equal(l.includes("severity:'NOTICE'"), /,log[,"]/.test(l), l);
  }
  assert.equal(conf.split("\n").filter((l) => /^ {4}SecRule /.test(l) && /ver:|severity:/.test(l)).length, 0, "a chained rule carries no ver or severity");
});

// wba.conf (the verifier's rules) and the generated rules name one release.
// Read from the repository; skipped while wba.conf's rules carry no ver yet.
const WBA_CONF = fileURLToPath(new URL("../lua/wba/wba.conf", import.meta.url));
const wbaVers = existsSync(WBA_CONF)
  ? readFileSync(WBA_CONF, "utf8").split("\n").filter((l) => !l.trimStart().startsWith("#")).flatMap((l) => [...l.matchAll(/ver:'([^']*)'/g)].map((m) => m[1]))
  : [];
(wbaVers.length ? test : test.skip)("generated rules carry the same ver as lua/wba/wba.conf"
  + (wbaVers.length ? "" : ` (skipped: ${existsSync(WBA_CONF) ? "no ver:'...' in lua/wba/wba.conf yet" : "lua/wba/wba.conf not found"}, nothing to compare)`), () => {
  assert.deepEqual([...new Set(wbaVers)], [VER], "change VER in lists.ts and every ver in wba.conf together");
});

test("generate: enforce mode refuses with 403; no tokens means no claim rule and no token file", () => {
  const bots: Bot[] = [{ name: "d", user_agent: "DBot", policy: "deny" }, { name: "s", wba: "https://s.example", policy: "deny" }];
  const g = generate({ bots, mode: "enforce", slots: { d: 0, s: 1 }, lists: new Map(), source: "b.yaml" });
  assert.match(g.conf, /id:9534203,phase:2,.*,deny,status:403,log,msg:'Bot policy: d is refused'"/);
  assert.match(g.conf, /# Policy mode: enforce\. Policies refuse with 403\./);
  const none = generate({ bots: [bots[1]], mode: "log", slots: { s: 0 }, lists: new Map(), source: "b.yaml" });
  assert.equal(none.tokens, "");
  assert.doesNotMatch(none.conf, /@pmFromFile/);
  assert.match(none.conf, /id:9534203,phase:2,.*,pass,log,msg:'Bot policy: \(log mode, would refuse\) s is refused'"/);
});

// --- Whole runs, against a fake server, in a temporary directory -------------------

const LIST = (prefixes: string[], creationTime = "2026-10-01T00:00:00Z") =>
  JSON.stringify({ creationTime, prefixes: prefixes.map((p) => (p.includes(":") ? { ipv6Prefix: p } : { ipv4Prefix: p })) });
type Route = { status?: number; type?: string; body: string };
const serve = (routes: Record<string, Route | undefined>) => (async (url: string) => {
  const r = routes[url];
  if (!r) return new Response("not found", { status: 404 });
  return new Response(r.body, { status: r.status ?? 200, headers: { "content-type": r.type ?? "application/json" } });
}) as unknown as typeof fetch;
const publicDns = async () => ["93.184.215.14"];
const G = "https://g.example/ips.json", T = "https://t.example/ips.txt";
const BOTS: Bot[] = [
  { name: "gbot", user_agent: "GBot", ips: G, policy: "allow" },
  { name: "tbot", user_agent: "TBot", ips: T },
];

async function run(dir: string, routes: Record<string, Route | undefined>, extra: Partial<Parameters<typeof runLists>[0]> = {}) {
  const lines: string[] = [];
  const code = await runLists({ bots: BOTS, mode: "log", source: "bots.yaml", out: dir, fetchImpl: serve(routes), resolve: publicDns,
    at: new Date("2026-10-11T00:00:00Z"), log: (l) => lines.push(l), ...extra });
  return { code, out: lines.join("\n") };
}
const read = (dir: string, f: string) => readFileSync(join(dir, f), "utf8");
const json = (dir: string, f: string) => JSON.parse(read(dir, f));

test("runLists: writes the rules, one data file per list, the token file, versions, ids and status", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-"));
  try {
    const r = await run(dir, { [G]: { body: LIST(["192.0.2.0/24", "2001:db8::/32"]) }, [T]: { type: "text/plain", body: "# monitors\n198.51.100.77\n\n198.51.100.0/28\n198.51.100.7\n" } });
    assert.equal(r.code, 0, r.out);
    assert.equal(read(dir, `${DATA}/gbot.data`), "192.0.2.0/24\n2001:db8::/32\n");
    assert.equal(read(dir, `${DATA}/tbot.data`), "198.51.100.0/28\n198.51.100.77\n", "198.51.100.7 is inside the /28");
    assert.equal(read(dir, `${DATA}/tokens.data`), "gbot\ntbot\n");
    assert.match(read(dir, CONF), /@ipMatchFromFile web-bot-auth-bots\/gbot\.data/);
    const v = json(dir, "versions.json");
    assert.match(v.gbot.version, /^2026-10-01T00:00:00Z#[0-9a-f]{8}$/);
    assert.match(v.tbot.version, /^undated#/);
    assert.deepEqual(json(dir, "ids.json"), { gbot: 0, tbot: 1 });
    assert.deepEqual(json(dir, "status.json").bots.map((b: { name: string; list: string }) => `${b.name}:${b.list}`), ["gbot:fetched", "tbot:fetched"]);
    assert.match(r.out, /== 2 lists: 2 fetched, 0 kept their previous version, 0 without a list/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("runLists: a list that fails keeps its previous version and file (exit 2); one never fetched has none", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-"));
  try {
    const good = { [G]: { body: LIST(["192.0.2.0/24"]) }, [T]: { type: "text/plain", body: "198.51.100.7\n" } };
    assert.equal((await run(dir, good)).code, 0);
    const before = read(dir, `${DATA}/gbot.data`), version = json(dir, "versions.json").gbot.version;
    for (const [what, route] of [["404", undefined], ["an empty list", { body: LIST([]) }], ["a private range", { body: LIST(["10.0.0.0/8"]) }],
      ["a redirect", { status: 301, body: "" }]] as const) {
      const r = await run(dir, { ...good, [G]: route });
      assert.equal(r.code, 2, what);
      assert.match(r.out, new RegExp(`kept  gbot: .*; keeping version ${version.replace(/[.+]/g, "\\$&")}`), what);
      assert.equal(read(dir, `${DATA}/gbot.data`), before, what);
      assert.equal(json(dir, "versions.json").gbot.version, version, what);
      assert.equal(json(dir, "status.json").bots[0].list, "kept", what);
    }
    const fresh = mkdtempSync(join(tmpdir(), "wba-lists-"));
    try {
      const r = await run(fresh, { [T]: good[T] });
      assert.equal(r.code, 2);
      assert.match(r.out, /none  gbot: HTTP 404; no list yet, so its claims are not checked against addresses/);
      assert.ok(!existsSync(join(fresh, DATA, "gbot.data")));
      assert.match(read(fresh, CONF), /setvar:tx\.bot_name=gbot,setvar:tx\.bot_status=claimed,setvar:tx\.bot_reason=no-list/);
    } finally { rmSync(fresh, { recursive: true, force: true }); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("runLists: a bot removed from the file loses its data file, and its ids stay reserved", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-"));
  try {
    const routes = { [G]: { body: LIST(["192.0.2.0/24"]) }, [T]: { type: "text/plain", body: "198.51.100.7\n" } };
    await run(dir, routes);
    const r = await run(dir, routes, { bots: [BOTS[1]] });
    assert.equal(r.code, 0, r.out);
    assert.ok(!existsSync(join(dir, DATA, "gbot.data")));
    assert.ok(!("gbot" in json(dir, "versions.json")));
    assert.deepEqual(json(dir, "ids.json"), { gbot: 0, tbot: 1 });
    assert.doesNotMatch(read(dir, CONF), /gbot/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("runLists: a failed check or reload puts every file back, so the next run tries again", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-"));
  try {
    const routes = { [G]: { body: LIST(["192.0.2.0/24"]) }, [T]: { type: "text/plain", body: "198.51.100.7\n" } };
    await run(dir, routes);
    const files = [CONF, `${DATA}/gbot.data`, `${DATA}/tbot.data`, `${DATA}/tokens.data`, "versions.json", "ids.json", "status.json"];
    const before = files.map((f) => read(dir, f));
    const changed = { [G]: { body: LIST(["192.0.2.0/25"], "2026-10-02T00:00:00Z") }, [T]: routes[T] };
    const r = await run(dir, changed, { bots: [...BOTS, { name: "new", user_agent: "NewBot", ips: "https://new.example/ips.json" }], check: "echo nginx: [emerg] bad >&2; exit 1", at: new Date("2026-10-12T00:00:00Z") });
    assert.equal(r.code, 1);
    assert.match(r.out, /FAIL  check \(.*\) failed, every file put back as it was:\nnginx: \[emerg\] bad/);
    assert.deepEqual(files.map((f) => read(dir, f)), before);
    const marker = join(dir, "reloaded");
    const ok = await run(dir, changed, { check: "true", reload: `touch '${marker}'` });
    assert.equal(ok.code, 0, ok.out);
    assert.ok(existsSync(marker));
    assert.equal(read(dir, `${DATA}/gbot.data`), "192.0.2.0/25\n");
    const same = await run(dir, changed, { check: "exit 1", reload: "exit 1", at: new Date("2026-10-13T00:00:00Z") });
    assert.equal(same.code, 0, "nothing the WAF reads changed: neither command runs");
    assert.match(same.out, /ok    the rules and lists are unchanged: no check or reload needed/);
    assert.equal(json(dir, "versions.json").gbot.fetched, "2026-10-13T00:00:00.000Z", "versions.json still records the fetch");
    const newer = { ...changed, [G]: { body: LIST(["192.0.2.0/26"]) } };
    const failed = await run(dir, newer, { check: "true", reload: "exit 3" });
    assert.equal(failed.code, 1);
    assert.match(failed.out, /FAIL  reload \(exit 3\) failed, every file put back as it was, so the next run tries again/);
    assert.equal(read(dir, `${DATA}/gbot.data`), "192.0.2.0/25\n", "the files match what the WAF still runs");
    const again = join(dir, "reloaded-again");
    const retried = await run(dir, newer, { check: "true", reload: `touch '${again}'` });
    assert.equal(retried.code, 0, retried.out);
    assert.ok(existsSync(again), "the next run reloads: the list the WAF never loaded is still new to it");
    assert.equal(read(dir, `${DATA}/gbot.data`), "192.0.2.0/26\n");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("runLists: the after file an older lists.ts wrote is removed with the new write, and put back if the check fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-"));
  try {
    const routes = { [G]: { body: LIST(["192.0.2.0/24"]) }, [T]: { type: "text/plain", body: "198.51.100.7\n" } };
    const old = join(dir, OLD_CONF);
    const oldText = `# ${OLD_CONF}: written by wba-keysync/lists.ts from bots.yaml (versions.json says when).\nSecRule TX:bot_name "@streq gbot" "id:9534203,phase:2,pass,log"\n`;
    writeFileSync(old, oldText);
    const failed = await run(dir, routes, { check: "exit 1" });
    assert.equal(failed.code, 1, failed.out);
    assert.match(failed.out, new RegExp(`ok    removed ${OLD_CONF.replace(/\./g, "\\.")}, which an older lists.ts wrote: the rules are now ${CONF.replace(/\./g, "\\.")}`));
    assert.equal(read(dir, OLD_CONF), oldText, "the check failed: the old rules are back");
    assert.ok(!existsSync(join(dir, CONF)), "and the new ones gone, so the WAF loads one set");
    const ok = await run(dir, routes, { check: "true" });
    assert.equal(ok.code, 0, ok.out);
    assert.ok(!existsSync(old) && existsSync(join(dir, CONF)));
    // A file of that name that lists.ts did not write (an operator's own Include line) is left alone.
    const mine = "# plugins/web-bot-auth-bots-after.conf\nInclude /etc/modsecurity.d/bots/web-bot-auth-bots-after.conf\n";
    writeFileSync(old, mine);
    const again = await run(dir, routes, { check: "true" });
    assert.doesNotMatch(again.out, /removed/);
    assert.equal(read(dir, OLD_CONF), mine);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("runLists: a bad file writes nothing; a private host is refused unless named with --allow-private-origin", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-"));
  try {
    const bad = await run(dir, {}, { bots: [{ name: "a", user_agent: "ABot", policy: "block" as Bot["policy"] }] });
    assert.equal(bad.code, 1);
    assert.match(bad.out, /FAIL  a: policy: "block": one of allow, deny, log/);
    assert.ok(!existsSync(join(dir, CONF)));
    const mode = await run(dir, {}, { mode: "on" });
    assert.match(mode.out, /policy_mode: "on": one of log, enforce/);
    const local = { bots: [BOTS[0]], resolve: async () => ["127.0.0.1"] };
    const refused = await run(dir, { [G]: { body: LIST(["192.0.2.0/24"]) } }, local);
    assert.match(refused.out, /none  gbot: g\.example resolves to 127\.0\.0\.1, a private, loopback or link-local address/);
    const allowed = await run(dir, { [G]: { body: LIST(["192.0.2.0/24"]) } }, { ...local, allow: new Set(["https://g.example"]) });
    assert.equal(allowed.code, 0, allowed.out);
    assert.match(allowed.out, /WARN  gbot: https:\/\/g\.example fetched without the private-address check/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("lists.ts: a token file and data files the WAF reads as written (no comments, no blank lines)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-lists-"));
  try {
    await run(dir, { [G]: { body: LIST(["192.0.2.0/24"]) }, [T]: { type: "text/plain", body: "# c\n\n198.51.100.7\n" } });
    for (const f of ["tokens.data", "gbot.data", "tbot.data"]) {
      const text = read(dir, `${DATA}/${f}`);
      assert.ok(text.endsWith("\n") && !text.split("\n").slice(0, -1).some((l) => l === "" || l.startsWith("#")), f);
    }
    writeFileSync(join(dir, DATA, "stray.data"), "192.0.2.1\n"); // not a bot: removed on the next run
    await run(dir, { [G]: { body: LIST(["192.0.2.0/24"]) }, [T]: { type: "text/plain", body: "198.51.100.7\n" } });
    assert.ok(!existsSync(join(dir, DATA, "stray.data")));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
