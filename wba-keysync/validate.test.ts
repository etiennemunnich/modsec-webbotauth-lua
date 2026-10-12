// validate.test.ts: the registry validator. Ranges and drift are checked
// against values worked out by hand below; the network checks run against a
// fake server, including a key directory made with the runtime's WebCrypto.
// Runs unchanged under `bun test` and `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEntries, checkSources, drift, embeddedList, extractCidrs, formatCidr, parseCidr, textList, type Bot } from "./validate.ts";
import { MEDIA_TYPE } from "./keysync.ts";

const fmt = (s: string) => { const c = parseCidr(s); return c ? formatCidr(c) : null; };

test("IP ranges: parsed, masked to the network, written canonically (RFC 5952 for IPv6)", () => {
  assert.equal(fmt("10.1.2.3/24"), "10.1.2.0/24");
  assert.equal(fmt("192.0.2.7"), "192.0.2.7/32");
  assert.equal(fmt("2001:DB8::1/32"), "2001:db8::/32");
  assert.equal(fmt("2001:db8:0:0:1:0:0:1/128"), "2001:db8::1:0:0:1/128"); // the first of two equal zero runs
  assert.equal(fmt("2001:db8:0:1:1:1:1:1/128"), "2001:db8:0:1:1:1:1:1/128"); // a single zero group is not compressed
  assert.equal(fmt("::/0"), "::/0");
  for (const bad of ["10.0.0.256/24", "1.2.3/24", "01.2.3.4/8", "10.0.0.0/33", "::1::/64", "2001:db8::/129", "10.0.0.0/24/1", "2026-09-22T00:00:00"]) {
    assert.equal(parseCidr(bad), null, bad);
  }
});

test("extractCidrs: every range in an operator's JSON, whatever the shape, nothing else", () => {
  const doc = {
    creationTime: "2026-09-22T00:00:00.000000", syncToken: "1695000000000",
    prefixes: [{ ipv4Prefix: "66.249.64.0/27" }, { ipv6Prefix: "2001:4860:4801:10::/64" }, { ipv4Prefix: "66.249.64.0/27" }],
    extra: ["192.0.2.0/24", "not a range", "1.0"],
  };
  assert.deepEqual(extractCidrs(doc).map(formatCidr).sort(), ["192.0.2.0/24", "2001:4860:4801:10::/64", "66.249.64.0/27"]);
});

test("drift: exact, stale, missing, and the share of live IPv4 addresses a hand-kept copy covers", () => {
  const p = (xs: string[]) => xs.map((x) => parseCidr(x)!);
  const d = drift(p(["10.0.0.0/25", "192.0.2.0/24", "2001:db8::/32"]), p(["10.0.0.0/24", "198.51.100.0/24", "2001:db8::/32"]));
  assert.equal(d.exact, 1);
  assert.deepEqual(d.stale, ["10.0.0.0/25", "192.0.2.0/24"]);
  assert.deepEqual(d.missing, ["10.0.0.0/24", "198.51.100.0/24"]);
  assert.equal(d.v4Coverage, 25); // 128 of the live 512 IPv4 addresses
  assert.equal(drift(p(["10.0.0.0/24"]), p(["10.0.0.0/25", "10.0.0.128/25"])).v4Coverage, 100); // adjacent live ranges merge
  assert.equal(drift(p([]), p(["2001:db8::/32"])).v4Coverage, null); // no IPv4 to cover
});

test("checkEntries: names, https only, DNS suffixes, User-Agent tokens and examples, hand-kept ranges", () => {
  const levels = (bots: Bot[]) => checkEntries(bots)
    .filter((f) => f.check !== "category" && f.check !== "docs") // the next test covers these
    .map((f) => `${f.level} ${f.check}`);
  assert.deepEqual(levels([{ name: "ok-bot", ips: "https://bot.example/ips.json", user_agent: "OkBot/", user_agent_example: "Mozilla/5.0 (compatible; OkBot/1.0)" }]), []);
  assert.deepEqual(levels([{ name: "a", ips: "https://x.example/a.json" }, { name: "a", ips: "https://x.example/b.json" }]), ["fail name"]);
  assert.deepEqual(levels([{ name: "b", ips: "http://x.example/a.json" }]), ["fail url"]);
  assert.deepEqual(levels([{ name: "c", wba: "https://x.example", rdns: ["googlebot.com", "*.evil", "http://x"] }]), ["fail rdns", "fail rdns"]);
  assert.deepEqual(levels([{ name: "d", user_agent: "DBot/", user_agent_example: "Mozilla/5.0 (OtherBot/1)" }]), ["fail user_agent", "warn user_agent"]);
  assert.deepEqual(levels([{ name: "e", ips: "https://x.example/a.json", cidrs: ["10.0.0.0/24", "nope"] }]), ["fail cidrs"]);
  assert.deepEqual(levels([{ name: "Bad Name", ips: "https://x.example/a.json" }]), ["fail name"]);
  assert.deepEqual(levels([{ name: "f" }]), ["fail entry"]);
});

test("embeddedList: the standard IP document inside an HTML page, and nothing else from HTML", () => {
  const page = `<html><body><h1>IPs</h1><p>Example: 192.0.2.1</p><pre>{
  "creationTime": "2026-09-08T05:24:10+00:00",
  "prefixes": [ { "ipv4Prefix": "3.81.245.78" }, { "ipv4Prefix": "100.24.134.117" } ]
}</pre><script>var x = "{";</script></body></html>`;
  assert.deepEqual(extractCidrs(embeddedList(page)).map(formatCidr).sort(), ["100.24.134.117/32", "3.81.245.78/32"]);
  assert.throws(() => embeddedList("<html><p>Our crawler uses 192.0.2.1</p></html>"), /no embedded IP list/);
  assert.throws(() => embeddedList('<html><p>"prefixes" are listed elsewhere</p></html>'), /not in a JSON object/);
});

// Every test host resolves to one public address, so the address guard passes them.
const publicDns = async () => ["93.184.215.14"];
const check = (b: Bot, fetchImpl: typeof fetch) => checkSources(b, fetchImpl, undefined, publicDns);

/** A fake server: url -> response. */
// It follows a redirect when asked to (redirect: "follow"), as fetch does, so a
// caller that stopped asking for "manual" would be caught.
const server = (routes: Record<string, () => Response>) => {
  const get = async (url: string, init?: RequestInit): Promise<Response> => {
    const r = routes[url];
    const res = r ? r() : new Response("not found", { status: 404 });
    const to = res.headers.get("location");
    return res.status >= 300 && res.status < 400 && to && init?.redirect !== "manual" ? get(new URL(to, url).href, init) : res;
  };
  return get as unknown as typeof fetch;
};

test("checkSources: the live list, a redirect refused, drift of a hand-kept copy", async () => {
  const fetchImpl = server({
    "https://bot.example/ips.json": () => Response.json({ creationTime: "2026-10-01T00:00:00Z", prefixes: [{ ipv4Prefix: "10.0.0.0/24" }, { ipv4Prefix: "10.0.1.0/24" }] }),
    "https://bot.example/moved.json": () => new Response(null, { status: 301, headers: { location: "https://www.bot.example/ips.json" } }),
  });
  const f = await check({ name: "b", ips: ["https://bot.example/ips.json", "https://bot.example/moved.json"], cidrs: ["10.0.0.0/24", "10.9.9.0/24"] }, fetchImpl);
  assert.equal(f[0].level, "ok");
  assert.match(f[0].detail, /2 ranges \(2 IPv4, 0 IPv6\), 2026-10-01/);
  assert.equal(f[1].level, "fail");
  assert.match(f[1].detail, /HTTP 301 to https:\/\/www\.bot\.example\/ips\.json: not followed/);
  assert.equal(f[2].check, "cidrs");
  assert.equal(f[2].level, "warn");
  assert.match(f[2].detail, /1 exact, 1 stale, 1 missing, covers 50% of the live IPv4 addresses; stale: 10\.9\.9\.0\/24/);
});

test("checkSources: a key directory, as key sync reads it", async () => {
  const kp = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const dir = "https://agent.example/.well-known/http-message-signatures-directory";
  const body = JSON.stringify({ keys: [{ kty: pub.kty, crv: pub.crv, x: pub.x }] });
  const ok = await check({ name: "a", wba: "https://agent.example" },
    server({ [dir]: () => new Response(body, { headers: { "content-type": MEDIA_TYPE } }) }));
  assert.equal(ok[0].level, "ok");
  assert.match(ok[0].detail, /1 usable key\(s\); proof none/);
  const wrongType = await check({ name: "a", wba: "https://agent.example" },
    server({ [dir]: () => new Response(body, { headers: { "content-type": "application/json" } }) }));
  assert.equal(wrongType[0].level, "fail");
  assert.match(wrongType[0].detail, /content-type "application\/json"/);
  const moved = await check({ name: "a", wba: "https://agent.example" },
    server({ [dir]: () => new Response(null, { status: 301, headers: { location: "https://www.agent.example/x" } }) }));
  assert.equal(moved[0].level, "fail");
  assert.match(moved[0].detail, /HTTP 301.*to https:\/\/www\.agent\.example\/x/);
});

test("checkEntries: a known category, AIPREF purpose labels, and operator documentation", () => {
  const levels = (bots: Bot[]) => checkEntries(bots).map((x) => `${x.level} ${x.check}`);
  const base = { name: "a", ips: "https://x.example/a.json", docs: "https://x.example/bot" };
  assert.deepEqual(levels([{ ...base, category: "search" }]), []);
  assert.deepEqual(levels([{ ...base, category: "crawler" }]), ["fail category"]);
  assert.deepEqual(levels([{ ...base, category: "toString" }]), ["fail category"]);
  assert.deepEqual(levels([{ ...base, category: "search", purpose: ["train-ai", "tdm"] }]), ["fail purpose"]);
  assert.deepEqual(levels([{ name: "a", ips: "https://x.example/a.json", category: "search" }]), ["warn docs"]);
  assert.deepEqual(levels([{ ...base, category: "search", docs: "http://x.example/bot" }]), ["fail url"]);
  assert.deepEqual(levels([{ ...base }]), ["warn category"]);
});

test("checkSources: documentation pages: 200 is ok; a redirect or a refusal is a warning, never a failure", async () => {
  const fetchImpl = server({
    "https://x.example/ok": () => new Response("<html>bot</html>", { status: 200 }),
    "https://x.example/moved": () => new Response(null, { status: 301, headers: { location: "https://x.example/new" } }),
    "https://x.example/blocked": () => new Response("no", { status: 403 }),
  });
  const r = await check({ name: "a", docs: ["https://x.example/ok", "https://x.example/moved", "https://x.example/blocked"] }, fetchImpl);
  assert.deepEqual(r.map((x) => [x.check, x.level]), [["docs", "ok"], ["docs", "warn"], ["docs", "warn"]]);
  assert.match(r[1].detail, /HTTP 301 to https:\/\/x\.example\/new; list the final URL/);
  assert.match(r[2].detail, /HTTP 403 \(refuses scripted fetches: check it by hand\)/);
});

test("textList: one address or range per line, comments and blank lines skipped; any other line refuses the list", async () => {
  assert.deepEqual(extractCidrs(textList("# probes\r\n3.12.251.153\n\n2001:db8::1\n  192.0.2.0/24  \n")).map(formatCidr),
    ["3.12.251.153/32", "2001:db8::1/128", "192.0.2.0/24"]);
  assert.throws(() => textList("3.12.251.153\nOur probes use the addresses above.\n"), /line 2 is not an IP address or range/);
  const f = await check({ name: "t", ips: "https://t.example/ips.txt" },
    server({ "https://t.example/ips.txt": () => new Response("192.0.2.1\n192.0.2.2\n", { headers: { "content-type": "text/plain; charset=utf-8" } }) }));
  assert.equal(f[0].level, "ok");
  assert.match(f[0].detail, /2 ranges \(2 IPv4, 0 IPv6\)/);
});

test("embeddedList: a page that starts with a brace and holds no list object ends, quickly (Forge F3)", () => {
  const t0 = Date.now();
  for (const page of ['{"prefixes":x}', '{"prefixes": [', "{".repeat(3000) + '"prefixes"']) assert.throws(() => embeddedList(page));
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
});

test("checkSources: a private, loopback or link-local host is refused before any fetch (draft 6.7; Forge F2)", async () => {
  let fetched = 0;
  const count = (async () => { fetched++; return new Response("{}"); }) as unknown as typeof fetch;
  const r = await checkSources({ name: "p", docs: "https://intranet.example/", ips: "https://intranet.example/ips.json", wba: "https://intranet.example" },
    count, undefined, async () => ["10.0.0.5"]);
  assert.equal(fetched, 0);
  assert.deepEqual(r.map((x) => [x.check, x.level]), [["docs", "warn"], ["ips", "fail"], ["wba", "fail"]]);
  assert.match(r[1].detail, /private, loopback or link-local/);
});

test("checkSources: a list holding a range wider than an IPv4 /8 or IPv6 /16 is refused (Forge F7)", async () => {
  const r = await check({ name: "w", ips: "https://w.example/ips.json" },
    server({ "https://w.example/ips.json": () => Response.json({ prefixes: [{ ipv4Prefix: "0.0.0.0/0" }, { ipv6Prefix: "::/0" }] }) }));
  assert.equal(r[0].level, "fail");
  assert.match(r[0].detail, /wider than \/8 \(IPv4\) or \/16 \(IPv6\), such as 0\.0\.0\.0\/0: refused/);
});

test("checkSources: a list over 4 MiB is refused without being read whole (Forge F4)", async () => {
  const big = () => new Response(new ReadableStream({ start(c) { for (let i = 0; i < 80; i++) c.enqueue(new Uint8Array(65536)); c.close(); } }),
    { headers: { "content-type": "application/json" } });
  const r = await check({ name: "b", ips: "https://b.example/ips.json" }, server({ "https://b.example/ips.json": big }));
  assert.deepEqual([r[0].level, r[0].detail], ["fail", "https://b.example/ips.json: larger than 4 MiB"]);
});

test("checkSources: a list whose body fails mid-read keeps its own error, not \"larger than 4 MiB\"", async () => {
  const broken = () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(10)); c.error(new Error("connection reset")); } }),
    { headers: { "content-type": "application/json" } });
  const r = await check({ name: "b", ips: "https://b.example/ips.json" }, server({ "https://b.example/ips.json": broken }));
  assert.equal(r[0].level, "fail");
  assert.match(r[0].detail, /connection reset/);
  assert.doesNotMatch(r[0].detail, /4 MiB/);
});

test("checkEntries: policy, claim_only and robots fields; a token that would claim two bots", () => {
  const fails = (bots: Bot[]) => checkEntries(bots).filter((f) => f.level === "fail").map((f) => `${f.bot} ${f.check}: ${f.detail}`);
  assert.deepEqual(fails([{ name: "a", user_agent: "ABot", policy: "deny", claim_only: true, robots: ["ABot", "A-Extended", "archive.org_bot"] }]), []);
  assert.match(fails([{ name: "a", user_agent: "ABot", policy: "block" as Bot["policy"] }]).join(), /a policy: "block": one of allow, deny, log/);
  assert.match(fails([{ name: "a", user_agent: "ABot", claim_only: "yes" as unknown as boolean }]).join(), /claim_only: true or false/);
  assert.match(fails([{ name: "a", user_agent: "ABot", robots: "A Bot" }]).join(), /"A Bot": a robots\.txt product token/);
  assert.equal(checkEntries([{ name: "a", claim_only: true, ips: "https://a.example/ips.json" }]).filter((f) => f.check === "claim_only")[0]?.level, "warn");
  // One bot may list a token inside another of its own; across bots it is ambiguous, whatever the case.
  assert.deepEqual(fails([{ name: "g", user_agent: ["GBot", "GBot-Image"] }]), []);
  assert.match(fails([{ name: "g", user_agent: "GBot" }, { name: "n", user_agent: "gbot-news" }]).join(),
    /g user_agent: token "gbot" is also inside n's "gbot-news": a User-Agent with that token would claim both bots/);
  assert.equal(fails([{ name: "x", user_agent: "Same" }, { name: "y", user_agent: "same" }]).length, 2);
});
