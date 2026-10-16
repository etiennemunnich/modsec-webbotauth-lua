/**
 * report.ts: what each bot in a bots file can prove, what your WAF has seen
 * from it, and a decisions block to edit. For the operator choosing, bot by
 * bot, what to allow, deny or just log.
 *
 *   bun wba-keysync/report.ts bots.yaml [--log waf.log ...] [--out report.md]
 *   bun wba-keysync/report.ts bots.yaml --catalogue [--out BOTS.md]
 *
 * For each bot it checks the operator's own sources live (validate.ts) and
 * lists the proofs the bot supports, strongest first:
 *   signature  it signs requests (Web Bot Auth) with keys its directory serves
 *   ip-list    its operator publishes the addresses it uses
 *   rdns       its operator documents reverse-DNS names
 *   user-agent a token in the User-Agent: a claim anyone can send
 * With --log (the WAF's JSON log, any lines around it ignored), it adds the
 * signed traffic seen: requests verified per bot, and why the rest failed.
 * It ends with a decisions block: one line per bot, policy "log" until you
 * change it; copy each choice into the bot's entry in bots.yaml, where
 * lists.ts reads it.
 * With --catalogue it writes the catalogue instead (the project's BOTS.md):
 * each bot's category and why, its operator's own words, every source and
 * what it answered, its level and its status.
 */
import { readFileSync } from "node:fs";
import { CATEGORIES, checkEntries, checkSources, type Bot, type Finding } from "./validate.ts";
import { directoryIdentifier, urlIdentifier } from "./identifier.ts";

type Proof = "signature" | "ip-list" | "rdns" | "user-agent";
const STRENGTH: Proof[] = ["signature", "ip-list", "rdns", "user-agent"];
const asList = <T>(x: T | T[] | undefined): T[] => (x === undefined ? [] : Array.isArray(x) ? x : [x]);

export interface Evidence { bot: Bot; proofs: Proof[]; notes: string[] }

/**
 * The proofs a bot supports, from its entry and the live checks of its
 * sources. An entry that fails its own checks supports none: its sources were
 * never fetched. An IP list counts only if one loaded and none failed.
 */
export function evidence(b: Bot, findings: Finding[]): Evidence {
  const mine = findings.filter((f) => f.bot === b.name);
  const ok = (check: string) => mine.some((f) => f.check === check && f.level !== "fail");
  const broken = checkEntries([b]).some((f) => f.level === "fail");
  const proofs: Proof[] = [];
  const ips = mine.filter((f) => f.check === "ips");
  if (!broken) {
    if (b.wba && ok("wba")) proofs.push("signature");
    if (ips.some((f) => f.level === "ok") && ips.every((f) => f.level !== "fail")) proofs.push("ip-list");
    if (asList(b.rdns).length > 0) proofs.push("rdns");
    if (asList(b.user_agent).length > 0) proofs.push("user-agent");
  }
  const notes = mine.filter((f) => f.level !== "ok" && !(f.check === "user_agent" && f.level === "warn")).map((f) => `${f.check}: ${f.detail}`);
  return { bot: b, proofs: STRENGTH.filter((p) => proofs.includes(p)), notes };
}

export interface Traffic { total: number; byAgent: Map<string, { verified: number; granted: number }>; failures: Map<string, number> }

/** Signed requests in WAF log text: verified ones per agent identifier, the others by status/reason. */
export function traffic(text: string): Traffic {
  const t: Traffic = { total: 0, byAgent: new Map(), failures: new Map() };
  for (const raw of text.split("\n")) {
    // Only a line that is the plugin's JSON from its first character: wba_log.lua
    // writes whole lines, and a line that merely contains the text (a logged
    // request header, say) is someone else's and could be forged.
    const line = raw.trim();
    if (!line.startsWith('{"event":"web-bot-auth"')) continue;
    let j: { status?: string; reason?: string; agent?: string | null; granted?: boolean };
    try { j = JSON.parse(line); } catch { continue; }
    t.total++;
    if (j.status === "verified" && j.agent) {
      const a = t.byAgent.get(j.agent) ?? { verified: 0, granted: 0 };
      a.verified++;
      if (j.granted) a.granted++;
      t.byAgent.set(j.agent, a);
    } else {
      const k = `${j.status}/${j.reason || (j.status === "verified" ? "url-less" : "")}`;
      t.failures.set(k, (t.failures.get(k) ?? 0) + 1);
    }
  }
  return t;
}

/** The identifier a bot's verified requests are logged under (its directory or JWK Set URL). */
export const agentId = (b: Bot) =>
  b.wba ? (b.wba_type === "jwks_uri" ? urlIdentifier(b.wba) : directoryIdentifier(b.wba)) ?? undefined : undefined;

/**
 * Text from a bots file or the network, made inert in Markdown: control
 * characters become spaces and Markdown's metacharacters are escaped, so a
 * name or quote cannot add headings, links, images or table cells.
 */
const text = (s: string) => s.replace(/[\x00-\x1f\x7f]/g, " ").replace(/([\\`*_{}[\]<>()#+!|~])/g, "\\$1"); // eslint-disable-line no-control-regex -- strips control characters from a remote value before printing it
const cell = text;
/** An https URL as an autolink; anything else as inert text. */
const link = (u: string) => { try { const x = new URL(u); return x.protocol === "https:" ? `<${x.href}>` : text(u); } catch { return text(u); } };
const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** The report, as Markdown. */
export function render(evs: Evidence[], t?: Traffic): string {
  const out: string[] = ["# Bot report", "", `Generated ${new Date().toISOString()}. Proofs are checked live against each bot's own sources.`, ""];
  out.push("| Bot | Operator | Category | Can prove | Strongest | Notes |", "|---|---|---|---|---|---|");
  for (const e of evs) {
    out.push(`| ${cell(e.bot.name)} | ${cell(e.bot.operator ?? "")} | ${cell(e.bot.category ?? "")} | ${e.proofs.join(", ") || "nothing"} | `
      + `${e.proofs[0] ?? "none"}${e.proofs[0] === "user-agent" ? " (claim only)" : ""} | ${cell(e.notes.join("; "))} |`);
  }
  if (t) {
    out.push("", "## Signed traffic in your log", "", `${t.total} signed request(s).`, "", "| Bot | Verified requests | Of which granted |", "|---|---|---|");
    const known = new Map(evs.map((e) => [agentId(e.bot), e.bot.name]));
    for (const [agent, a] of [...t.byAgent].sort((x, y) => y[1].verified - x[1].verified)) {
      const who = known.get(agent);
      out.push(`| ${who ? cell(who) : `${cell(agent)} (not in your list)`} | ${a.verified} | ${a.granted} |`);
    }
    if (t.failures.size) {
      out.push("", "| Not verified (status/reason) | Requests |", "|---|---|");
      for (const [k, n] of [...t.failures].sort((x, y) => y[1] - x[1])) out.push(`| ${cell(k)} | ${n} |`);
    }
  }
  out.push("", "## Your decisions", "",
    "policy: allow (refuse whoever claims the bot from outside its IP list), deny, or log (record only, the default).",
    "Copy each choice into the bot's entry in your bots file as `policy:`; lists.ts writes the rules from there.", "", "```yaml", "decisions:");
  // Only well-formed names (a name is a YAML key here), and only bots that can prove something.
  for (const e of evs.filter((x) => NAME.test(x.bot.name) && x.proofs.length > 0)) {
    out.push(`  ${e.bot.name}: { policy: log }  # can prove: ${e.proofs.join(", ")}`);
  }
  out.push("```", "");
  return out.join("\n");
}

/**
 * How far a bot's identity can be checked, from its strongest proof:
 *   verified    a signature or IP list, fetched live and usable
 *   documented  reverse DNS only: the operator documents the names; checking
 *               a request against them takes a forward-confirmed DNS lookup
 *               per request, which the plugin does not do
 *   claim only  a User-Agent token, which anyone can send
 *   unverified  every source listed failed
 */
export type Status = "verified" | "documented" | "claim only" | "unverified";
export const status = (e: Evidence): Status =>
  e.proofs[0] === "signature" || e.proofs[0] === "ip-list" ? "verified"
    : e.proofs[0] === "rdns" ? "documented" : e.proofs[0] === "user-agent" ? "claim only" : "unverified";

const STATUS_MEANING: Record<Status, string> = {
  verified: "its signature keys or IP list were fetched from the operator and are usable",
  documented: `reverse DNS only: the operator documents the names; checking them takes a forward-confirmed DNS lookup, which this project does not do yet (planned: offline, never inside a request; see "Reverse DNS" above)`,
  "claim only": "a User-Agent token only, which anyone can send",
  unverified: "every source listed failed when checked",
};
const PROOF_MEANING: Record<Proof, string> = {
  signature: "signs its requests (Web Bot Auth) with keys from its own key directory",
  "ip-list": "its operator publishes the addresses it sends from",
  rdns: "its operator documents the reverse-DNS names of its addresses (this project does not check them yet)",
  "user-agent": "a token in the User-Agent header",
};

/**
 * Why the catalogue's bots are not checked by reverse DNS inside requests.
 */
const RDNS_NOTE = [
  "## Reverse DNS", "",
  "Some operators publish no IP list, only the reverse-DNS names of their crawlers (Baidu, Yandex, Kagi, Scientific Advisor). "
  + "Checking such a claim takes a DNS lookup and a second lookup to confirm it, so this project does not do it inside a request: "
  + "it uses each operator's published IP list, compiled when the WAF starts, and Web Bot Auth signatures. "
  + "Reverse DNS is not built. When it is, it will run offline in the sync tool and be reviewed, never inside a request. "
  + "This project does not use CRS's fake-bot plugin, which checks reverse DNS while the request waits.",
];

/**
 * The catalogue: every bot with its category and why, the operator's own
 * words, its sources and what each answered, and its level and status. The
 * project's BOTS.md is this, generated from bots.seed.yaml.
 */
export function catalogue(evs: Evidence[], findings: Finding[], at = new Date()): string {
  const day = at.toISOString().slice(0, 10);
  const out: string[] = [
    "# Bot catalogue", "",
    `Generated ${at.toISOString()} by \`bun wba-keysync/report.ts wba-keysync/bots.seed.yaml --catalogue --out wba-keysync/BOTS.md\`, `
    + "which fetches every source below. Do not edit it by hand: edit `bots.seed.yaml` and regenerate.", "",
    "Every source is the bot operator's own (first party). An aggregator may have led us to a bot; it is never the source.", "",
    ...RDNS_NOTE, "",
    "## How to read it", "",
    "**Level:** the strongest proof the bot supports, strongest first.", "",
    "| Level | Meaning |", "|---|---|", ...STRENGTH.map((p) => `| ${p} | ${PROOF_MEANING[p]} |`), "",
    `**Status:** what the check on ${day} found.`, "",
    "| Status | Meaning |", "|---|---|", ...(Object.keys(STATUS_MEANING) as Status[]).map((s) => `| ${s} | ${STATUS_MEANING[s]} |`), "",
    "**Category:** a grouping, each defined on the two axes of a Signature Agent Card (draft-meunier-webbotauth-registry-03 3.2.4, 3.2.5): "
    + "trigger (`crawler` acts on its own, `fetcher` because a user asked) and purpose, from the IETF AIPREF vocabulary "
    + "(draft-ietf-aipref-vocab-08: `train-ai`, `ai-use`, `search`). AIPREF names AI and search uses only. "
    + "Why a bot is in its category: the category's meaning, matched to what its operator says it does (quoted under each bot). "
    + "Two AIPREF readings are still open: whether a page a user named by URL is `ai-use` (vocab-08 4.2, issue 249), "
    + "and whether an AI search index is `search` (4.3 excludes generated summaries). The labels below are the likelier reading.", "",
    "| Category | Trigger | AIPREF purpose | Meaning | Bots |", "|---|---|---|---|---|",
  ];
  for (const [name, c] of Object.entries(CATEGORIES)) {
    out.push(`| ${name} | ${c.trigger} | ${c.purpose.join(", ") || "none"} | ${c.meaning} | ${evs.filter((e) => e.bot.category === name).length} |`);
  }
  out.push("", "## Summary", "", "| Bot | Operator | Category | Level | Status |", "|---|---|---|---|---|");
  for (const e of evs) {
    const name = NAME.test(e.bot.name) ? `[${e.bot.name}](#${e.bot.name})` : cell(e.bot.name);
    out.push(`| ${name} | ${cell(e.bot.operator ?? "")} | ${cell(e.bot.category ?? "")} | ${e.proofs[0] ?? "none"} | ${status(e)} |`);
  }
  out.push("", "## Bots");
  const cats = [...new Set(evs.map((e) => e.bot.category ?? "uncategorised"))];
  for (const cat of cats) {
    const c = CATEGORIES[cat];
    out.push("", `### ${text(cat)}`, "", c ? `${c.meaning}. Trigger \`${c.trigger}\`; AIPREF purpose ${c.purpose.map((p) => `\`${p}\``).join(", ") || "none"}.` : "No category.");
    for (const e of evs.filter((x) => (x.bot.category ?? "uncategorised") === cat)) {
      const b = e.bot, mine = findings.filter((f) => f.bot === b.name);
      const result = (check: string, url: string) => mine.find((f) => f.check === check && f.detail.startsWith(url))?.detail.slice(url.length + 2);
      out.push("", `#### ${text(b.name)}`, "");
      out.push(`- **Operator:** ${b.operator ? text(b.operator) : "not given"}`);
      out.push(`- **What its operator says:** ${b.description ? `"${text(b.description)}"` : "not recorded"}`);
      if (b.note) out.push(`- **Note:** ${text(b.note)}`);
      const own = asList(b.purpose);
      out.push(`- **Category:** ${text(cat)}${own.length ? ` (purpose as documented: ${own.map(text).join(", ")})` : ""}`);
      out.push(`- **Level:** ${e.proofs.join(", ") || "none"}; **status:** ${status(e)} (${day})`);
      out.push("- **Sources:**");
      const said = (check: string, u: string) => { const r = result(check, u); return r === undefined ? "not checked" : text(r); };
      for (const u of asList(b.docs)) out.push(`  - documentation ${link(u)}: ${said("docs", u)}`);
      for (const u of asList(b.ips)) out.push(`  - IP list ${link(u)}: ${said("ips", u)}`);
      if (b.wba) {
        const url = b.wba_type === "jwks_uri" ? b.wba : directoryIdentifier(b.wba) ?? b.wba;
        out.push(`  - signing keys ${link(url)}: ${said("wba", url)}`);
      }
      if (asList(b.rdns).length) out.push(`  - reverse DNS ${asList(b.rdns).map((r) => text(String(r))).join(", ")}: documented; checking needs a forward-confirmed DNS lookup, which this project does not do yet (planned: offline)`);
      const code = (t: string) => (/^[^`\x00-\x1f\x7f]+$/.test(t) ? `\`${t}\`` : text(t)); // eslint-disable-line no-control-regex -- strips control characters from a remote value before printing it
      if (asList(b.user_agent).length) out.push(`  - User-Agent ${asList(b.user_agent).map((t) => code(String(t))).join(", ")}: a claim on its own`);
      for (const n of e.notes.filter((x) => !/^(docs|ips|wba):/.test(x))) out.push(`  - note: ${text(n)}`);
    }
  }
  return out.join("\n") + "\n";
}

async function main(argv: string[]) {
  const file = argv.find((a, i) => !a.startsWith("--") && !["--log", "--out"].includes(argv[i - 1] ?? ""));
  if (!file) { console.error("usage: bun wba-keysync/report.ts bots.yaml [--log waf.log ...] [--catalogue] [--out report.md]"); process.exit(2); }
  const yaml = (globalThis as { Bun?: { YAML: { parse(s: string): unknown } } }).Bun?.YAML;
  if (!yaml) { console.error("report.ts reads YAML with Bun: run it with bun"); process.exit(2); }
  const bots = ((yaml.parse(readFileSync(file, "utf8")) as { bots?: Bot[] })?.bots ?? []);
  const findings = checkEntries(bots);
  const broken = new Set(findings.filter((x) => x.level === "fail").map((x) => x.bot));
  for (const b of bots) if (!broken.has(b.name)) findings.push(...await checkSources(b));
  const logs = argv.flatMap((a, i) => (argv[i - 1] === "--log" ? [a] : []));
  const t = logs.length ? traffic(logs.map((f) => readFileSync(f, "utf8")).join("\n")) : undefined;
  const evs = bots.map((b) => evidence(b, findings));
  const md = argv.includes("--catalogue") ? catalogue(evs, findings) : render(evs, t);
  const out = argv[argv.indexOf("--out") + 1];
  if (argv.includes("--out") && out) { await Bun.write(out, md); console.log(`report written to ${out}`); }
  else console.log(md);
}

if (import.meta.main) await main(process.argv.slice(2));
