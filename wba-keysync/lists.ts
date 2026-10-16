// wba-lists: turns a bots file (bots.yaml) into ModSecurity rules that say,
// for each request, which bot its User-Agent claims to be and whether that is
// true: its address is on the bot's own published IP list, or it carries the
// bot's verified Web Bot Auth signature. Optional per-bot policies (allow,
// deny, log) act on that. Run it from cron; the WAF reads the result when it
// starts or reloads, so no request ever waits on a fetch.
//
//   bun wba-keysync/lists.ts bots.yaml --out DIR [--allow-private-url URL]...
//                            [--check 'nginx -t' [--reload 'nginx -s reload']]
//
// DIR receives:
//   web-bot-auth-bots-before.conf the rules; load it as a CRS plugin file
//   web-bot-auth-bots/            tokens.data (every User-Agent token, lower
//                                 case) and <bot>.data (each bot's ranges);
//                                 the rules name them relative to the .conf
//   versions.json                 each list's version: the operator's
//                                 creationTime and a sha-256 of the ranges,
//                                 when it was fetched and when it last changed
//   status.json                   what this run did for each bot
//   ids.json                      the rule ids each bot holds, kept between
//                                 runs so a bot's ids never change
//
// Why a "before" file: CRS loads plugin files of one kind in name order, so
// web-bot-auth-bots-before.conf loads just after the verifier's
// web-bot-auth-before.conf (whose results, phase 2 included, are final by
// then) and ahead of every *-after.conf. An operator's own rules in, say,
// site-wba-rules-after.conf therefore see tx.bot_* already set. As an after
// file it sorted after that one ("s" before "w"), so a bot verified by its
// signature still read "claimed" there. The rules read only the User-Agent,
// the client address, the verifier's tx.wba_status and tx.wba_agent and
// their own tx.bot_*; they read and set nothing of CRS's (no anomaly score),
// so running ahead of CRS's own rules changes nothing CRS decides. A
// web-bot-auth-bots-after.conf an older lists.ts wrote in DIR (its first line
// says so) is removed in the same run, and put back with the rest if the
// check or reload fails: loaded together, the two would repeat every rule id.
//
// Each list is fetched as validate.ts fetches it (https, no redirects, 4 MiB,
// the private-address guard), normalised (canonical text, one range per line,
// a range inside another dropped) and refused whole if it is empty, holds a range wider than an IPv4 /8 or
// IPv6 /16, or touches private, loopback, link-local or multicast space. A
// list that fails keeps its previous version, and the run says so. A bot
// whose list has never been fetched gets no address check: its claims are
// "no-list", which no policy refuses as an impostor. Files are written under
// new names and renamed into place, data first and the rules last.
//
// --allow-private-url URL, repeatable: a list on a private, loopback or
// link-local address is refused, unless its exact URL is named here (your own
// list on your own network, or a test server); each such fetch is reported.
// It names one list, not a host, so a bots file from elsewhere cannot use it
// to reach any other path on that host.
//
// With --check the command is run after writing (through sh); if it fails,
// every file goes back to what it was. With --reload it is run after a check
// that passed; if the reload fails, the files go back too, so what is on disk
// matches what the WAF runs and the next run tries again. When the rules and
// data files come out the same as before, neither runs: an hourly cron
// reloads the WAF only when a list changed.
//
// Bun only: YAML is read with Bun.YAML (the functions run anywhere).
// Exit codes: 0 every list fetched; 2 rules written, but a list kept its
// previous version or has none; 1 nothing changed (bad file or usage, or the
// check or the reload failed and the files were put back).

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { basename, join } from "node:path";
import { guardAddress, parseAgent, printable, resolveHost, writeAtomic, type FetchLike, type Resolver } from "./keysync.ts";
import { checkEntries, extractCidrs, fetchList, formatCidr, MIN_V4_BITS, MIN_V6_BITS, parseCidr, type Bot, type Cidr } from "./validate.ts";

export const CONF = "web-bot-auth-bots-before.conf";
export const DATA = "web-bot-auth-bots";
/** The rules' name before it became a before file, and the first line lists.ts wrote into it. */
export const OLD_CONF = "web-bot-auth-bots-after.conf";
const OLD_HEADER = `# ${OLD_CONF}: written by wba-keysync/lists.ts`;
/** The plugin release every generated rule names (ver), as wba.conf's rules do: an audit log entry says which release wrote the rule. */
export const VER = "web-bot-auth-plugin/0.1.0";
/** The claim rule; each bot then holds four ids from RULE_BASE (slot k: RULE_BASE + 4k). */
export const CLAIM_RULE = 9534150, RULE_BASE = 9534200, MAX_SLOTS = 175;
const SLOT_SIZE = 4;
const MODES = ["log", "enforce"] as const;
export type Mode = (typeof MODES)[number];

const asList = <T>(x: T | T[] | undefined): T[] => (x === undefined ? [] : Array.isArray(x) ? x : [x]);
const WIDTH = { 4: 32n, 6: 128n } as const;

/**
 * Ranges a bot's list must never touch: they hold your own network or no
 * real client. The space key sync's forbiddenAddress refuses (private,
 * loopback, link-local, shared, multicast, reserved), and the IPv6 forms that
 * carry an IPv4 address (mapped, translated, NAT64, 6to4).
 */
export const LOCAL_RANGES: Cidr[] = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3",
  "::/96", "::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
].map((c) => parseCidr(c)!);

/** Two prefixes overlap only when the shorter one contains the other. */
export function overlaps(a: Cidr, b: Cidr): boolean {
  if (a.v !== b.v) return false;
  const shift = WIDTH[a.v] - BigInt(Math.min(a.bits, b.bits));
  return a.net >> shift === b.net >> shift;
}

/** One data-file line: canonical text; a single address is written bare (libmodsecurity refuses an explicit /128). */
export function dataLine(c: Cidr): string {
  const text = formatCidr(c);
  return BigInt(c.bits) === WIDTH[c.v] ? text.slice(0, text.lastIndexOf("/")) : text;
}

/**
 * The ranges of one list, checked and sorted (IPv4 first, then by address),
 * or why it is refused. A range inside another one (192.0.2.8/29 inside
 * 192.0.2.0/24, or the same range twice) is dropped: the outer one already
 * covers it, and libmodsecurity's address tree can lose a range nested in
 * another (ModSecurity issue #3588). Ranges side by side are kept as they are.
 */
export function normalise(cidrs: Cidr[]): string[] {
  if (cidrs.length === 0) throw new Error("no IP ranges in it");
  const broad = cidrs.find((c) => c.bits < (c.v === 4 ? MIN_V4_BITS : MIN_V6_BITS));
  if (broad) throw new Error(`${formatCidr(broad)} is wider than an IPv4 /${MIN_V4_BITS} or IPv6 /${MIN_V6_BITS}`);
  const local = cidrs.find((c) => LOCAL_RANGES.some((l) => overlaps(c, l)));
  if (local) throw new Error(`${formatCidr(local)} touches private, loopback, link-local or multicast space`);
  // Sorted by address, then wider first: a range inside an earlier one is
  // inside the last one kept (ranges are nested or apart, never half over).
  const sorted = [...cidrs].sort((x, y) => x.v - y.v || (x.net < y.net ? -1 : x.net > y.net ? 1 : x.bits - y.bits));
  const kept: Cidr[] = [];
  for (const c of sorted) if (!kept.length || !overlaps(kept[kept.length - 1], c)) kept.push(c);
  return kept.map(dataLine);
}

export interface ListVersion {
  version: string; creationTime: string | null; sha256: string;
  ranges: number; ipv4: number; ipv6: number; urls: string[]; fetched: string; changed: string;
}

/**
 * A list's version: the operator's creationTime (the latest, for a bot with
 * several lists) and the first 8 hex digits of the sha-256 of its data file.
 * The hash tells versions apart when an operator leaves creationTime alone.
 */
export function versionOf(lines: string[], creationTimes: (string | null)[], urls: string[], at: Date, previous?: ListVersion): ListVersion {
  const sha256 = createHash("sha256").update(lines.join("\n") + "\n").digest("hex");
  const clean = creationTimes.filter((t): t is string => typeof t === "string" && /^[0-9A-Za-z:.+_-]{1,40}$/.test(t)).sort();
  const creationTime = clean.length ? clean[clean.length - 1] : null;
  const ipv6 = lines.filter((l) => l.includes(":")).length;
  return {
    version: `${creationTime ?? "undated"}#${sha256.slice(0, 8)}`, creationTime, sha256,
    ranges: lines.length, ipv4: lines.length - ipv6, ipv6, urls, fetched: at.toISOString(),
    changed: previous?.sha256 === sha256 ? previous.changed : at.toISOString(),
  };
}

/**
 * The list URL named by --allow-private-url, normalised as the URL parser
 * writes it, or null unless it is an https URL with a path or query, no
 * userinfo and no fragment: one list, never a whole host.
 */
export function allowedUrl(value: string): string | null {
  let u: URL;
  try { u = new URL(value); } catch { return null; }
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.hash !== "" || /\s/.test(value)) return null;
  if (u.pathname === "/" && u.search === "") return null; // an origin: it would cover every list on the host
  return u.href;
}

/** Each bot's slot: kept from the last run; a new bot takes the lowest slot never used. A removed bot's slot is not reused. */
export function assignSlots(names: string[], previous: Record<string, number>): Record<string, number> {
  const slots = { ...previous };
  const used = new Set(Object.values(slots));
  let next = 0;
  for (const n of names) {
    if (Object.hasOwn(slots, n)) continue;
    while (used.has(next)) next++;
    if (next >= MAX_SLOTS) throw new Error(`more than ${MAX_SLOTS} bots have held rule ids (ids.json): remove old entries from it`);
    slots[n] = next; used.add(next);
  }
  return slots;
}

const TOKEN = /^[A-Za-z0-9][A-Za-z0-9 ._/:+-]*[A-Za-z0-9._/:+-]$|^[A-Za-z0-9]$/;
const escapeRx = (t: string) => t.replace(/[.+]/g, "\\$&");

/** Checks lists.ts adds to validate.ts's: the policy mode, and tokens that can go into a rule as written. */
export function checkRules(bots: Bot[], mode: unknown): string[] {
  const out: string[] = [];
  if (!(MODES as readonly unknown[]).includes(mode)) out.push(`policy_mode: ${JSON.stringify(mode)}: one of ${MODES.join(", ")}`);
  for (const b of bots) {
    for (const t of asList(b.user_agent)) if (!TOKEN.test(String(t))) out.push(`${b.name}: user_agent ${JSON.stringify(t)}: letters, digits, spaces and . _ / : + - only, no space at either end`);
    if (b.wba && signsAs(b) === null) out.push(`${b.name}: wba ${JSON.stringify(b.wba)}: not a key directory origin or JWK Set URL key sync accepts`);
  }
  return out;
}

/** The identifier a bot signs as (tx.wba_agent), as agents.ts and key sync compute it. */
function signsAs(b: Bot): string | null {
  if (!b.wba) return null;
  const a = parseAgent(b.wba_type === "jwks_uri" ? `${b.wba} type=jwks_uri` : b.wba);
  return typeof a === "string" ? null : a.id;
}

export interface Generated { conf: string; tokens: string }

/** The rules and the token file, for bots in bots.yaml order. lists maps a bot to the list its data file holds. */
export function generate(g: { bots: Bot[]; mode: Mode; slots: Record<string, number>; lists: Map<string, ListVersion>; source: string }): Generated {
  const tokens = [...new Set(g.bots.flatMap((b) => asList(b.user_agent).map((t) => String(t).toLowerCase())))].sort();
  const refuse = g.mode === "enforce" ? "deny,status:403,log" : "pass,log";
  const would = g.mode === "enforce" ? "" : "(log mode, would refuse) ";
  const out = [
    `# ${CONF}: written by wba-keysync/lists.ts from ${g.source} (versions.json says when).`,
    `# Do not edit it: the next run replaces it. Edit ${g.source} and run lists.ts again.`,
    "# Keep this name: CRS then runs it after the verifier's web-bot-auth-before.conf",
    "# and before every *-after.conf, so your own rules there see tx.bot_* set.",
    "#",
    "# For a request whose User-Agent names a bot, or that carries a bot's verified",
    "# Web Bot Auth signature, these rules set:",
    "#   tx.bot_name          the bot's name",
    "#   tx.bot_status        verified, or claimed (the User-Agent names it; nothing proves it)",
    "#   tx.bot_reason        ip-list (its address is on the bot's list) or signature, for",
    "#                        verified; not-in-list or no-list (no list for this bot), for claimed",
    "#   tx.bot_list_version  the version of the bot's list that was checked, or none",
    `# Policy mode: ${g.mode}. ${g.mode === "enforce" ? "Policies refuse with 403." : "Policies only log what they would refuse; policy_mode: enforce refuses."}`,
    `# Rule ids: ${CLAIM_RULE} (the claim), and ${SLOT_SIZE} per bot from ${RULE_BASE} (kept in ids.json).`,
    "",
  ];
  if (tokens.length) {
    out.push("# The claim: which token the User-Agent holds, in one pass over every bot's tokens.",
      `SecRule REQUEST_HEADERS:User-Agent "@pmFromFile ${DATA}/tokens.data" \\`,
      `    "id:${CLAIM_RULE},phase:1,pass,nolog,t:none,t:lowercase,capture,ver:'${VER}',setvar:'tx.bot_claimed=%{TX.0}'"`, "");
  }
  const signers = new Map<string, string>();
  for (const b of g.bots) {
    const own = asList(b.user_agent).map((t) => String(t).toLowerCase());
    const list = g.lists.get(b.name);
    const id = signsAs(b);
    if (!own.length && !list && !id) continue;
    const base = RULE_BASE + SLOT_SIZE * g.slots[b.name];
    const notes = [list ? `list ${list.version} (${list.ranges} ranges)` : asList(b.ips).length ? "list never fetched" : "no list"];
    if (id) notes.push(`signs as ${id}`);
    if (list && !own.length) notes.push("no user_agent tokens, so its list is never consulted");
    if (b.policy) notes.push(`policy ${b.policy}${b.claim_only ? ", claim only" : ""}`);
    out.push(`# ${b.name}: ${notes.join("; ")}`);
    if (own.length) {
      out.push(`SecRule TX:bot_claimed "@rx ^(?:${[...new Set(own)].map(escapeRx).join("|")})$" \\`,
        `    "id:${base},phase:1,pass,nolog,t:none,ver:'${VER}',setvar:tx.bot_name=${b.name},setvar:tx.bot_status=claimed,`
        + `setvar:tx.bot_reason=${list ? "not-in-list" : "no-list"},setvar:'tx.bot_list_version=${list ? list.version : "none"}'"`);
      if (list) {
        out.push(`SecRule TX:bot_name "@streq ${b.name}" "id:${base + 1},phase:1,pass,nolog,t:none,ver:'${VER}',chain"`,
          `    SecRule REMOTE_ADDR "@ipMatchFromFile ${DATA}/${b.name}.data" "t:none,setvar:tx.bot_status=verified,setvar:tx.bot_reason=ip-list"`);
      }
    }
    // A signature is checked in phase 2 (the plugin settles body-bound
    // signatures there). Bots sharing one key source: the first is named.
    if (id && signers.has(id)) out.push(`# ${b.name} signs with ${signers.get(id)}'s key source, so its signatures name ${signers.get(id)}`);
    else if (id) {
      signers.set(id, b.name);
      out.push(`SecRule TX:wba_status "@streq verified" "id:${base + 2},phase:2,pass,nolog,t:none,ver:'${VER}',chain"`,
        `    SecRule TX:wba_agent "@streq ${id}" "t:none,setvar:tx.bot_name=${b.name},setvar:tx.bot_status=verified,setvar:tx.bot_reason=signature,setvar:tx.bot_list_version=none"`);
    }
    const act = `id:${base + 3},phase:2,t:none,tag:'web-bot-auth-bots',ver:'${VER}',severity:'NOTICE',logdata:'%{tx.bot_status} by %{tx.bot_reason}, list %{tx.bot_list_version}'`;
    if (b.policy === "deny") {
      out.push(`SecRule TX:bot_name "@streq ${b.name}" "${act},${refuse},msg:'Bot policy: ${would}${b.name} is refused'${b.claim_only ? ",chain" : ""}"`);
      if (b.claim_only) out.push(`    SecRule TX:bot_status "@streq verified" "t:none"`);
    } else if (b.policy === "allow" && b.claim_only) {
      out.push(`# ${b.name}: claim only, so a claim from outside its list is not refused`);
    } else if (b.policy === "allow" && list) {
      out.push(`SecRule TX:bot_name "@streq ${b.name}" "${act},${refuse},msg:'Bot policy: ${would}claims to be ${b.name} from an address not on its list',chain"`,
        `    SecRule TX:bot_reason "@streq not-in-list" "t:none"`);
    } else if (b.policy === "allow") {
      out.push(`# ${b.name}: allow, but there is no list to check a claim against`);
    } else if (b.policy === "log") {
      out.push(`SecRule TX:bot_name "@streq ${b.name}" "${act},pass,log,msg:'Bot: ${b.name}'"`);
    }
    out.push("");
  }
  return { conf: out.join("\n"), tokens: tokens.length ? tokens.join("\n") + "\n" : "" };
}

interface BotResult { name: string; list: "fetched" | "kept" | "none"; version?: string; error?: string }
export interface RunOptions {
  bots: Bot[]; mode: unknown; source: string; out: string;
  fetchImpl?: FetchLike; resolve?: Resolver; allow?: ReadonlySet<string>; at?: Date;
  check?: string; reload?: string; log?: (line: string) => void;
}

const readJson = <T>(path: string, fallback: T): T => (existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) as T : fallback);

/** Shell command; its output is returned for the report. */
function sh(cmd: string): { ok: boolean; output: string } {
  const r = spawnSync("sh", ["-c", cmd], { encoding: "utf8" });
  return { ok: r.status === 0, output: `${r.stdout ?? ""}${r.stderr ?? ""}`.trim() };
}

/** One run: fetch, write, check, reload. Returns the exit code. */
export async function runLists(o: RunOptions): Promise<number> {
  const log = o.log ?? ((l: string) => console.log(l));
  const at = o.at ?? new Date();
  const problems = [
    ...checkEntries(o.bots).filter((f) => f.level === "fail").map((f) => printable(`${f.bot}: ${f.check}: ${f.detail}`)), // a bad name is printed as it is labelled
    ...checkRules(o.bots, o.mode),
  ];
  if (problems.length) { for (const p of problems) log(`FAIL  ${p}`); log(`== ${o.source}: nothing written`); return 1; }
  const mode = o.mode as Mode;

  const dataDir = join(o.out, DATA);
  mkdirSync(dataDir, { recursive: true });
  const previous = readJson<Record<string, ListVersion>>(join(o.out, "versions.json"), {});
  let slots: Record<string, number>;
  try { slots = assignSlots(o.bots.map((b) => b.name), readJson<Record<string, number>>(join(o.out, "ids.json"), {})); }
  catch (e) { log(`FAIL  ${(e as Error).message}`); return 1; }

  const fetchImpl = o.fetchImpl ?? fetch, resolve = o.resolve ?? resolveHost, allow = o.allow ?? new Set<string>();
  const versions: Record<string, ListVersion> = {}, lists = new Map<string, ListVersion>(), fresh = new Map<string, string[]>();
  const results: BotResult[] = [];
  for (const b of o.bots) {
    const urls = asList(b.ips);
    if (!urls.length) continue;
    try {
      const cidrs: Cidr[] = [], times: (string | null)[] = [];
      for (const url of urls) {
        if (allow.has(new URL(url).href)) log(`WARN  ${b.name}: ${new URL(url).href} fetched without the private-address check (--allow-private-url)`);
        else await guardAddress(url, resolve);
        const { doc } = await fetchList(url, fetchImpl);
        cidrs.push(...extractCidrs(doc));
        times.push((doc as { creationTime?: unknown })?.creationTime as string ?? null);
      }
      const lines = normalise(cidrs);
      const v = versionOf(lines, times, urls, at, previous[b.name]);
      versions[b.name] = v; lists.set(b.name, v); fresh.set(b.name, lines);
      results.push({ name: b.name, list: "fetched", version: v.version });
      log(`ok    ${b.name}: ${v.ranges} ranges (${v.ipv4} IPv4, ${v.ipv6} IPv6), version ${v.version}${previous[b.name] && previous[b.name].sha256 !== v.sha256 ? `, was ${previous[b.name].version}` : ""}`);
    } catch (e) {
      const error = printable((e as Error).message);
      const kept = previous[b.name];
      if (kept && existsSync(join(dataDir, `${b.name}.data`))) {
        versions[b.name] = kept; lists.set(b.name, kept);
        results.push({ name: b.name, list: "kept", version: kept.version, error });
        log(`kept  ${b.name}: ${error}; keeping version ${kept.version}`);
      } else {
        results.push({ name: b.name, list: "none", error });
        log(`none  ${b.name}: ${error}; no list yet, so its claims are not checked against addresses`);
      }
    }
  }

  // Remember every file as it was, so a failed check can put it back.
  const before = new Map<string, string | null>();
  const keep = (p: string) => { if (!before.has(p)) before.set(p, existsSync(p) ? readFileSync(p, "utf8") : null); };
  const write = (p: string, text: string) => { keep(p); writeAtomic(p, text); };
  const putBack = () => { for (const [p, text] of before) { if (text === null) rmSync(p, { force: true }); else writeAtomic(p, text); } };
  const { conf, tokens } = generate({ bots: o.bots, mode, slots, lists, source: o.source });
  for (const [name, lines] of fresh) write(join(dataDir, `${name}.data`), lines.join("\n") + "\n");
  const tokensPath = join(dataDir, "tokens.data");
  if (tokens) write(tokensPath, tokens);
  write(join(o.out, CONF), conf);
  const old = join(o.out, OLD_CONF);
  if (existsSync(old) && readFileSync(old, "utf8").startsWith(OLD_HEADER)) {
    keep(old); rmSync(old);
    log(`ok    removed ${OLD_CONF}, which an older lists.ts wrote: the rules are now ${CONF}, so an Include that names the old file must name the new one`);
  }
  if (!tokens && existsSync(tokensPath)) { keep(tokensPath); rmSync(tokensPath); }
  for (const f of readdirSync(dataDir).filter((x) => x.endsWith(".data"))) {
    const name = f.slice(0, -".data".length);
    if (f !== "tokens.data" && !lists.has(name)) { keep(join(dataDir, f)); rmSync(join(dataDir, f)); }
  }
  write(join(o.out, "versions.json"), JSON.stringify(versions, null, 1) + "\n");
  write(join(o.out, "ids.json"), JSON.stringify(slots, null, 1) + "\n");
  write(join(o.out, "status.json"), JSON.stringify({ generated: at.toISOString(), source: o.source, mode, bots: results }, null, 1) + "\n");

  const fetched = results.filter((r) => r.list === "fetched").length, kept = results.filter((r) => r.list === "kept").length;
  const none = results.length - fetched - kept;
  // Only the rules and data files reach the WAF (not the JSON files): when none changed, there is nothing to check or reload.
  const changed = [...before].some(([p, text]) => !/(versions|status|ids)\.json$/.test(p) && text !== (existsSync(p) ? readFileSync(p, "utf8") : null));
  if (o.check && !changed) log("ok    the rules and lists are unchanged: no check or reload needed");
  else if (o.check) {
    const c = sh(o.check);
    if (!c.ok) {
      putBack();
      log(`FAIL  check (${o.check}) failed, every file put back as it was:\n${c.output}`);
      return 1;
    }
    log(`ok    check: ${o.check}`);
    if (o.reload) {
      const r = sh(o.reload);
      if (!r.ok) { putBack(); log(`FAIL  reload (${o.reload}) failed, every file put back as it was, so the next run tries again:\n${r.output}`); return 1; }
      log(`ok    reload: ${o.reload}`);
    }
  }
  log(`== ${results.length} lists: ${fetched} fetched, ${kept} kept their previous version, ${none} without a list; rules in ${join(o.out, CONF)} (policy mode ${mode})`);
  return kept || none ? 2 : 0;
}

function usage(msg: string): never {
  console.error(`${msg}\nusage: bun wba-keysync/lists.ts bots.yaml --out DIR [--allow-private-url URL]... [--check CMD [--reload CMD]]`);
  process.exit(1);
}

async function main(argv: string[]): Promise<number> {
  let file: string | undefined, out: string | undefined, check: string | undefined, reload: string | undefined;
  const allow = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], value = () => argv[++i] ?? usage(`${a} needs a value`);
    if (a === "--out") out = value();
    else if (a === "--check") check = value();
    else if (a === "--reload") reload = value();
    else if (a === "--allow-private-url") {
      const url = allowedUrl(value());
      if (!url) usage(`--allow-private-url: ${JSON.stringify(argv[i])}: the exact https URL of one list (https://host[:port]/path), not an origin`);
      allow.add(url);
    } else if (a === "--allow-private-origin") {
      usage("--allow-private-origin is key sync's: lists.ts excepts one list at a time, --allow-private-url https://host[:port]/path/to/list");
    } else if (a.startsWith("--")) usage(`unknown option ${a}`);
    else if (file === undefined) file = a;
    else usage(`one bots file only (${file}, ${a})`);
  }
  if (!file || !out) usage("a bots file and --out are needed");
  if (reload && !check) usage("--reload needs --check, so a broken file is never loaded");
  const yaml = (globalThis as { Bun?: { YAML: { parse(s: string): unknown } } }).Bun?.YAML;
  if (!yaml) usage("lists.ts reads YAML with Bun: run it with bun");
  const parsed = yaml.parse(readFileSync(file, "utf8")) as { bots?: Bot[]; policy_mode?: unknown } | null;
  if (!parsed?.bots?.length) usage(`${file}: no bots`);
  return runLists({ bots: parsed.bots, mode: parsed.policy_mode ?? "log", source: basename(file), out, allow, check, reload });
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
