/**
 * validate.ts: check a bot registry file (bots.yaml) against each bot's own
 * first-party sources. Run it before seeding or trusting a list: on the
 * project's seed list, on an operator's own registry, or on a registry an
 * operator is about to subscribe to.
 *
 *   bun wba-keysync/validate.ts bots.yaml [--only name,name] [--json] [--strict]
 *
 * For each bot it checks:
 *   - the entry itself: a name, a known category (CATEGORIES) and AIPREF
 *     purpose labels, https URLs only, well-formed reverse-DNS suffixes,
 *     User-Agent tokens that the given example contains;
 *   - `docs`: the operator's own documentation pages still answer 200;
 *   - `ips`: each URL answers 200 without a redirect and holds IP ranges
 *     (the operator's own published list: JSON, plain text one per line, or
 *     the standard JSON document inside an HTML page);
 *   - `cidrs`, a hand-kept copy of the ranges, against the live list: exact
 *     matches, stale (only in the copy), missing (only live), and how much of
 *     the live IPv4 space the copy covers. Hand-kept copies drift; this
 *     measures by how much;
 *   - `wba`: the key directory (or JWK Set) as key sync fetches it: 200, no
 *     redirect, the right media type, usable keys, and its Appendix B proof.
 * Every fetch is refused first if its host is or resolves to a private,
 * loopback or link-local address (draft 6.7, as key sync does), since a
 * bots.yaml may come from a third-party registry; redirects are never
 * followed, and bodies are capped. Text from the network is printed with its
 * control characters removed.
 * Exit 0: no failures (warnings allowed unless --strict). Exit 1: a failure.
 * Exit 2: usage. Only the URLs in the file are fetched.
 */
import { DEFAULT_LIMITS, getDirectory, guardAddress, HttpError, keysFromDirectory, printable, readCapped, resolveHost, type FetchLike, type Resolver } from "./keysync.ts";
import { directoryProofs } from "./proof.ts";
import { directoryIdentifier, WELL_KNOWN } from "./identifier.ts";

export interface Bot {
  name: string; operator?: string; category?: string;
  docs?: string | string[]; description?: string; note?: string; purpose?: string[];
  wba?: string; wba_type?: "directory" | "jwks_uri";
  ips?: string | string[]; cidrs?: string[];
  rdns?: string[]; user_agent?: string | string[]; user_agent_example?: string;
  policy?: "allow" | "deny" | "log"; claim_only?: boolean; robots?: string | string[];
}

/**
 * The categories a bot may be filed under. Each is defined on the two axes a
 * Signature Agent Card uses (draft-meunier-webbotauth-registry-03 3.2.4 and
 * 3.2.5): trigger, "fetcher" (a user started the request) or "crawler"
 * (autonomous); and purpose, labels from the IETF AIPREF vocabulary
 * (draft-ietf-aipref-vocab-08 6.1), which registry-03 says purposes SHOULD be
 * drawn from. AIPREF names AI and search uses only, so the other categories
 * carry no label. An entry's own `purpose` overrides its category's when its
 * operator documents a different use.
 * Two readings are open in AIPREF itself: whether a page fetched because a
 * user named its URL counts as "directly provided by the user" (vocab-08 4.2;
 * issue 249), which decides `ai-use` for user-fetch, agent and local-agent;
 * and whether an AI search index is `search` (4.3 excludes generated
 * summaries). The labels here are the likelier reading, not a settled one.
 */
const AIPREF_LABELS = ["train-ai", "ai-use", "search"] as const;
export const CATEGORIES: Record<string, { trigger: "crawler" | "fetcher"; purpose: string[]; meaning: string }> = {
  search: { trigger: "crawler", purpose: ["search"], meaning: "Crawls to build a search index that sends users to the pages it lists" },
  training: { trigger: "crawler", purpose: ["train-ai"], meaning: "Crawls to collect content for training AI models" },
  "ai-search": { trigger: "crawler", purpose: ["ai-use", "search"], meaning: "Crawls to build an index that an AI assistant answers from" },
  "user-fetch": { trigger: "fetcher", purpose: ["ai-use"], meaning: "Fetches a page because a user asked an AI assistant to" },
  agent: { trigger: "fetcher", purpose: ["ai-use"], meaning: "A hosted browser or agent acting for a user, from its operator's servers" },
  "local-agent": { trigger: "fetcher", purpose: ["ai-use"], meaning: "An AI tool on the user's own machine, sending from the user's own address" },
  research: { trigger: "crawler", purpose: [], meaning: "Crawls for research, internet measurement or development, not to serve a product" },
  archive: { trigger: "crawler", purpose: [], meaning: "Preserves pages in a public archive" },
  "security-scanner": { trigger: "crawler", purpose: [], meaning: "Scans the internet for exposed services or vulnerabilities" },
  seo: { trigger: "crawler", purpose: [], meaning: "Crawls for search-engine optimisation, links or marketing analysis" },
  "social-preview": { trigger: "fetcher", purpose: [], meaning: "Fetches a page to show a preview when a user shares its link" },
  monitoring: { trigger: "crawler", purpose: [], meaning: "Checks a site's availability, performance or compliance, usually for its owner" },
  dataset: { trigger: "crawler", purpose: [], meaning: "Crawls to build a dataset it sells or publishes; how buyers use it is theirs to decide" },
  "site-service": { trigger: "crawler", purpose: [], meaning: "Fetches for a product the site's owner uses, such as feeds, previews or verification" },
  advertising: { trigger: "crawler", purpose: [], meaning: "Crawls for an advertising product: ad quality, brand safety or ad targeting" },
};
/**
 * What an operator wants done with a bot (lists.ts writes the rules): allow
 * it and refuse whoever claims its User-Agent from outside its list; deny it;
 * or only log it.
 */
const POLICIES = ["allow", "deny", "log"] as const;
type Level = "ok" | "warn" | "fail";
export interface Finding { bot: string; check: string; level: Level; detail: string }

// --- IP ranges ---------------------------------------------------------------

export interface Cidr { v: 4 | 6; net: bigint; bits: number }
const WIDTH = { 4: 32, 6: 128 } as const;

function parseV4(s: string): bigint | null {
  const p = s.split(".");
  if (p.length !== 4) return null;
  let n = 0n;
  for (const o of p) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(o) || Number(o) > 255) return null;
    n = (n << 8n) | BigInt(o);
  }
  return n;
}

function parseV6(s: string): bigint | null {
  if (!/^[0-9a-fA-F:]+$/.test(s) || (s.match(/::/g) ?? []).length > 1) return null;
  const [head, tail] = s.includes("::") ? s.split("::") : [s, undefined];
  const h = head ? head.split(":") : [], t = tail ? tail.split(":") : [];
  if (tail === undefined ? h.length !== 8 : h.length + t.length > 7) return null;
  const groups = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

/** "a.b.c.d/n" or an IPv6 prefix, masked to its network; a bare address is /32 or /128. */
export function parseCidr(s: string): Cidr | null {
  const [addr, len, extra] = s.trim().split("/");
  if (extra !== undefined || addr === undefined) return null;
  const v: 4 | 6 = addr.includes(":") ? 6 : 4;
  const n = v === 4 ? parseV4(addr) : parseV6(addr);
  if (n === null) return null;
  const width = WIDTH[v];
  const bits = len === undefined ? width : /^(0|[1-9][0-9]{0,2})$/.test(len) ? Number(len) : NaN;
  if (!(bits >= 0 && bits <= width)) return null;
  const host = (1n << BigInt(width - bits)) - 1n;
  return { v, net: n & ~host & ((1n << BigInt(width)) - 1n), bits };
}

/** Canonical text: IPv4 dotted, IPv6 per RFC 5952 (lower case, longest zero run compressed). */
export function formatCidr(c: Cidr): string {
  if (c.v === 4) return `${[24n, 16n, 8n, 0n].map((s) => (c.net >> s) & 255n).join(".")}/${c.bits}`;
  const g = Array.from({ length: 8 }, (_, i) => Number((c.net >> BigInt(112 - 16 * i)) & 0xffffn));
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  const text = best < 0 ? hex.join(":")
    : `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
  return `${text}/${c.bits}`;
}

/** Every IP range in a JSON document, whatever its shape (Google-style `prefixes`, plain arrays, ...). */
export function extractCidrs(doc: unknown): Cidr[] {
  const seen = new Map<string, Cidr>();
  const walk = (x: unknown) => {
    if (typeof x === "string") {
      const c = x.includes("/") || x.includes(".") || x.includes(":") ? parseCidr(x) : null;
      if (c) seen.set(formatCidr(c), c);
    } else if (Array.isArray(x)) x.forEach(walk);
    else if (x && typeof x === "object") Object.values(x).forEach(walk);
  };
  walk(doc);
  return [...seen.values()];
}

/** Sorted, merged [start, end] address intervals of IPv4 ranges. */
function intervals(cs: Cidr[]): [bigint, bigint][] {
  const r = cs.filter((c) => c.v === 4).map((c) => [c.net, c.net + (1n << BigInt(32 - c.bits)) - 1n] as [bigint, bigint])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const out: [bigint, bigint][] = [];
  for (const [s, e] of r) {
    const last = out[out.length - 1];
    if (last && s <= last[1] + 1n) { if (e > last[1]) last[1] = e; } else out.push([s, e]);
  }
  return out;
}

export interface Drift { exact: number; stale: string[]; missing: string[]; v4Coverage: number | null }

/** A hand-kept copy against the live list: what matches, what is stale, what is missing, IPv4 coverage. */
export function drift(copy: Cidr[], live: Cidr[]): Drift {
  const c = new Set(copy.map(formatCidr)), l = new Set(live.map(formatCidr));
  const stale = [...c].filter((x) => !l.has(x)).sort(), missing = [...l].filter((x) => !c.has(x)).sort();
  const liveIv = intervals(live), copyIv = intervals(copy);
  let total = 0n, covered = 0n;
  for (const [s, e] of liveIv) {
    total += e - s + 1n;
    for (const [cs, ce] of copyIv) {
      const lo = cs > s ? cs : s, hi = ce < e ? ce : e;
      if (lo <= hi) covered += hi - lo + 1n;
    }
  }
  return { exact: c.size - stale.length, stale, missing, v4Coverage: total === 0n ? null : Number((covered * 10000n) / total) / 100 };
}

// --- The entry ----------------------------------------------------------------

const DNS_SUFFIX = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const asList = <T>(x: T | T[] | undefined): T[] => (x === undefined ? [] : Array.isArray(x) ? x : [x]);

/**
 * A value from a bots file, shown in a message: a string JSON-quoted and cut
 * at 200 characters; anything else by its kind, never serialised (YAML
 * aliases nest, so serialising one can take memory exponential in its depth).
 */
export function show(v: unknown): string {
  if (typeof v === "string") { const s = JSON.stringify(v); return s.length > 200 ? `${s.slice(0, 200)}..."` : s; }
  if (typeof v === "number" || typeof v === "boolean" || v === null) return String(v);
  return Array.isArray(v) ? "a list" : typeof v === "object" ? "a mapping" : typeof v;
}

/**
 * Why a bot name is unusable, or null. A name becomes a rule value, a file
 * name (lists.ts) and a comment line (agents.ts, robots.ts), so it is a
 * string of lower-case letters, digits and hyphens: never a number or a
 * boolean (YAML reads `name: 360` as a number), never a space, a newline or
 * a control character.
 */
export function nameProblem(name: unknown): string | null {
  if (typeof name !== "string") return name === undefined ? "no name" : `name ${show(name)} is not a string: quote it`;
  return /^[a-z0-9][a-z0-9-]{0,62}$/.test(name) ? null : `name ${show(name)}: lower-case letters, digits and hyphens`;
}

/**
 * Names a bot cannot take: lists.ts writes each bot's IP list to
 * <name>.data and every User-Agent token to tokens.data, in one directory.
 */
const RESERVED_NAMES = new Set(["tokens"]);

/** Checks that need no network: names, URLs, suffixes, User-Agent tokens, hand-kept ranges. */
export function checkEntries(bots: Bot[]): Finding[] {
  const out: Finding[] = [];
  const names = new Set<string>();
  for (const [i, b] of bots.entries()) {
    const bot = typeof b?.name === "string" && b.name ? b.name : `#${i + 1}`;
    const f = (check: string, level: Level, detail: string) => out.push({ bot, check, level, detail });
    if (!b || typeof b !== "object") { f("entry", "fail", "not a mapping"); continue; }
    const why = nameProblem(b.name);
    if (why !== null) f("name", "fail", why);
    else if (RESERVED_NAMES.has(b.name)) f("name", "fail", `name "${b.name}" is reserved: lists.ts writes its own ${b.name}.data beside each bot's <name>.data`);
    else if (names.has(b.name)) f("name", "fail", "duplicate name");
    names.add(b.name);
    if (!b.wba && asList(b.ips).length === 0 && asList(b.user_agent).length === 0) f("entry", "fail", "needs at least one of wba, ips, user_agent");
    if (b.category === undefined) f("category", "warn", "no category");
    else if (typeof b.category !== "string" || !Object.hasOwn(CATEGORIES, b.category)) f("category", "fail", `${show(b.category)}: not one of ${Object.keys(CATEGORIES).join(", ")}`);
    for (const p of asList(b.purpose)) {
      if (!(AIPREF_LABELS as readonly unknown[]).includes(p)) f("purpose", "fail", `${show(p)}: not an AIPREF label (${AIPREF_LABELS.join(", ")})`);
    }
    if (asList(b.docs).length === 0) f("docs", "warn", "no operator documentation: the category and tokens cannot be traced to a source");
    for (const u of [b.wba, ...asList(b.ips), ...asList(b.docs)].filter((x) => x !== undefined)) {
      let ok = false;
      try { ok = typeof u === "string" && new URL(u).protocol === "https:"; } catch { /* not a URL */ }
      if (!ok) f("url", "fail", `${show(u)}: not an https URL`);
    }
    // One URL: agents.txt's parser splits a line at whitespace, so "URL type=cimd" would change the agent's type.
    if (typeof b.wba === "string" && /\s/.test(b.wba)) f("wba", "fail", `wba ${show(b.wba)}: one URL, no spaces (wba_type says the type)`);
    if (b.wba_type !== undefined && b.wba_type !== "directory" && b.wba_type !== "jwks_uri") f("wba", "fail", "wba_type: directory or jwks_uri");
    for (const s of asList(b.rdns)) if (typeof s !== "string" || !DNS_SUFFIX.test(s)) f("rdns", "fail", `${show(s)}: not a DNS name suffix`);
    const tokens = asList(b.user_agent);
    for (const t of tokens) if (typeof t !== "string" || !/^[\x21-\x7e][\x20-\x7e]*$/.test(t)) f("user_agent", "fail", `${show(t)}: not a printable token`);
    if (b.user_agent_example !== undefined && !tokens.some((t) => b.user_agent_example!.includes(t))) {
      f("user_agent", "fail", "user_agent_example contains none of the user_agent tokens");
    }
    if (tokens.length > 0 && asList(b.ips).length === 0 && !b.wba && asList(b.rdns).length === 0) {
      f("user_agent", "warn", "User-Agent only: anyone can send it, so it can only ever be a claim");
    }
    if (b.cidrs !== undefined) {
      const bad = asList(b.cidrs).filter((c) => typeof c !== "string" || !parseCidr(c));
      if (bad.length) f("cidrs", "fail", `not IP ranges: ${bad.slice(0, 3).map(show).join(", ")}`);
    }
    if (b.policy !== undefined && !(POLICIES as readonly unknown[]).includes(b.policy)) f("policy", "fail", `${show(b.policy)}: one of ${POLICIES.join(", ")}`);
    if (b.claim_only !== undefined && typeof b.claim_only !== "boolean") f("claim_only", "fail", "claim_only: true or false");
    if (b.claim_only && tokens.length === 0) f("claim_only", "warn", "claim_only without user_agent tokens does nothing");
    for (const t of asList(b.robots)) if (typeof t !== "string" || !/^[A-Za-z0-9._-]+$/.test(t)) f("robots", "fail", `${show(t)}: a robots.txt product token (letters, digits, ".", "_", "-")`);
  }
  // One User-Agent naming two bots would be ambiguous: the claim names
  // whichever token the engine reports first. Compared without case, as the
  // WAF compares them.
  const owner: [string, string][] = bots.flatMap((b) => (b && typeof b === "object" ? asList(b.user_agent) : [])
    .filter((t): t is string => typeof t === "string").map((t) => [b.name, t.toLowerCase()] as [string, string]));
  for (const [a, ta] of owner) {
    const other = owner.find(([b, tb]) => b !== a && tb.includes(ta));
    if (other) out.push({ bot: a, check: "user_agent", level: "fail", detail: `token ${show(ta)} is also inside ${other[0]}'s ${show(other[1])}: a User-Agent with that token would claim both bots` });
  }
  return out;
}

// --- The sources --------------------------------------------------------------

const LIST_MAX_BYTES = 4 * 1024 * 1024;

export async function fetchList(url: string, fetchImpl: FetchLike): Promise<{ doc: unknown; headers: Headers }> {
  const res = await fetchImpl(url, {
    redirect: "manual", signal: AbortSignal.timeout(DEFAULT_LIMITS.timeoutMs),
    headers: { accept: "application/json", "accept-encoding": "identity" },
  });
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`HTTP ${res.status} to ${res.headers.get("location") ?? "?"}: not followed; list the final https URL`);
  }
  if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
  const buf = await readCapped(res, LIST_MAX_BYTES).catch((e: Error) => { // a timeout or a reset keeps its own message
    throw /exceeds maxBytes/.test(e.message) ? new Error("larger than 4 MiB") : e;
  });
  const text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
  const type = (res.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  const doc = type === "text/html" ? embeddedList(text) : type === "text/plain" ? textList(text) : JSON.parse(text);
  return { doc, headers: res.headers };
}

/**
 * A plain-text list (UptimeRobot, Pingdom, Better Stack): one address or range
 * per line; blank lines and "#" comments allowed. Any other line refuses the
 * whole list, so a text page that merely mentions an address is never a list.
 */
export function textList(text: string): string[] {
  const out: string[] = [];
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (!parseCidr(line)) throw new Error(`line ${i + 1} is not an IP address or range: ${JSON.stringify(line.slice(0, 40))}`);
    out.push(line);
  }
  return out;
}

/**
 * Some operators (Amazon's bot pages) publish the standard IP document inside
 * an HTML page. Only that document is taken: the JSON object holding a
 * "prefixes" array; an HTML page without one is refused, so a page that merely
 * mentions an address never counts as a list.
 */
export function embeddedList(html: string): unknown {
  const at = html.indexOf('"prefixes"');
  if (at < 0) throw new Error("an HTML page with no embedded IP list (no \"prefixes\" object)");
  // Try at most 16 enclosing braces, nearest first; lastIndexOf with a
  // negative start would return 0 again, so the loop stops at the start.
  for (let start = html.lastIndexOf("{", at), tries = 0; start >= 0 && tries < 16; start = start > 0 ? html.lastIndexOf("{", start - 1) : -1, tries++) {
    let depth = 0, inString = false;
    for (let i = start; i < html.length; i++) {
      const ch = html[i];
      if (inString) { if (ch === "\\") i++; else if (ch === '"') inString = false; continue; }
      if (ch === '"') inString = true;
      else if (ch === "{") depth++;
      else if (ch === "}" && --depth === 0) {
        try {
          const doc = JSON.parse(html.slice(start, i + 1));
          if (Array.isArray((doc as { prefixes?: unknown }).prefixes)) return doc;
        } catch { /* not this brace; try an enclosing one */ }
        break;
      }
    }
  }
  throw new Error("an HTML page whose \"prefixes\" is not in a JSON object");
}

/** The widest range a bot's IP list may hold: an IPv4 /8, an IPv6 /16. */
export const MIN_V4_BITS = 8, MIN_V6_BITS = 16;

/** Network checks for one bot: its IP lists (and any hand-kept copy) and its key directory. */
export async function checkSources(
  b: Bot, fetchImpl: FetchLike = fetch, now?: number, resolve: Resolver = resolveHost,
): Promise<Finding[]> {
  const out: Finding[] = [];
  // Details carry text from the network (headers, parse errors): no control characters.
  const f = (check: string, level: Level, detail: string) => out.push({ bot: b.name, check, level, detail: printable(detail) });

  // The operator's documentation is where the category and tokens come from:
  // it should still be there. Only a warning when it is not, since many
  // documentation sites refuse scripted fetches.
  for (const url of asList(b.docs)) {
    try {
      await guardAddress(url, resolve);
      // sec-fetch-mode: some documentation sites (Meta's) answer 400 to a fetch without it.
      const res = await fetchImpl(url, { redirect: "manual", signal: AbortSignal.timeout(DEFAULT_LIMITS.timeoutMs),
        headers: { accept: "text/html", "sec-fetch-mode": "navigate" } });
      await res.body?.cancel();
      if (res.status === 200) f("docs", "ok", `${url}: 200`);
      else if (res.status >= 300 && res.status < 400) f("docs", "warn", `${url}: HTTP ${res.status} to ${res.headers.get("location") ?? "?"}; list the final URL`);
      else f("docs", "warn", `${url}: HTTP ${res.status}${res.status === 403 ? " (refuses scripted fetches: check it by hand)" : ""}`);
    } catch (e) {
      f("docs", "warn", `${url}: ${(e as Error).message}`);
    }
  }

  const live: ReturnType<typeof extractCidrs> = [];
  for (const url of asList(b.ips)) {
    try {
      await guardAddress(url, resolve);
      const { doc, headers } = await fetchList(url, fetchImpl);
      const cs = extractCidrs(doc);
      const v4 = cs.filter((c) => c.v === 4).length;
      const when = String((doc as { creationTime?: string })?.creationTime ?? headers.get("last-modified") ?? "no date").slice(0, 40);
      // No bot's list legitimately holds a range wider than an IPv4 /8 or an IPv6 /16.
      const broad = cs.filter((c) => c.bits < (c.v === 4 ? MIN_V4_BITS : MIN_V6_BITS));
      if (cs.length === 0) f("ips", "fail", `${url}: no IP ranges in it`);
      else if (broad.length) f("ips", "fail", `${url}: ${broad.length} range(s) wider than /${MIN_V4_BITS} (IPv4) or /${MIN_V6_BITS} (IPv6), such as ${formatCidr(broad[0])}: refused`);
      else { f("ips", "ok", `${url}: ${cs.length} ranges (${v4} IPv4, ${cs.length - v4} IPv6), ${when}`); live.push(...cs); }
    } catch (e) {
      f("ips", "fail", `${url}: ${(e as Error).message}`);
    }
  }
  if (b.cidrs !== undefined && live.length > 0) {
    const copy = asList(b.cidrs).map((c) => parseCidr(String(c))).filter((c): c is Cidr => c !== null);
    const d = drift(copy, live);
    const cov = d.v4Coverage === null ? "" : `, covers ${d.v4Coverage}% of the live IPv4 addresses`;
    const level: Level = d.stale.length || d.missing.length ? "warn" : "ok";
    f("cidrs", level, `hand-kept ${copy.length} vs live ${live.length}: ${d.exact} exact, ${d.stale.length} stale, ${d.missing.length} missing${cov}`
      + (d.stale.length ? `; stale: ${d.stale.slice(0, 5).join(" ")}${d.stale.length > 5 ? " ..." : ""}` : ""));
  }

  if (b.wba) {
    const url = b.wba_type === "jwks_uri" ? b.wba : directoryIdentifier(b.wba);
    if (!url) f("wba", "fail", `${b.wba}: not an https origin`);
    else {
      try {
        await guardAddress(url, resolve);
        const res = await getDirectory(url, DEFAULT_LIMITS, fetchImpl);
        // Judged at the time this response arrived (B.1), not when the checks began:
        // the fetches before it can take seconds.
        const at = now ?? Math.floor(Date.now() / 1000);
        const notes: string[] = [];
        const atWellKnown = new URL(url).pathname === WELL_KNOWN;
        const keys = await keysFromDirectory(res.doc, DEFAULT_LIMITS, at, (m) => notes.push(m), atWellKnown);
        let proof = "n/a (not a key directory)", proofInvalid = false;
        if (atWellKnown && res.body) {
          const p = await directoryProofs({ authority: new URL(url).host, headers: res.headers, body: res.body, keys, now: at });
          proof = p.summary + (p.notes.length ? ` (${p.notes.join("; ")})` : "");
          proofInvalid = p.summary === "invalid";
        }
        // The proof is RECOMMENDED (B.1): an invalid one is worth a look, not a failure.
        const level: Level = keys.length === 0 ? "fail" : notes.length || proofInvalid ? "warn" : "ok";
        f("wba", level, `${url}: ${keys.length} usable key(s); proof ${proof}${notes.length ? `; ${notes.join("; ")}` : ""}`);
      } catch (e) {
        const msg = e instanceof HttpError && e.status >= 300 && e.status < 400
          ? `${e.message}, to ${e.headers.get("location") ?? "?"}` : (e as Error).message;
        f("wba", "fail", `${url}: ${msg}`);
      }
    }
  }
  return out;
}

// --- Command line ---------------------------------------------------------------

async function main(argv: string[]) {
  const file = argv.find((a) => !a.startsWith("--"));
  if (!file) { console.error("usage: bun wba-keysync/validate.ts bots.yaml [--only a,b] [--json] [--strict]"); process.exit(2); }
  const only = argv.find((a) => a.startsWith("--only="))?.slice(7).split(",") ?? (argv.includes("--only") ? argv[argv.indexOf("--only") + 1]?.split(",") : undefined);
  const yaml = (globalThis as { Bun?: { YAML: { parse(s: string): unknown } } }).Bun?.YAML;
  if (!yaml) { console.error("validate.ts reads YAML with Bun: run it with bun"); process.exit(2); }
  const parsed = yaml.parse(await (await import("node:fs/promises")).readFile(file, "utf8")) as { bots?: Bot[] };
  const bots = (parsed?.bots ?? []).filter((b) => !only || only.includes(b?.name));
  if (bots.length === 0) { console.error(`${file}: no bots${only ? " matching --only" : ""}`); process.exit(2); }

  const findings = checkEntries(bots);
  const broken = new Set(findings.filter((x) => x.level === "fail").map((x) => x.bot));
  for (const b of bots) if (!broken.has(b.name)) findings.push(...await checkSources(b));

  if (argv.includes("--json")) console.log(JSON.stringify(findings, null, 1));
  else for (const x of findings) console.log(`${x.level.toUpperCase().padEnd(4)}  ${printable(x.bot)}  ${x.check}: ${x.detail}`); // a name is printed before it is checked
  const fails = findings.filter((x) => x.level === "fail").length, warns = findings.filter((x) => x.level === "warn").length;
  if (!argv.includes("--json")) console.log(`== ${bots.length} bots: ${fails} failure(s), ${warns} warning(s)`);
  process.exit(fails || (argv.includes("--strict") && warns) ? 1 : 0);
}

if (import.meta.main) await main(process.argv.slice(2));
