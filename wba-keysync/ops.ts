// ops.ts: doctor (read-only), unknown-agent suggestions, debug-sig explainers.
// Fail-closed: never mutates allowlists, never adds --allow-private-*, never fetches.
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { printable } from "./keysync.ts";

export interface DoctorResult { ok: boolean; mutated: false; lines: string[] }

export interface DoctorOptions {
  storePath?: string;
  botsPath?: string;
  agentsPath?: string;
  bunPath?: string;
  requireBun?: boolean;
  acceptSignaturePath?: string;
  now?: Date;
}

const EXIT_TABLE = [
  "Exit codes (do not conflate):",
  "  keysync (cli.ts): 0 all origins usable; 2 some failed (store still written); 1 usage/config (store untouched)",
  "  lists.ts:         0 every list fetched; 2 rules written but a list kept/none; 1 nothing changed / check-reload failed",
  "Private exceptions stay CLI and exact: keysync --allow-private-origin; lists --allow-private-url. Never from bots.yaml.",
];

function bunOk(path?: string): boolean {
  if (path) {
    const r = spawnSync(path, ["--version"], { encoding: "utf8" });
    return r.status === 0;
  }
  const r = spawnSync("bun", ["--version"], { encoding: "utf8" });
  return r.status === 0;
}

/** Read-only health report. Never chmods, never rewrites files, never suggests auto private-allow. */
export function doctor(o: DoctorOptions = {}): DoctorResult {
  const lines: string[] = [];
  let ok = true;
  const needBun = o.requireBun !== false;
  if (needBun && !bunOk(o.bunPath)) {
    ok = false;
    lines.push(`FAIL  bun not found${o.bunPath ? ` at ${o.bunPath}` : " on PATH"}: install Bun and use its absolute path in cron/systemd`);
  } else {
    lines.push("ok    bun available for validate/agents/lists/report");
  }

  if (o.storePath) {
    if (!existsSync(o.storePath)) {
      ok = false;
      lines.push(`FAIL  key store missing: ${o.storePath} (mount the keys *directory* at /etc/modsecurity.d/wba/keys)`);
    } else {
      const head = readFileSync(o.storePath, "utf8").split("\n", 2)[0] ?? "";
      if (!head.startsWith("# wba-keys v2")) {
        ok = false;
        lines.push(`FAIL  store header is not "# wba-keys v2": ${JSON.stringify(head.slice(0, 80))}`);
      } else {
        lines.push("ok    store header # wba-keys v2");
      }
      try {
        const st = statSync(o.storePath);
        const mode = st.mode & 0o777;
        if (mode & 0o002) {
          ok = false;
          lines.push(`FAIL  store is world-writable (mode ${mode.toString(8)}); prefer 640, directory 750, owner wba, group readable by nginx`);
        } else {
          lines.push(`ok    store mode ${mode.toString(8)} (hint: 640 file / 750 dir; nginx workers need read)`);
        }
        const dirMode = statSync(dirname(o.storePath)).mode & 0o777;
        if (dirMode & 0o002) {
          ok = false;
          lines.push(`FAIL  store directory is world-writable (mode ${dirMode.toString(8)})`);
        }
      } catch (e) {
        lines.push(`WARN  could not stat store: ${(e as Error).message}`);
      }
      const hist = `${o.storePath}.history`;
      if (existsSync(hist)) {
        const ageSec = ((o.now ?? new Date()).getTime() - statSync(hist).mtimeMs) / 1000;
        const age = ageSec < 120 ? `${Math.round(ageSec)}s` : ageSec < 7200 ? `${Math.round(ageSec / 60)}m` : `${Math.round(ageSec / 3600)}h`;
        lines.push(`ok    .history present, mtime age ~${age} (exit 2 from keysync means some origins failed; store may still be usable)`);
      } else {
        lines.push("WARN  no .history beside the store yet (keysync has not recorded adds/removes)");
      }
    }
  }

  if (o.botsPath && o.agentsPath && existsSync(o.botsPath) && existsSync(o.agentsPath)) {
    const botsM = statSync(o.botsPath).mtimeMs;
    const agentsM = statSync(o.agentsPath).mtimeMs;
    if (agentsM + 1000 < botsM) {
      lines.push("WARN  agents.txt is older than bots.yaml: run `wba-ops agents` (edits to agents.txt alone are overwritten)");
    } else {
      lines.push("ok    agents.txt is not older than bots.yaml");
    }
  }

  if (o.acceptSignaturePath) {
    if (!existsSync(o.acceptSignaturePath)) {
      lines.push(`WARN  Accept-Signature nginx snippet missing at ${o.acceptSignaturePath} (clients may see raw 460/461)`);
    } else {
      lines.push("ok    Accept-Signature snippet path exists");
    }
  }

  for (const l of EXIT_TABLE) lines.push(l);
  lines.push("Next: DAY-2.md checklist. Doctor never weakens allowlists and never adds --allow-private-*.");
  return { ok, mutated: false, lines: lines.map(printable) };
}

export interface UnknownAgentResult {
  suggestions: string[];
  wrote: false;
  reminder: string;
}

/** Suggest bots.yaml / agents lines from audit text that includes rule 9534139. Never writes. */
export function suggestUnknownAgents(
  audit: string,
  opts: { requireRule?: boolean } = {},
): UnknownAgentResult {
  const requireRule = opts.requireRule !== false;
  const suggestions: string[] = [];
  const seen = new Set<string>();
  // Split into chunks around rule id so a stray Signature-Agent elsewhere is ignored when requireRule.
  const chunks = requireRule
    ? audit.split(/(?=\[id\s+"9534139"\]|id:9534139\b)/i).filter((c) => /9534139/.test(c))
    : [audit];
  const re = /Signature-Agent\s*:\s*(?:[A-Za-z0-9_]+=)?"?(https:\/\/[^"\s;]+)"?/gi;
  for (const chunk of chunks) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(chunk))) {
      const url = m[1].replace(/\/$/, "");
      if (seen.has(url)) continue;
      seen.add(url);
      // Suggest only — no Signature body, no auto-enroll.
      suggestions.push(`# suggested from audit (untrusted until validate):`);
      suggestions.push(`# - name: <pick-a-name>`);
      suggestions.push(`#   wba: ${url}`);
      suggestions.push(`${url}`);
    }
  }
  return {
    suggestions: suggestions.map(printable),
    wrote: false,
    reminder: printable(
      "Suggest only: copy into bots.yaml after you pick a name, then wba-ops validate → agents → sync-keys. "
      + "Remove temporary audit rule 9534139 when done (it logs raw Signature). Never enroll from Signature-Agent alone.",
    ),
  };
}

/** Offline next-step prose for a tx.wba_status/reason; no network, no npm. */
export function debugSigExplain(statusReason: string): string {
  const key = statusReason.trim().toLowerCase();
  const map: Record<string, string> = {
    "invalid/bad-signature":
      "Rebuild the expected signature base with `wba-ops debug-sig curl …` (reuses sign.ts). Check covered components (@method @authority @path signature-agent), Host vs @authority, and that the bot's keyid is a thumbprint. Optional second opinion on your laptop only — do not upload prod signatures to a hosted verifier as primary.",
    "unverified/unknown-agent":
      "Agent not in the key store. Temporary audit rule 9534139 → `wba-ops unknown-agent` (suggest only) → add to bots.yaml → validate → agents → sync-keys. Do not auto-enroll.",
    "unverified/unknown-key":
      "keyid not in the store. Run sync-keys; confirm directory kids are RFC 7638 thumbprints (label kids are dropped).",
    "invalid/expired":
      "Signature expires at its expires time. Sync NTP on WAF and keysync host; check created/expires skew.",
    "invalid/too-old":
      "Signature older than tx.wba_max_age. Check clock skew and the bot's created timestamp.",
    "invalid/not-yet-valid":
      "created is ahead of your clock (beyond skew). Check NTP.",
    "unverified/keystore-unavailable":
      "Mount the keys *directory* (not only the file) readable by nginx workers; run doctor.",
  };
  return printable(
    map[key]
      ?? `See README Outcomes for ${statusReason}. Path: doctor → reason → wba-ops debug-sig (sign.ts base) → validate → lab interop.sh → FOR-BOT-OPERATORS. No npm install on the ops path.`,
  );
}
