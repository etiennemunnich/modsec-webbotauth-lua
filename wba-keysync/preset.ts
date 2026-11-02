// preset.ts: category / alias filter for agents.ts and validate.ts.
// Selection only — never skips validate, never writes allowlists.
// Category names mirror validate.ts CATEGORIES (kept here to avoid a cycle).
import type { Bot } from "./validate.ts";

const CATEGORY_KEYS = new Set([
  "search", "training", "ai-search", "user-fetch", "agent", "local-agent",
  "research", "archive", "security-scanner", "seo", "social-preview",
  "monitoring", "dataset", "site-service", "advertising",
]);

/** `ai` expands to the AIPREF / agent categories; every other token is a category key. */
const ALIASES: Record<string, readonly string[]> = {
  ai: ["training", "ai-search", "user-fetch", "agent", "local-agent"],
};

/** Category set for a comma-separated `--preset` value, or throws. */
export function expandPreset(raw: string): Set<string> {
  const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) throw new Error("--preset is empty: pass category names (or ai), comma-separated");
  const out = new Set<string>();
  for (const token of parts) {
    const alias = ALIASES[token];
    if (alias) {
      for (const c of alias) out.add(c);
      continue;
    }
    if (!CATEGORY_KEYS.has(token)) {
      throw new Error(`unknown preset/category ${JSON.stringify(token)} (known: ${["ai", ...CATEGORY_KEYS].join(", ")})`);
    }
    out.add(token);
  }
  return out;
}

/** Bots whose `category` is in the preset set. */
export function filterByPreset(bots: Bot[], categories: Set<string>): Bot[] {
  return bots.filter((b) => typeof b.category === "string" && categories.has(b.category));
}
