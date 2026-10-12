// audit-entry.ts: for crs-evidence.sh. Reads container logs on stdin, finds the
// ModSecurity JSON audit entry whose X-WBA-Test request header is TAG, and
// prints, as Markdown, the request as ModSecurity recorded it and the CRS rules
// it matched (anomaly totals and the outbound 502 rule left out).
//   ... | TAG=<tag> node lua/tests/live/audit-entry.ts
import { readFileSync } from "node:fs";

type Message = { message?: string; details?: { ruleId?: string; data?: string; tags?: string[] } };
type Entry = { transaction?: { request?: { method?: string; uri?: string; http_version?: number | string; headers?: Record<string, string>; body?: string }; messages?: Message[] } };

const fence = "```";
for (const line of readFileSync(0, "utf8").split("\n")) {
  if (!line.startsWith("{")) continue;
  let t: Entry["transaction"];
  try { t = (JSON.parse(line) as Entry).transaction; } catch { continue; }
  const headers = t?.request?.headers ?? {};
  if (Object.entries(headers).find(([k]) => k.toLowerCase() === "x-wba-test")?.[1] !== process.env.TAG) continue;
  const r = t?.request ?? {};
  const out = ["Request, as ModSecurity recorded it:", "", fence + "http", `${r.method} ${r.uri} HTTP/${r.http_version}`];
  for (const [k, v] of Object.entries(headers)) out.push(`${k}: ${v}`);
  if (r.body) out.push("", String(r.body).slice(0, 200));
  out.push(fence, "", "CRS rules matched (anomaly totals and the outbound 502 rule left out):", "", fence);
  const ms = (t?.messages ?? []).filter((m) => !/^9534|^949110$|^980170$|^950100$/.test(m.details?.ruleId ?? ""));
  for (const m of ms) {
    const pl = m.details?.tags?.find((x) => x.startsWith("paranoia-level/"))?.slice("paranoia-level/".length) ?? "?";
    out.push(`${m.details?.ruleId} (PL${pl}) "${m.message}"`, `    ${(m.details?.data ?? "").slice(0, 300)}`);
  }
  if (!ms.length) out.push("none");
  out.push(fence);
  console.log(out.join("\n"));
  process.exit(0);
}
console.log("(no audit log entry for this request)");
