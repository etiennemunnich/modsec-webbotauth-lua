// issue-forms.ts <dir>: the GitHub issue forms in <dir> parse, and follow the
// issue-form rules GitHub enforces (a form that breaks one is silently not
// offered): name and description, a body with a field, unique ids and labels,
// dropdown options as strings, render on textareas only; config.yml's links.
//   bun lua/tests/issue-forms.ts .github/ISSUE_TEMPLATE
import { readdirSync, readFileSync } from "node:fs";
const dir = process.argv[2]; let bad = 0;
const fail = (f: string, m: string) => { console.log(`FAIL ${f}: ${m}`); bad = 1; };
for (const f of readdirSync(dir).filter((n) => n.endsWith(".yml"))) {
  let doc: any;
  try { doc = Bun.YAML.parse(readFileSync(`${dir}/${f}`, "utf8")); } catch (e) { fail(f, `YAML: ${(e as Error).message}`); continue; }
  if (f === "config.yml") {
    if (typeof doc.blank_issues_enabled !== "boolean") fail(f, "blank_issues_enabled not a boolean");
    for (const l of doc.contact_links ?? []) if (!l.name || !String(l.url ?? "").startsWith("https://") || !l.about) fail(f, "contact link needs name, https url, about");
    console.log(`ok   ${f}`); continue;
  }
  for (const k of ["name", "description"]) if (typeof doc[k] !== "string" || !doc[k]) fail(f, `missing ${k}`);
  if (!Array.isArray(doc.body) || !doc.body.some((b: any) => b.type !== "markdown")) fail(f, "body needs a non-markdown field");
  const ids = new Set<string>(), labels = new Set<string>();
  for (const b of doc.body ?? []) {
    if (!["markdown", "textarea", "input", "dropdown", "checkboxes"].includes(b.type)) fail(f, `bad type ${b.type}`);
    if (b.type === "markdown") { if (typeof b.attributes?.value !== "string") fail(f, "markdown needs value"); continue; }
    if (!/^[A-Za-z0-9_-]+$/.test(b.id ?? "") || ids.has(b.id)) fail(f, `bad or duplicate id ${b.id}`); ids.add(b.id);
    const label = b.attributes?.label; if (!label || labels.has(label)) fail(f, `bad or duplicate label ${label}`); labels.add(label);
    if (b.type === "dropdown" && !(b.attributes.options?.length > 0 && b.attributes.options.every((o: unknown) => typeof o === "string"))) fail(f, `${b.id}: options must be strings`);
    if (b.attributes.render && b.type !== "textarea") fail(f, `${b.id}: render only on textarea`);
  }
  console.log(`ok   ${f} (${ids.size} fields, labels ${JSON.stringify(doc.labels)})`);
}
process.exit(bad);
