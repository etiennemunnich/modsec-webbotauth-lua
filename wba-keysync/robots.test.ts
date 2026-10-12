// robots.test.ts: wba-keysync/robots.ts, a suggested robots.txt from a bots
// file. Runs unchanged under `bun test` and `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { robotsTxt } from "./robots.ts";
import type { Bot } from "./validate.ts";

const at = new Date("2026-10-11T00:00:00Z");

test("one group for every bot whose policy is deny; robots tokens first, else User-Agent tokens", () => {
  const bots: Bot[] = [
    { name: "gptbot", user_agent: "GPTBot", policy: "deny" },
    { name: "google-extended", user_agent: "Googlebot", robots: ["Google-Extended"], policy: "deny" },
    { name: "aider", user_agent: "Aider/", policy: "deny" },
    { name: "googlebot", user_agent: "Googlebot", policy: "allow" },
    { name: "logged", user_agent: "LogBot", policy: "log" },
    { name: "none", user_agent: "NoPolicyBot" },
    { name: "again", user_agent: ["gptbot", "Better Stack Bot"], policy: "deny" },
  ];
  assert.equal(robotsTxt(bots, "bots.yaml", at), [
    "# Suggested by wba-keysync/robots.ts from bots.yaml on 2026-10-11.",
    "# robots.txt asks; it does not refuse anything. The WAF rules from lists.ts do.",
    "# Left out (not one word, so not a product token): again: \"Better Stack Bot\"",
    "",
    "User-agent: GPTBot",
    "User-agent: Google-Extended",
    "User-agent: Aider",
    "Disallow: /",
    "",
  ].join("\n"));
});

test("no bot to deny: nothing to ask", () => {
  assert.match(robotsTxt([{ name: "a", user_agent: "ABot", policy: "allow" }], "b.yaml", at), /# No bot in b\.yaml has policy deny: nothing to ask\.\n$/);
  assert.doesNotMatch(robotsTxt([], "b.yaml", at), /User-agent/);
});
