# Day-2 checklist (operators)

One path: **`bun wba-keysync/wba-ops.ts`**. Fail-closed defaults. Do not mount `recipes.conf` as production policy.

> Catalogue `verified` in BOTS.md ≠ request `tx.wba_status=verified`.

## After Quick start (502 = pass)

A signed demo request that returns **502** means the WAF accepted it (no backend in the demo). Next:

```bash
bun wba-keysync/wba-ops.ts init-bots bots.yaml          # copy seed; edit what you recognise
bun wba-keysync/wba-ops.ts validate bots.yaml           # first-party checks; optional --preset search,ai
bun wba-keysync/wba-ops.ts agents bots.yaml --out /srv/wba/agents.txt
# install wba-keysync/deploy/ units (User=wba; no --allow-private-* baked in)
bun wba-keysync/wba-ops.ts sync-keys --origins /srv/wba/agents.txt --out /srv/wba/keys/wba-keys.tsv
# mount the keys *directory* at /etc/modsecurity.d/wba/keys
bun wba-keysync/wba-ops.ts doctor --store /srv/wba/keys/wba-keys.tsv --bots bots.yaml --agents /srv/wba/agents.txt
```

## Lists (log first)

```bash
bun wba-keysync/wba-ops.ts sync-lists bots.yaml --out /srv/wba/bots          # dry-run impact
bun wba-keysync/wba-ops.ts sync-lists bots.yaml --out /srv/wba/bots --write  # then nginx -t && reload yourself
```

Default `policy_mode: log`. `allow` without a fetched list does **not** refuse impostors (`no-list`).

## Signature failure

1. `wba-ops doctor`
2. JSON log `status`/`reason` → README Outcomes
3. `wba-ops debug-sig explain <status/reason>` then `wba-ops debug-sig curl … --dir <test-dir>` (signature base; offline)
4. `wba-ops validate` on the directory URL
5. Lab only: [CF research /debug](https://http-message-signatures-example.research.cloudflare.com/debug) — not a seed
6. Share [FOR-BOT-OPERATORS.md](FOR-BOT-OPERATORS.md) with the signing side

## Unknown signing bot

Temporary audit rule **9534139** → `wba-ops unknown-agent --audit FILE` (**suggest only**) → edit bots.yaml → validate → agents → sync-keys → **remove 9534139**. Never enroll from `Signature-Agent` alone.

## Exit codes

| Tool | 0 | 2 | 1 |
|---|---|---|---|
| sync-keys | all origins usable | some failed (store written) | usage/config (store untouched) |
| sync-lists | every list fetched | written but kept/none | nothing changed / check failed |

Private exceptions stay exact CLI flags you type: keysync `--allow-private-origin`; lists `--allow-private-url`. Doctor never adds them.

## Pending seed WBA

Active signing seed: youbot, chatgpt-agent, cloudflare-browser-run, kernel-agent, kernel-search, exasearchbot. Leave other commented `wba` rows pending until first-party Signature-Agent is clear **and** `validate` keeps thumbprint kids. Enroll only proven first-party directories — never from public self-reg scrapes.

## Optional second opinions (external)

Edge/SaaS verifiers are complementary to this origin ModSec plugin — not a seed feed. Cite only:

- [Cloudflare Web Bot Auth](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/) (string `Signature-Agent`)
- [cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth)
- [Agent-readiness WBA explainer](https://specification.website/spec/agent-readiness/web-bot-auth/) (RFC 9421 / `tag=web-bot-auth` / common mistakes)
- [webbotauth.net guide](https://webbotauth.net/guide) · [kb rubric](https://webbotauth.net/kb)
- [Fingerprint WBA implementation](https://docs.fingerprint.com/docs/bot-detection/web-bot-auth-implementation)
- [Protocol draft](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) · [registry draft](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/)
- Peers: [Vercel Bot Management](https://vercel.com/docs/bot-management) · [Akamai WBA](https://www.akamai.com/blog/security/redefine-trust-web-bot-authentication) · [DataDome bot authentication](https://docs.datadome.co/docs/bot-authentication) · [Stytch WBA](https://stytch.com/blog/stytch-supports-web-bot-auth/) · [Shopify changelog](https://shopify.dev/changelog/bots-and-agents-should-identify-themselves-via-web-bot-auth) · [HUMAN agent trust levels](https://docs.humansecurity.com/applications/about-agent-trust-levels)

Never paste production signatures into hosted verifiers. No Coraza path here.
