# modsec-webbotauth-lua

> **Alpha: do not use this in production yet.** This is a public alpha, for testing only. Run it on test sites, never in front of traffic you depend on. Rule IDs, settings and log fields may change before the first release. What is in this version: [CHANGELOG.md](CHANGELOG.md).

Licensed under the [Apache License 2.0](LICENSE).

This checks signed requests from bots and AI agents at your web application firewall (WAF). It runs inside ModSecurity v3 with the OWASP Core Rule Set (CRS), on the official CRS nginx image.

## What it does

Some bots now sign their requests, using a standard called [Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/). The bot signs each request with a private key, and publishes the matching public key on its own website. Anyone can then check that a request really came from that bot.

This project does four things:

1. `wba-keysync` downloads the public keys of the bots you choose.
2. The plugin checks the signature on each request against those keys.
3. It gives your WAF rules the result: `verified`, `invalid`, `unverified` or `not-signed`, and which bot signed. [Outcomes and reasons](lua/wba/README.md#outcomes-and-reasons) lists every outcome and what it means.
4. `lists.ts` writes plain ModSecurity rules from the IP lists and User-Agent names that bot operators publish, for the bots that do not sign yet. A request whose User-Agent names a bot is checked against that bot's own list: from a listed address it is `verified`, from anywhere else only `claimed`. A `policy` per bot (`allow`, `deny` or `log`) says what to do with it. With `policy_mode: log`, the default, the rules only write what they would refuse; `policy_mode: enforce` refuses with 403.

It refuses almost nothing on its own; you decide what happens, with rules. [`lua/wba/recipes.conf`](lua/wba/recipes.conf) has six example rules. The one exception is a signed request it cannot read: a body digest the signature covers that cannot be parsed gets a 400 (rule 9534107).

## What is in this repository

| Folder | What it is |
|---|---|
| [`lua/wba/`](lua/wba/README.md) | The plugin: Lua code, ModSecurity rules, nginx settings and a Dockerfile. **Start with its README.** |
| [`wba-keysync/`](wba-keysync/) | Command-line tools: download bot keys, check a list of bots, write `agents.txt` from it (`agents.ts`), write IP and User-Agent rules from it (`lists.ts`), print a suggested `robots.txt` (`robots.ts`), sign test requests, report what the WAF saw, clean up replay files. |
| [`wba-keysync/BOTS.md`](wba-keysync/BOTS.md) | A starting list of bots, each linked to its operator's own documentation. |
| [`lua/tests/`](lua/tests/) | The tests. |
| [`tests/regression/`](tests/regression/) | CRS-style [go-ftw](https://github.com/coreruleset/go-ftw) tests for the rules, sent through a test bot that signs them. |

## Try it

You need [Finch](https://github.com/runfinch/finch) or Docker, and [Bun](https://bun.sh) (or Node 26). The [Quick start](lua/wba/README.md#quick-start) takes about five minutes. It builds the image, makes a test bot, and sends one signed and one unsigned request. To install on Debian 13 without the image, follow [GETTING-STARTED.md](lua/wba/GETTING-STARTED.md).

## What to test

1. Run the Quick start. If a step fails or is unclear, open an issue.
2. Put it in front of a test site with no rule that refuses. Load the plugin and leave `recipes.conf` out: the plugin then only sets variables and writes one JSON log line for each signed request ([Logs](lua/wba/README.md#logs)). First set your site's host names (`tx.wba_site_names`, rule 9534017 in [`web-bot-auth-config.conf`](lua/wba/web-bot-auth-config.conf)): until you do, no signature verifies (`unverified/no-site-names`). Read the log lines for a few days.
3. Choose your bots. Copy [`wba-keysync/bots.seed.yaml`](wba-keysync/bots.seed.yaml) to `bots.yaml`, delete the bots you do not recognise, check it with `validate.ts`, and write `agents.txt` from it with `agents.ts`; only bots with a key source (level `signature` in [`BOTS.md`](wba-keysync/BOTS.md)) end up there. Then run key sync from cron. The steps are in the plugin README under [List the bots you recognise](lua/wba/README.md#2-list-the-bots-you-recognise) and [Keep their keys current](lua/wba/README.md#3-keep-their-keys-current). A log line names a bot only once its signature verifies. A bot you have not listed shows as `unverified/unknown-agent`, with no name; to see which bot it is, add the audit rule (9534139) under [Other logs](lua/wba/README.md#other-logs) for a while, and the audit log entry shows the request's `Signature-Agent` header.
4. If you want, turn on one refusing rule at a time.

The most useful reports:

- a request it got wrong, such as a real bot marked `invalid`, or a request refused that should have passed;
- extra load or slower responses at your WAF;
- any step in the docs that is wrong, missing or hard to follow;
- anything that looks like a security hole. Please report these privately: see [SECURITY.md](SECURITY.md).

## Known limits

Read [Known limits](lua/wba/README.md#known-limits) before you start. The two that matter most for a test:

- **Rule IDs may still change** before the first release: 9534000-9534999 is not yet registered with the CRS plugin registry. Exclusions that name them may need updating.
- **Some tools need Bun:** `validate.ts`, `agents.ts`, `report.ts`, `lists.ts`, `robots.ts`, and `lua/tests/interop/interop.sh`, which checks your WAF against the latest upstream signing library and test vectors ([Check your deployment against the latest upstream](lua/wba/README.md#check-your-deployment-against-the-latest-upstream)). The other tools also run on Node 26.

## Feedback

[Open an issue](https://github.com/etiennemunnich/modsec-webbotauth-lua/issues/new/choose) and pick the form that fits:

- **Wrong result:** a request the plugin judged wrongly. Paste its log line.
- **Something broke:** a step failed, a tool crashed, or nginx would not start.
- **Docs problem:** a step that is wrong, missing or hard to follow.
- **Other feedback:** anything else.

For a security problem, do not open an issue: see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0: you may use, change and share this code under the terms in [LICENSE](LICENSE). [NOTICE](NOTICE) lists the third-party material it includes, and its licenses.
