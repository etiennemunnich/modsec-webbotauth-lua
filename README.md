# modsec-webbotauth-lua

> **Do not use this in production yet.** This is an alpha for a few testers. Run it only on test sites. Rule IDs, settings and log fields may change before the first release.

Licensed under the [Apache License 2.0](LICENSE).

This checks signed requests from bots and AI agents at your web application firewall (WAF). It runs inside ModSecurity v3 with the OWASP Core Rule Set (CRS), on the official CRS nginx image.

## What it does

Some bots now sign their requests, using a standard called [Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/). The bot signs each request with a private key, and publishes the matching public key on its own website. Anyone can then check that a request really came from that bot.

This project does three things:

1. `wba-keysync` downloads the public keys of the bots you choose.
2. The plugin checks the signature on each request against those keys.
3. It gives your WAF rules the result: `verified`, `invalid`, `unverified` or `not-signed`, and which bot signed.

It does not block anything on its own. You decide what happens, with rules. [`lua/wba/recipes.conf`](lua/wba/recipes.conf) has six example rules.

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

1. Run the Quick start. Tell me if a step fails or is unclear.
2. Put it in front of a test site in log-only mode. First set your site's host names (`tx.wba_site_names`, rule 9534017 in [`web-bot-auth-config.conf`](lua/wba/web-bot-auth-config.conf)): until you do, no signature verifies. Load the plugin without the example rules that refuse requests. Read the log lines for a few days.
3. Choose the signing bots (level `signature`) from [`BOTS.md`](wba-keysync/BOTS.md) and copy them into your `bots.yaml`. Run `agents.ts` to write `agents.txt` from it, then run `wba-keysync` from cron. A log line names a bot only once its signature verifies. Before that, the audit log shows the request's `Signature-Agent` header.
4. If you want, turn on one refusing rule at a time.

I most want to hear about:

- a request it got wrong, such as a real bot marked `invalid`, or a request refused that should have passed;
- extra load or slower responses at your WAF;
- any step in the docs that is wrong, missing or hard to follow;
- anything that looks like a security hole. Please report these privately: see [SECURITY.md](SECURITY.md).

## Known limits

Read [Known limits](lua/wba/README.md#known-limits) before you start. The three that matter most for a test:

- **Rule IDs may still change** before the first release: 9534000-9534999 is not yet registered with the CRS plugin registry. Exclusions that name them may need updating.
- **Behind a load balancer that ends TLS,** you must edit the nginx guard, or every signed request gets a 400.
- **`validate.ts`, `agents.ts`, `report.ts`, `lists.ts`, `robots.ts` and the interop check need Bun.** The other tools also run on Node 26.

## Feedback

Open an issue and pick the form that fits:

- **Wrong result:** a request the plugin judged wrongly. Paste its log line.
- **Something broke:** a step failed, a tool crashed, or nginx would not start.
- **Docs problem:** a step that is wrong, missing or hard to follow.
- **Other feedback:** anything else.

For a security problem, do not open an issue: see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0: you may use, change and share this code under the terms in [LICENSE](LICENSE). [NOTICE](NOTICE) lists the third-party material it includes, and its licenses.
