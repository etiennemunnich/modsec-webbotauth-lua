# Web Bot Auth for ModSecurity

> **Alpha (v0.1.0-alpha.1): do not use this in production yet.** Test it on a test site first. Rule IDs, settings and log fields may still change before the first release ([Known limits](#known-limits)). Licensed under the Apache License 2.0.

This project tells your WAF which bots a request really comes from. It runs inside ModSecurity v3 with the OWASP Core Rule Set (CRS), and has two parts:

- **Signatures ([Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/)).** A bot signs each request with a private key and publishes the matching public key on its own site. This plugin is the verifier: the program that checks a signature against that key. It is Lua, run by ModSecurity.
- **Bot lists.** Most bots do not sign yet, but their operators publish the addresses they send from. [Bot lists](#bot-lists-and-policies) check a request that names a bot in its User-Agent against that bot's list. They are plain ModSecurity rules, written by a script.

**How it works.** Ahead of time, a cron job downloads the signing bots' public keys and the bots' IP lists. Then, for each request:

1. **Is it signed?** The signature is checked with that bot's key: `verified`, or not.
2. **Does the User-Agent name a bot?** The address is checked against that bot's list: on it, `verified`; off it, only `claimed`.
3. **What did you decide?** Your rules, or a `policy` per bot, let it through, refuse it or log it.

For example: OpenAI's ChatGPT agent, signed, is `verified`. "GPTBot" from one of OpenAI's addresses is `verified`. "GPTBot" from anywhere else is only `claimed`, and with `policy: allow` and `policy_mode: enforce` it is refused as a fake (the default `policy_mode: log` only logs it). A normal browser gets nothing, and CRS treats it as usual.

Apart from a 400 for broken protocol ([Controls and defaults](#controls-and-defaults)), nothing is refused unless you say so: the plugin and the lists set ModSecurity variables, write a log line for every signed request, and leave the decisions to your rules. [`recipes.conf`](recipes.conf) has six example rules.

| You want to | Read |
|---|---|
| See how it works, with diagrams | [HOW-IT-WORKS.md](HOW-IT-WORKS.md) |
| Try it in five minutes | [Quick start](#quick-start) |
| Run it for real | [Set up](#set-up) |
| Install it on your own nginx (Debian 13), step by step | [GETTING-STARTED.md](GETTING-STARTED.md) |
| Know what each file does | [The files](#the-files) |
| Write policy | [Use it](#use-it) |
| Check bots by their IP lists | [Bot lists and policies](#bot-lists-and-policies) |
| Read the logs | [Logs](#logs) |
| Fix something | [Troubleshooting](#troubleshooting) |
| Know what it does not do yet | [Known limits](#known-limits) |
| Make your bot verifiable | [FOR-BOT-OPERATORS.md](FOR-BOT-OPERATORS.md) |
| Know how it works, and why | [DESIGN.md](DESIGN.md) |
| See what is proven | [TESTING.md](TESTING.md), [CONFORMANCE.md](CONFORMANCE.md) |

## Quick start

Run these steps from the repository root. You need [Finch](https://github.com/runfinch/finch) or Docker, and [Bun](https://bun.sh) or Node 26. The commands use `finch` and `bun`.

- With Docker, type `docker` in place of `finch`. Every `finch` command on this page works with `docker`.
- With Node 26, type `node` in place of `bun`.
- On Linux, Finch runs as root: type `sudo finch`, and use `DOCKER="sudo finch"` for the test scripts.
- On macOS, Finch runs in a virtual machine (VM). Start it first: `finch vm init` the first time, `finch vm start` after that. Keep the repository under your home directory, which the VM can see. Run `finch vm stop` when you are done.

Everything the steps write goes in `wba-demo/`, which git ignores. [`lua/tests/live/quickstart.sh`](../tests/live/quickstart.sh) runs these exact steps as a test.

```bash
# 1. Build the image: the official CRS nginx image plus this plugin.
finch build -f lua/wba/Dockerfile -t crs-wba .

# 2. Make a test bot: a new Ed25519 key, and a key store (the file of
#    public keys the plugin reads) that lists it.
bun wba-keysync/sign.ts init wba-demo

# 3. Name your site. A signature made for any other host name never verifies.
cat > wba-demo/site.conf <<'CONF'
SecAction "id:9534017,phase:1,pass,nolog,t:none,setvar:'tx.wba_site_names=example.com'"
CONF

# 4. Run the image with the example rules (recipes.conf). No application runs
#    behind it here, so a request that passes every rule gets a 502 from nginx.
finch run -d --name waf -p 8443:8443 \
  -v "$PWD/wba-demo/keys:/etc/modsecurity.d/wba/keys:ro" \
  -v "$PWD/wba-demo/site.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-site-config.conf:ro" \
  -v "$PWD/lua/wba/recipes.conf:/etc/modsecurity.d/owasp-crs/plugins/wba-recipes-after.conf:ro" \
  crs-wba
```

Wait a few seconds for nginx to start. Then see it work:

```bash
# Unsigned, on the bot-only path /agents/ (recipe A): 403, asking for a signature.
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Host: example.com' https://localhost:8443/agents/hello

# Signed by your test bot: passes every rule, so 502 (--insecure: the demo certificate is self-signed).
bun wba-keysync/sign.ts curl https://localhost:8443/agents/hello --dir wba-demo --host example.com --insecure | sh

# The result: one line of JSON for each signed request.
finch logs waf 2>&1 | grep -F '{"event":"web-bot-auth"'
# ... "status":"verified","reason":"","agent":"https://test-agent.example/.well-known/http-message-signatures-directory" ...

# Done: remove the container and the demo files.
finch rm -f waf && rm -rf wba-demo
```

`sign.ts curl` prints the `curl` command it would run. Leave off `| sh` to read the signed headers instead of sending them. To verify real bots, list them and let key sync fetch their keys ([Set up](#set-up)). Key sync is `wba-keysync`, a program that downloads the public keys of the bots you list. Your rules decide what `verified` allows ([Use it](#use-it)).

## Set up

### What you need

- The official CRS nginx image, `owasp/modsecurity-crs:*-nginx-*` (Debian). The [`Dockerfile`](Dockerfile) pins `4.30.0-nginx-202610051210` by digest. [TESTING.md](TESTING.md#version-matrix) records the results on every CRS release of the last 12 months (ModSecurity 3.0.14 to 3.0.17, CRS 3.3.8 to 4.30.0). The Alpine images do not work: the Dockerfile uses `apt-get`.
- Or your own nginx with libmodsecurity 3.0.14 or later built with Lua 5.3, ModSecurity-nginx 1.0.x and CRS. See [Your own nginx](#your-own-nginx), and [GETTING-STARTED.md](GETTING-STARTED.md) for every step on Debian 13.
- HTTPS for signed traffic: a signature does not cover every part of a request ([step 5](#5-tls-and-load-balancers)). The image serves TLS on port 8443.
- Bun 1.3 or Node 26 wherever the `wba-keysync` tools run. Node 26 runs `cli.ts` (key sync), `sign.ts` and `sweep.ts`. `validate.ts`, `agents.ts`, `report.ts`, `lists.ts`, `robots.ts` and [`lua/tests/interop/interop.sh`](../tests/interop/interop.sh) need Bun.
- A clock kept in sync by NTP, on the WAF and on the key sync host. A signature may be dated up to 60 seconds ahead of your clock. It expires exactly at its `expires` time, unless you set a grace period. It counts for at most an hour after it was made.

### The files

Every file you set up or may change, in the order you meet them. "Plugins" is the CRS plugins directory, `/etc/modsecurity.d/owasp-crs/plugins/` in the image.

| File | What it does | Who writes it | Where it goes |
|---|---|---|---|
| `bots.yaml` | Your list of bots: each one's key source (`wba`), IP lists, User-Agent tokens and policy ([Bot lists and policies](#bot-lists-and-policies)). Start from [`bots.seed.yaml`](../../wba-keysync/bots.seed.yaml) | you | anywhere on the key sync host |
| `agents.txt` | The key sources key sync may fetch, one per line ([step 2](#2-list-the-bots-you-recognise)) | `agents.ts`, from `bots.yaml`; or you, by hand | the key sync host, given with `--origins` |
| `wba-keys.tsv` | The key store: every public key key sync accepted, read for each signed request | key sync | its directory, mounted at `/etc/modsecurity.d/wba/keys/` |
| `wba-keys.tsv.cache.json`, `wba-keys.tsv.history` | Key sync's HTTP cache, and a record of every key added or removed, for attributing a signature later | key sync | next to the key store |
| `web-bot-auth-bots-before.conf`, `web-bot-auth-bots/`, `versions.json`, `status.json`, `ids.json` | The bot list rules and their data, each list's version, what the last run did, and each bot's rule ids ([Bot lists and policies](#bot-lists-and-policies)) | `lists.ts`, from `bots.yaml` | the plugins directory, or mounted and included from it |
| [`web-bot-auth-config.conf`](web-bot-auth-config.conf) | The settings: your site names (required), grants and limits ([Controls and defaults](#controls-and-defaults)). Every setting is commented out until you set it | you, from the shipped copy | plugins, over the image's copy |
| your `*-after.conf` | Your rules: what `verified` allows, and what is refused. Start from [`recipes.conf`](recipes.conf), six examples | you | plugins (CRS loads it after its own rules) |
| [`wba.conf`](wba.conf) | The plugin's own rules: they run the verifier, set the `tx.wba_*` variables, write the JSON log line and send 400 for broken protocol. Do not edit it: remove a rule with `SecRuleRemoveById` in your `*-after.conf` | the project | plugins, as `web-bot-auth-before.conf` |
| [`nginx/web-bot-auth-accept-signature.conf`](nginx/web-bot-auth-accept-signature.conf) | Turns status 460 and 461 into 403 and 429 with an `Accept-Signature` header ([Asking for a signature](#asking-for-a-signature)) | the project; you, to ask for more | every `server` block |
| [`modsecurity_entry.lua`](modsecurity_entry.lua) | Its `CONFIG` names the key store and module paths, and can override the limits set in code (`CONFIG.policy`) | the project; you, on your own nginx or to change a limit | `/etc/modsecurity.d/wba/lua/` |
| [`wba_log.lua`](wba_log.lua) | Its `CONFIG.path` is where the JSON log lines go (`/dev/stdout`) | the project; you, on your own nginx | `/etc/modsecurity.d/wba/lua/` |
| `/var/lib/wba/replay` | Replay counters, only with [replay accounting](#replay-accounting) on. `sweep.ts` removes the old ones | the plugin | a filesystem of its own |

### 1. Build the image

```bash
finch build -f lua/wba/Dockerfile -t crs-wba .
# another CRS release:
finch build -f lua/wba/Dockerfile --build-arg CRS_IMAGE=owasp/modsecurity-crs:4.25.2-nginx-202610051210-lts -t crs-wba .
```

On top of the CRS image, the build adds [lua-openssl](https://github.com/zhaozg/lua-openssl) 0.11.1 (compiled in a separate stage against the image's own OpenSSL, so no compiler ends up in the image you run), the rules as a CRS "before" plugin, the settings file with every setting commented out, the nginx file for [`Accept-Signature`](#asking-for-a-signature) responses, and `/var/lib/wba/replay` for [replay accounting](#replay-accounting).

### 2. List the bots you recognise

You keep your list of bots in a bots file, `bots.yaml`. Key sync reads a simpler file made from it, `agents.txt`, with one key source per line. An agent is a bot, or an AI agent that acts for a person. Only keys from the agents in `agents.txt` can ever produce `verified`. Listing an agent gives it no extra access.

Start from the project's list, check it, and write `agents.txt` from it:

```bash
cp wba-keysync/bots.seed.yaml bots.yaml                        # 1. copy it, then delete the bots you do not recognise
bun wba-keysync/validate.ts bots.yaml                          # 2. check it: exit 1 on any failure; --strict also fails on warnings
bun wba-keysync/agents.ts bots.yaml --out /srv/wba/agents.txt  # 3. write agents.txt from it
```

**The project's list.** [`wba-keysync/bots.seed.yaml`](../../wba-keysync/bots.seed.yaml) uses the operators' own sources only, and explains its fields at the top. [`wba-keysync/BOTS.md`](../../wba-keysync/BOTS.md) is generated from it: each bot's category, its operator's description, every source and what it answered, and whether the bot is confirmed (its keys or IP list were fetched from the operator and checked) or only a claim. BOTS.md calls a confirmed bot `verified`; that is not the plugin's `verified`, which means a request's signature checked out. Most bots do not sign yet: only the few with a `wba` key source end up in `agents.txt`.

**Check a list of bots before you trust it**, this one or any you are offered. [`wba-keysync/validate.ts`](../../wba-keysync/validate.ts) checks every entry against the bot operator's own sources:
- its key directory, fetched the same way key sync fetches it, with its proof (a signature the directory carries to show it holds each key; see [DESIGN.md](DESIGN.md#possession-proofs));
- its published IP lists;
- any hand-kept copy of those IP ranges. It reports which ranges are stale, which are missing, and how much of the live list the copy covers.

**Write `agents.txt`.** [`wba-keysync/agents.ts`](../../wba-keysync/agents.ts) writes one line for each bot with a `wba` key source, and leaves the others out. Every line passes key sync's own parser: a bad entry stops it before anything is written. Bots that share a key source share one line. `--only name,name` writes only the bots you name. Run it again whenever you change `bots.yaml`: key sync picks up the new list on its next run.

You can also write `agents.txt` by hand, at any path you give key sync with `--origins`:

```
# a key directory (the default type): the origin
https://bot.example
# a JWK Set URL
https://bot.example/keys/jwks.json type=jwks_uri
# an OAuth Client ID Metadata Document
https://bot.example/oauth/client type=cimd
```

A key directory is listed by its origin: `https://`, the bot's host name in lower case and any port other than 443, with no path. Each bot's documentation says which URL and type it signs with.

**Decide bot by bot.** `bun wba-keysync/report.ts bots.yaml --log <your WAF log> --out report.md` writes a report with three parts:
- what each bot can prove: a signature, an IP list, reverse DNS, or only a User-Agent claim;
- its signed traffic in your log, verified or not, and why;
- a decisions block, one line per bot that can prove something: `policy: allow | deny | log`, `log` until you change it.

Copy each decision into the bot's entry in `bots.yaml` as `policy:`. [`lists.ts`](#bot-lists-and-policies) writes the rules for IP lists, User-Agent claims and policies from there. You act on signing bots through your own rules and grants too ([Use it](#use-it)).

### 3. Keep their keys current

[`wba-keysync`](../../wba-keysync/cli.ts) (key sync) fetches the keys of each agent in `agents.txt`. It writes them to the key store, the file of public keys the verifier reads. Run it every minute. It fetches a directory again only when its HTTP cache lifetime has run out, so most runs send no request at all. It never runs while a request waits. It fetches the URLs in your `agents.txt`, and the `jwks_uri` that a listed CIMD document names (that document's server chooses it, so it always gets the private-address check).

The examples below are for a Linux host. The repository is at `/opt/web-bot-auth`, the files are in `/srv/wba`, and key sync runs as the user `wba`. Use your own paths and user. Cron's `PATH` does not include Bun's default install directory (`~/.bun/bin`), so give the full path that `command -v bun` prints.

With cron:

```
# /etc/cron.d/wba-keysync
* * * * * wba cd /opt/web-bot-auth && flock -n /srv/wba/keys/wba-keysync.lock /usr/local/bin/bun wba-keysync/cli.ts --origins /srv/wba/agents.txt --out /srv/wba/keys/wba-keys.tsv >> /var/log/wba-keysync.log 2>&1
```

With systemd:

```ini
# /etc/systemd/system/wba-keysync.service
[Service]
Type=oneshot
User=wba
WorkingDirectory=/opt/web-bot-auth
ExecStart=/usr/local/bin/bun wba-keysync/cli.ts --origins /srv/wba/agents.txt --out /srv/wba/keys/wba-keys.tsv

# /etc/systemd/system/wba-keysync.timer
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
```

The key store's directory (`/srv/wba/keys` here) must be writable by the user key sync runs as. It must also be readable by the nginx workers in the container (uid 101).

Watch the exit code:

| Exit | Meaning | Do |
|---|---|---|
| 0 | every agent resolved to at least one usable key | nothing |
| 2 | some agent failed, or has no usable key. The store was still written, and failed agents keep their last good keys | read the output: it names the agent and why. Alert on this |
| 1 | usage error, or `agents.txt` is missing, lists nothing, or has a line key sync cannot parse (the output names the line). The store was not touched | fix the command or the file |

Key sync writes a new store and renames it over the old one in one step (an atomic rename), so a reader never sees half a file. Its HTTP cache and its history of every key added or removed sit next to the store ([The files](#the-files)). [DESIGN.md](DESIGN.md#wba-keysync-in-detail) says what it checks on every fetch.

**Your own bots on your own network.** Key sync never fetches from a private, loopback or link-local address (draft 6.7). For a bot whose keys are reachable only inside, name its exact origin on the command line, once for each: `--allow-private-origin https://bot.internal:8443`. Each such fetch is printed as a warning, and no `agents.txt` or bots file can turn it on. It covers only the URLs your `agents.txt` lists on that origin, never a `jwks_uri` that a CIMD document names. An `agents.txt` line can name any path on an excepted origin, so except only hosts you run. For `lists.ts`, name each private list's exact URL: `--allow-private-url https://lists.internal/bot.json`. TLS is still checked: give key sync your own CA with `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`.

### 4. Run the WAF

This is a Linux example for a real site. `/srv/wba` stands for your own directory, and `BACKEND=http://your-app:8080` for the URL of your application. On macOS, use a directory under `$HOME` instead of `/srv`: Finch's VM can see your home directory.

```bash
finch run -d --name waf -p 8443:8443 \
  -v /srv/wba/keys:/etc/modsecurity.d/wba/keys:ro \
  -v /srv/wba/web-bot-auth-config.conf:/etc/modsecurity.d/owasp-crs/plugins/web-bot-auth-config.conf:ro \
  -v /srv/wba/site-wba-rules-after.conf:/etc/modsecurity.d/owasp-crs/plugins/site-wba-rules-after.conf:ro \
  -e BACKEND=http://your-app:8080 crs-wba
```

- **Mount the key directory, not the file.** Key sync replaces the file by renaming a new one over it. A single-file bind mount would keep showing the old file. The plugin reads the store on every signed request, so a key change takes effect without a restart.
- **Settings:** your copy of [`web-bot-auth-config.conf`](web-bot-auth-config.conf), mounted over the image's copy. Set at least `tx.wba_site_names` in it ([Settings](#controls-and-defaults)).
- **Rules:** CRS loads any file named `*-after.conf` in its plugins directory after its own rules. Put your Web Bot Auth rules there ([Rule examples](#rule-examples)). By then the plugin and the [bot list rules](#bot-lists-and-policies) have set every `tx.wba_*` and `tx.bot_*` variable, whatever your file is called.
- Every other CRS image setting (paranoia level, anomaly thresholds, ports, TLS certificates) works as the [CRS image documentation](https://github.com/coreruleset/modsecurity-crs-docker) says.

### 5. TLS and load balancers

**Serve signed traffic over HTTPS.** A signature covers only the parts of a request the bot chose to sign. Say a bot signs `@authority` and its `Signature-Agent` entry, but not the path, and sends `GET /page`. Over plain HTTP, anyone on the path can change that to `GET /admin`, and the signature still verifies. Over TLS, nobody between the bot and your site can change anything.

The plugin cannot enforce this for you. ModSecurity cannot see whether the client used TLS, so a signed request over plain HTTP is verified like any other. Draft 6.1 asks a site to refuse such a request, and this plugin cannot ([CONFORMANCE.md](CONFORMANCE.md#declared-deviations)). So redirect plain HTTP to HTTPS for every name you serve, at nginx or at your load balancer.

**Behind a load balancer that ends TLS**, nginx receives plain HTTP from the load balancer, and cannot see the client's TLS either. Signatures need nothing extra there: the plugin verifies each request the same way. Let only your load balancer reach nginx (with a firewall rule or security group), so that no client can go around its TLS.

**The visitor's address behind a load balancer or CDN.** Your proxy passes the visitor's address in a header (`X-Forwarded-For`, `X-Real-IP`, or a CDN's own such as `CF-Connecting-IP`), and nginx's real-IP module swaps it in for requests from addresses you trust. **Where you put the settings decides what ModSecurity sees.** At http or server level, nginx swaps the address before ModSecurity reads it; inside a `location` block, afterwards, and ModSecurity (connector 1.0.4) keeps the proxy's address. The CRS image's `SET_REAL_IP_FROM` and `REAL_IP_HEADER` sit inside `location /`, so on their own ModSecurity logs and matches the proxy (tested: `lua/tests/live/real-ip.sh`). Add an http-level file instead, for example mounted as `/etc/nginx/conf.d/00-real-ip.conf`:

```nginx
set_real_ip_from 192.0.2.10;   # your load balancer's or CDN's addresses, and nothing else
real_ip_header X-Forwarded-For;
real_ip_recursive on;          # read the list from the right, skipping your own proxies
```

List only your own proxies. Anyone you list can claim any address, and address-based rules (including published bot address lists) would then believe them.

**Hosts you do not serve.** A signature made for a host name outside `tx.wba_site_names` never verifies (`invalid/foreign-authority`). Also add a catch-all server in every deployment. Then a request for a name you do not serve reaches no application at all, a full URL in the request line included (`GET http://other.example/` with `Host: example.com` lands on the catch-all when other.example is not a name you serve; when it is, see [Known limits](#known-limits)):

```nginx
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_reject_handshake on;   # TLS for a name no server lists: no certificate, no handshake
    return 421;                # any other request for an unknown Host: Misdirected Request (RFC 9110 15.5.20)
}
```

### Your own nginx

The image is the tested path. To install into an nginx you build and run yourself, put the files in [The files](#the-files) where that table says, plus two that the image builds in. [GETTING-STARTED.md](GETTING-STARTED.md) does this on Debian 13 with Debian's own nginx and ModSecurity, every command tested.

- lua-openssl's `openssl.so`, in Lua 5.3's C path (for example `/usr/local/lib/lua/5.3/`): build 0.11.1 at commit `bd640c2` against your OpenSSL 3 and Lua 5.3 headers, as the Dockerfile's `build` stage does.
- The verifier's modules: every `.lua` file in `lua/wba/` other than `modsecurity_entry.lua` and `wba_log.lua`, in `/etc/modsecurity.d/wba/lua/wba/`.

[`nginx/web-bot-auth-accept-signature.conf`](nginx/web-bot-auth-accept-signature.conf) is needed only if you use recipes A, D or E. If you change any path, change it in `modsecurity_entry.lua`, `wba_log.lua` and `wba.conf` together: `wba.conf`'s `SecRuleScript` lines name the two Lua entry files. If nginx runs as a daemon, point `wba_log.lua`'s `CONFIG.path` at a file the worker user can append to. `/dev/stdout` is right only in a container.

### Upgrading

Upgrade the image first, then `wba-keysync`: the verifier reads every key-store format key-sync has written, and a new key-sync may write a newer one. Read [CHANGELOG.md](../../CHANGELOG.md) for changed settings, reasons and recipes before upgrading.

## Use it

### What every request gets

The plugin sets these ModSecurity variables on every request. Every variable after the first two is `n/a` unless the request verified (`tx.wba_granted` is then `0`). So a negated test always has something to match:

| Variable | Value |
|---|---|
| `tx.wba_status` | `verified`, `invalid`, `unverified` or `not-signed` |
| `tx.wba_reason` | why, as a fixed string ([Outcomes and reasons](#outcomes-and-reasons)) |
| `tx.wba_agent` | the identifier the request is attributed to: a bot's key directory URL, or its `jwks_uri` / `cimd` URL without the query |
| `tx.wba_agents` | every identifier a signature on the request verified for, space-separated |
| `tx.wba_agent_proof` | whether the bot's directory proved it holds the key: `valid`, `invalid`, `expired` or `none` ([DESIGN.md](DESIGN.md#possession-proofs)) |
| `tx.wba_keyid` | the key's RFC 7638 thumbprint |
| `tx.wba_label`, `tx.wba_created`, `tx.wba_expires` | the signature's label and validity window |
| `tx.wba_covered` | the request parts it signed, space-separated (`@authority signature-agent @path`) |
| `tx.wba_sighash` | SHA-256 of the signature's bytes, to spot a replay in logs |
| `tx.wba_granted` | `1` when the agent is in your grants and the signature covered what a grant needs (`@method @path` by default; [settings](#controls-and-defaults)) |
| `tx.wba_uses`, `tx.wba_nonce_uses` | with [replay accounting](#replay-accounting) on: how many times this host has seen the signed statement, and its nonce |

`verified` means all of this:
- the request's host is one of your site names;
- a signature tagged `web-bot-auth` is inside its time window;
- it covers the host and the `Signature-Agent` entry it names;
- it was made with a current key that the named bot publishes and you listed;
- the body matches any body digest it covers. A digest is a hash of the body, sent in a header.

`verified` proves who signed. It does not prove that the request is harmless (draft 4.1). Verified traffic still runs every CRS attack rule. A request with no `Signature-Agent`, signed with a key you hold, is `verified` with reason `url-less`: it names no bot, only the key. [DESIGN.md](DESIGN.md#what-verified-means) has the full definition.

### Controls and defaults

One setting is required: your site's own host names. Until it is set, no signed request is verified (`unverified/no-site-names`).

Two limits are on by default:
- a signature counts for at most an hour after it was made (`tx.wba_max_age`, 3600 seconds);
- a grant needs the signature to cover `@method @path` (`tx.wba_grant_require_components`). A grant marks a verified bot you trust (`tx.wba_granted=1`) for your own rules to read.

Every other control is off until you turn it on. A signature's window (from its `created` to its `expires`) has no cap by default, because the maximum age already bounds how long it counts; the draft's 24 hours is advice to signers (draft 5.2).

Installing the plugin changes no request's outcome, except broken protocol, which gets 400 from rule 9534107: a signature from a key you list whose covered body digest header (`Content-Digest`, `Repr-Digest` or `Unencoded-Digest`) cannot be parsed. That is `invalid/malformed-digest` whatever `tx.wba_malformed` says, because ignoring the header would leave the body unchecked while the signature says it covers it. The rule also refuses a request whose `Signature-Input` or `Signature` header cannot be parsed, but only with `tx.wba_malformed=reject` (the Unparsable headers row below).

One CRS check also changes: at paranoia level 4, rule 920274 skips the three signature headers ([CRS paranoia levels](#crs-paranoia-levels)).

Settings live in [`web-bot-auth-config.conf`](web-bot-auth-config.conf), each a commented-out rule to copy and edit. Set one there for the whole site, or for some paths only with a rule of your own placed before the plugin (the file shows how).

| Setting | Variable | Default | Effect |
|---|---|---|---|
| **Site names (required)** | `tx.wba_site_names` | none: nothing verifies | this site's own `Host` values (`host` or `host:port`). A signed request for any other is `invalid/foreign-authority`: a signature a bot made for another site, replayed here |
| Grants | `tx.wba_grant_agents` | none | origins or identifiers, exact match, that get `tx.wba_granted=1` when verified. Write an origin with no `:443` and no path. Keep it narrower than `agents.txt` |
| What a grant needs | `tx.wba_grant_require_components` | `@method @path` | a verified signature that leaves one out is not granted (one over `@authority` alone works for any method and path); `@target-uri` counts as `@path`; `none` turns it off |
| Minimum coverage | `tx.wba_require_components` | none | a signature that leaves out one of these (e.g. `@method @path`) is `unverified/insufficient-coverage`. Where query parameters decide anything, require the raw `@query` too: `@query-param` binds the URL Standard's reading of the query, which can differ from your application's (PHP, for example, turns `.` in a name into `_` and keeps the last value, so `?a_b=1&a.b=evil` verifies `a_b` as `1` while PHP reads `evil`); `@target-uri` counts as `@path`, as for a grant |
| Longest window | `tx.wba_max_window` | none; 86400 when `tx.wba_max_age` is 0 | seconds from `created` to `expires`; longer is `invalid/window-too-long`. Not needed while the maximum age is on: that already bounds how long a signature counts |
| Maximum age | `tx.wba_max_age` | 3600 | seconds a signature counts after its `created`, never past its `expires`; older is `invalid/too-old` (RFC 9421 3.2.1). `0` turns it off |
| Expiry grace | `tx.wba_expiry_grace` | 0 (strict) | seconds past `expires` still accepted, up to 60, for clocks a little behind the bot's |
| Unparsable headers | `tx.wba_malformed` | `ignore` | RFC 9651 4.2. Covers `Signature-Input` and `Signature`. `ignore` (default): an unparsable one counts as unsigned, `not-signed/unparsable-field` (Mastodon's `Signature` is one). `reject`: it is `invalid/malformed-headers` and gets 400. An unparsable `Signature-Agent` is different: in the usual form, `"signature-agent";key="sig1"`, it is `invalid/missing-component` under both settings and never a 400. Only a signature that covers the whole field gets `invalid/unparsable-agent`, or, with `reject`, `invalid/malformed-headers` and 400 |
| Replay accounting | `tx.wba_replay_dir` | off | counts each signed statement and nonce per host ([Replay accounting](#replay-accounting)) |
| Require a nonce | `tx.wba_require_nonce` | 0 | `1`: a signature without a `nonce` is `unverified/missing-nonce` |
| Strict field lines | `tx.wba_strict_field_lines` | 0 | `1`: a signature header sent as several lines, one of which does not parse alone, is unparsable (handled as `tx.wba_malformed` says); a covered digest header's line that does not parse is `invalid/malformed-digest` and 400 |
| On or off | `tx.web-bot-auth-plugin_enabled` | 1 (on) | `0`: the plugin does nothing, and every request reads `not-signed` ([Turning the plugin off](#turning-the-plugin-off)) |

A malformed setting value makes every signed request `unverified/bad-config`. So a typo shows in every log line instead of silently falling back to a default. Some limits are set in code, not in settings: published test keys are refused, and body digest sizes are capped. Their defaults are in `verify.lua`'s `DEFAULT_POLICY`. Override them in `modsecurity_entry.lua`'s `CONFIG.policy` ([DESIGN.md](DESIGN.md#body-digests) says what each costs).

### Turning the plugin off

There are two ways, and they do different things. Both go in a rule that runs before the plugin: in your settings file, or in another `*-config.conf`. The ids below (1000, 1001) stand for ids from your own range.

**The switch, `tx.web-bot-auth-plugin_enabled=0`, stops the plugin and keeps your rules running.** No Lua runs and no log line is written. One thing it does not undo: at paranoia level 4, CRS rule 920274 keeps skipping the three signature headers, because that exclusion is applied when the rules load, not per request. The plugin's variables still exist with their starting values, so every request reads `not-signed`, and your rules treat it as unsigned. Recipe A still refuses a bot on `/agents/`, even one with a valid signature. To turn the plugin off everywhere, uncomment the switch in [`web-bot-auth-config.conf`](web-bot-auth-config.conf). To turn it off for one site, set it from the `Host` header:

```
SecRule REQUEST_HEADERS:Host "@streq static.example.com" \
    "id:1000,phase:1,pass,nolog,t:none,setvar:tx.web-bot-auth-plugin_enabled=0"
```

**The tag, `ctl:ruleRemoveByTag=web-bot-auth`, removes every Web Bot Auth rule for the request.** Every rule in `wba.conf` and `recipes.conf` carries `tag:'web-bot-auth'`, so this removes the plugin and any recipes you copied. Nothing is verified and none of those recipes refuses anything. Use it where Web Bot Auth does not matter, such as static files:

```
SecRule REQUEST_FILENAME "@beginsWith /static/" \
    "id:1001,phase:1,pass,nolog,t:none,ctl:ruleRemoveByTag=web-bot-auth"
```

With the tag form no `tx.wba_*` variable is set, so a rule of your own without the tag that refuses anything not verified never matches there. Give such rules the tag too, or use the switch.

Neither way turns off the [bot list rules](#bot-lists-and-policies), which carry no `web-bot-auth` tag and keep applying your policies. With the plugin switched off, a bot that proves itself only by its signature is `claimed` there.

**`ctl:ruleRemoveById=9534100-9534199`, the CRS way to turn a plugin off, does not work here.** In ModSecurity v3 it removes only `SecRule` rules: the plugin's `SecAction` and `SecRuleScript` rules keep running the verifier, while your recipes are removed. Use the switch or the tag.

### Writing rules

Every Web Bot Auth rule needs four things:

- **Decide in phase 2.** ModSecurity checks a request in phases: phase 1 sees the headers, phase 2 the body. A signature that covers the body is settled in phase 2. In phase 1 it is still `unverified/digest-pending`, so a phase 1 rule would refuse a good body-signed request and could never grant it. Phase 2 needs request body access on, which is the CRS default.
- **Compare with `@streq`.** `@eq` compares integers: `"verified"` and `"invalid"` both become 0, so `@eq verified` matches everything.
- **Only `verified` may grant or exempt anything.** `invalid`, `unverified` and `not-signed` all mean "not verified". Grant only on `tx.wba_granted`. It is `1` only for a bot in `tx.wba_grant_agents` whose signature covered `@method` and `@path` (the default), so a copied signature cannot be reused on other paths. Test `tx.wba_agent` only to refuse (recipe B). Never grant on `tx.wba_status`: a URL-less signature is verified and names no bot.
- **Do not punish most failures.** Anyone can strip the signature headers and get the unsigned treatment, so refusing a failed signature mostly hurts honest bots whose clock is off or whose key just changed. The draft leaves each outcome to local policy (Appendix C.1). [Cloudflare](https://blog.cloudflare.com/verified-bots-with-cryptography/) "falls back to existing bot identification and mitigation mechanisms"; [AWS WAF Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html) labels the failure (`web_bot_auth:invalid`) for rules you write. Recipe F refuses the few failures that say the signature itself is forged or broken.

Try a refusing rule with `pass,log` instead of `deny` first. Each request it matches is then written to the audit log with the rule's message, and nothing is refused. Read the audit log for a while before you switch to `deny`.

### Rule examples

These are [`recipes.conf`](recipes.conf), exactly as the live suite runs them (`run_all.sh` fails if this page and that file differ). Copy what you need into your `*-after.conf` file. Change the paths, the User-Agent and the bot.

**A. Require a verified signature on paths reserved for bots, and ask for one.** The rule decodes, normalises and lowercases the path first, and matches `/agents` with or without a slash or a `;` parameter. So `/./agents/`, `//agents/`, `/%61gents/`, `/AGENTS/`, `/agents` and `/agents;jsessionid=x/` (which Java servers serve as `/agents/`) cannot slip past. nginx turns status 460 into 403 with an `Accept-Signature` header ([Asking for a signature](#asking-for-a-signature)). Without that nginx file, use `status:403`.

```
SecRule REQUEST_FILENAME "@rx ^/agents(?:[;/]|$)" \
    "id:9534130,phase:2,deny,status:460,log,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,\
    msg:'Web Bot Auth: a verified signature is required here',\
    tag:'web-bot-auth',ver:'web-bot-auth-plugin/0.1.0',severity:'NOTICE',chain"
    SecRule TX:wba_status "!@streq verified" "t:none"
```

**B. A request whose User-Agent claims to be a bot must be verified for that bot.** The User-Agent header proves nothing. This rule stops anything behind the WAF that trusts it from being fooled. Use it only for a bot that signs every request.

```
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)\bExampleBot/" \
    "id:9534131,phase:2,deny,status:403,log,t:none,\
    msg:'Web Bot Auth: User-Agent claims ExampleBot without its signature',\
    tag:'web-bot-auth',ver:'web-bot-auth-plugin/0.1.0',severity:'NOTICE',chain"
    SecRule TX:wba_agent "!@streq https://agent.example/.well-known/http-message-signatures-directory" "t:none"
```

**C. Exempt granted bots from your own bot management**, by marking the request for that rule to test. Never use a grant to skip CRS attack detection.

```
SecRule TX:wba_granted "@streq 1" \
    "id:9534132,phase:2,pass,nolog,t:none,\
    tag:'web-bot-auth',ver:'web-bot-auth-plugin/0.1.0',\
    setvar:tx.bot_management_exempt=1"
```

**D. A signed statement may be used once on recipe A's paths** (needs [replay accounting](#replay-accounting)). A second use gets 429 with a fresh `Accept-Signature`. As shipped it counts uses on `/agents` only. Widen the path to every one where `verified` or a grant changes anything, because a signature that does not cover `@path` can be replayed on any path ([Known limits](#known-limits)).

```
SecRule REQUEST_FILENAME "@rx ^/agents(?:[;/]|$)" \
    "id:9534133,phase:2,deny,status:461,log,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,\
    msg:'Web Bot Auth: signature used %{tx.wba_uses} times',\
    tag:'web-bot-auth',ver:'web-bot-auth-plugin/0.1.0',severity:'NOTICE',chain"
    SecRule TX:wba_uses "@gt 1" "t:none"
```

**E. A nonce may be used once anywhere** (needs replay accounting). A nonce is a random value a bot puts in a signature. RFC 9421 2.3 defines it as unique to its signature.

```
SecRule TX:wba_nonce_uses "@gt 1" \
    "id:9534134,phase:2,deny,status:461,log,t:none,\
    msg:'Web Bot Auth: nonce used %{tx.wba_nonce_uses} times',\
    tag:'web-bot-auth',ver:'web-bot-auth-plugin/0.1.0',severity:'NOTICE'"
```

**F. Refuse a signature that cannot be genuine.** It refuses four reasons:
- `foreign-authority`: a signature made for another site, replayed here. Its Host is not one of `tx.wba_site_names`.
- `bad-signature`: not a valid signature for the key it names. Either no allowed key could accept those bytes, or the check failed for a key you hold.
- `digest-mismatch`: the body is not the one signed.
- `test-key`: a published key that anyone can sign with.

A proxy that rewrites a covered header also causes `bad-signature`, for an honest bot. So run this rule as `pass,log` first. Stripping the headers still gets the unsigned treatment, so this rule refuses only forged and broken signatures. Recipe A is the gate.

```
SecRule TX:wba_reason "@rx ^(?:foreign-authority|bad-signature|digest-mismatch|test-key)$" \
    "id:9534135,phase:2,deny,status:403,log,t:none,\
    msg:'Web Bot Auth: a signature that cannot be genuine (%{tx.wba_reason})',\
    tag:'web-bot-auth',ver:'web-bot-auth-plugin/0.1.0',severity:'WARNING',chain"
    SecRule TX:wba_status "@streq invalid" "t:none"
```

### Asking for a signature

Draft 5.3 lets a site ask a client to sign. The site answers `403` with an `Accept-Signature` header. It asks again with `429` when a signature or nonce has been used too often. ModSecurity cannot add a response header. So recipe A denies with status 460, and recipes D and E with 461. [`nginx/web-bot-auth-accept-signature.conf`](nginx/web-bot-auth-accept-signature.conf) (the image installs it) turns them into:

```
HTTP/1.1 403 Forbidden
Accept-Signature: sig1=("@authority" "@method" "@path" "signature-agent";key="sig1");created;expires;nonce="5b7f2c0e9d4a43b1a6f0c2d8e9b14a7c";tag="web-bot-auth"
Cache-Control: no-store
```

The client sees only 403 or 429. nginx's error log records the 460 or 461 (`Access denied with code 460`). The audit log records the status the client was sent, 403 or 429, with the rule that refused. The nonce is nginx's `$request_id`, new on every response. **The verifier does not check that a returned nonce is one it issued.** ModSecurity-nginx gives the rules no way to see it. Storing every nonce handed to unsigned clients would also let them fill the store. With replay accounting on, a nonce seen before is refused (recipe E).

The header asks for `@method` and `@path` because a grant needs them by default (`tx.wba_grant_require_components`). A client that answers must sign exactly the components asked for (RFC 9421 5.2). So if you set `tx.wba_require_components`, add those components to the header in the nginx file too. [DESIGN.md](DESIGN.md#asking-for-a-signature-in-detail) has the details.

### Replay accounting

A replay is a captured signed request, sent again. A signature can be replayed until it expires or is an hour old (`tx.wba_max_age`), whichever comes first (draft 6.9). It can be replayed to any path it does not cover. Covering `@method @path` limits that. Replay accounting stops it on one host. The plugin counts each signed statement (what the signature covers, with its key and times) and each nonce. Replay accounting is off by default. To turn it on:

1. Give `/var/lib/wba/replay` a filesystem of its own. It must be writable by the nginx workers (uid 101 in the image) and have an inode budget, a cap on the number of files. Then filling it cannot fill anything else. Use one of these:
   - **a host directory** (recommended; Linux), so the sweeper can run on the host. Mount a tmpfs there, `mount -t tmpfs -o size=64m,nr_inodes=200000,uid=101,gid=101,mode=0700 tmpfs /srv/wba/replay`, and add `-v /srv/wba/replay:/var/lib/wba/replay` to `finch run`;
   - or **a tmpfs inside the container**: add `--tmpfs /var/lib/wba/replay:rw,size=64m,nr_inodes=200000,uid=101,gid=101,mode=0700` to `finch run`.
2. Set it in your settings file: `setvar:tx.wba_replay_dir=/var/lib/wba/replay` (the commented-out rule 9534014).
3. Add recipes D and E.
4. Sweep the directory on the key sync timer, as root or uid 101. The sweep removes files that can no longer matter:
   - **host directory:** `bun wba-keysync/sweep.ts --dir /srv/wba/replay --max-window 3600`. Give `--max-window` your `tx.wba_max_age` (3600 by default), or your `tx.wba_max_window` if you set a smaller one. With `tx.wba_max_age` off, give it the window (a day, 86400, unless you set `tx.wba_max_window`). If several `server` blocks share the directory, give it the largest. It removes a statement's counter five minutes after the signature's own expiry, and any counter once it has gone unused for the window plus five minutes, and touches nothing else.
   - **tmpfs in the container:** `finch exec waf find /var/lib/wba/replay -type f -mmin +65 -delete` (the image has no Bun). This removes files untouched for the maximum age plus five minutes. With `tx.wba_max_age` off, use the window instead (`-mmin +1445` for 24 hours).

What you get, and the limits:

- **It counts the signed statement, not the signature bytes**, so a second valid ECDSA signature over the same request counts as the same use. Every verified signature on a request is counted ([DESIGN.md](DESIGN.md#sessions-and-replay) says why, and why ModSecurity's own persistent collections cannot count).
- **Exact under load.** When 20 requests use one signature at the same moment, exactly one gets through (a live test case). It is the first copy to arrive that passes.
- **Per host.** Behind a load balancer, a signature can be used once on each host. Pin a bot to one host, or treat the limit as per host.
- **Fails closed, and sizing.** If the directory is not writable or is full, every request that would have verified is `unverified/replay-unavailable`, and the debug log ([Other logs](#other-logs)) says `[wba] replay accounting unavailable`. There is one file per new statement and one per new nonce, each kept until it has gone unused for `tx.wba_max_age` (plus five minutes), or sooner once its signature expires: about 2 × verified requests a second × 3600 files by default. `nr_inodes=200000` holds about 28 verified requests a second. Lower `tx.wba_max_age` before you raise the budget. Only a key you hold can add files.

### Bot lists and policies

Most bots do not sign yet, but their operators publish the addresses they send from. [`wba-keysync/lists.ts`](../../wba-keysync/lists.ts) turns those lists into rules. Each request whose User-Agent names a bot is then checked against that bot's own list. A bot verified by its signature is named the same way. The rules are plain SecRules (no Lua), and the WAF compiles the lists when it starts, so a request never waits on a fetch or a DNS lookup.

```bash
bun wba-keysync/lists.ts bots.yaml --out /srv/wba/bots    # from cron, after validate.ts passes
```

For such a request the rules set:

| Variable | Value |
|---|---|
| `tx.bot_name` | the bot's name in `bots.yaml` |
| `tx.bot_status` | `verified`, or `claimed`: the User-Agent names the bot and nothing proves it |
| `tx.bot_reason` | `ip-list` or `signature` when verified; `not-in-list` (the address is not on the bot's list) or `no-list` (there is no list for this bot) when claimed |
| `tx.bot_list_version` | the version of the list that was checked, or `none`: the operator's `creationTime` and the first 8 hex digits of a sha-256 of the ranges, such as `2026-09-22T02:00:07.000000#09686b94` |

For example, `User-Agent: ... GPTBot/1.3` from 20.171.206.10, which is on OpenAI's list, gets `gptbot`, `verified`, `ip-list`. The same User-Agent from 203.0.113.9 gets `gptbot`, `claimed`, `not-in-list`. A request whose User-Agent names no bot gets nothing: a list is only checked for the bot a request claims. The address checked is the one ModSecurity sees, so behind a load balancer or CDN set up the real-IP file in [step 5](#5-tls-and-load-balancers) first.

**Policies.** Add `policy` to a bot's entry in `bots.yaml`:
- `allow`: the bot is treated as usual, and a request that claims it from outside its list is refused as an impostor. Nothing is exempted from CRS or your other rules.
- `deny`: refused, whether verified or only claimed.
- `log`: written to the log, never refused.

`policy_mode: log` at the top of `bots.yaml` (the default) only logs what would be refused, so you can watch first; `policy_mode: enforce` refuses with 403. `claim_only: true` marks a User-Agent token that others send too: Claude Code's web fetch sends `Claude-User` from the user's own address, so the seed list marks `claude-user` this way. For such a bot a claim from outside its list is never refused, and `deny` applies only when the request is verified. Every policy match is logged with the tag `web-bot-auth-bots`, the bot's status and reason, and the list version.

**Install.** lists.ts writes into the `--out` directory: `web-bot-auth-bots-before.conf` (the rules) and `web-bot-auth-bots/` (the data files the rules name, relative to themselves), plus `versions.json`, `status.json` and `ids.json`. On your own nginx, give the plugins directory as `--out`. In a container, mount the directory and add a one-line plugin file that includes the rules:

```
# plugins/web-bot-auth-bots-before.conf, with -v /srv/wba/bots:/etc/modsecurity.d/bots:ro
Include /etc/modsecurity.d/bots/web-bot-auth-bots-before.conf
```

Run lists.ts once before you add that line: nginx does not start while the file it names is missing.

Keep the name `web-bot-auth-bots-before.conf`: CRS loads it right after the plugin's own `web-bot-auth-before.conf` and before every `*-after.conf`, so your rules see a bot that signed as `verified`, never `claimed`.

**Updates and failures.** The WAF reads the files when it starts or reloads. `--check 'nginx -t' --reload 'nginx -s reload'` checks the new files and then reloads; with the container, `--check 'finch exec waf nginx -t' --reload 'finch exec waf nginx -s reload'` (or `docker exec`). If the check or the reload fails, every file goes back to what it was, so the next run tries again.

A list keeps its previous version when it cannot be fetched, is empty, holds a range wider than an IPv4 /8 or IPv6 /16, or touches private, loopback, link-local or multicast space; `status.json` says which and why. A range inside a wider one on the same list is left out, because ModSecurity's address lookup can miss addresses when ranges nest. A bot whose list has never been fetched gets `no-list`, which no policy refuses as an impostor. `versions.json` records each list's version, when it was fetched and when it last changed, so you can tell later which list a decision used. Exit codes: 0 every list fetched; 2 the rules were written but a list kept its previous version or has none; 1 nothing changed. Rule ids are 9534150 and four per bot from 9534200; `ids.json` keeps each bot's ids the same between runs.

**robots.txt.** `bun wba-keysync/robots.ts bots.yaml` prints a suggested robots.txt that asks every `deny` bot not to crawl. It only asks; the rules refuse. Merge it into your own as you see fit.

[`lua/tests/live/bot-lists.sh`](../tests/live/bot-lists.sh) tests all of this in the image, a list server that breaks included.

### Check your deployment against the latest upstream

Bots sign with libraries that keep changing, and so does the draft. You run this check on your own schedule: weekly, and before every upgrade. [`lua/tests/interop/interop.sh`](../tests/interop/interop.sh) does three things:
- it signs requests with the **newest** release of Cloudflare's reference signer (npm `web-bot-auth`) and with a copy of Stytch's example recipe, as reviewed (the run says if that example has changed upstream since);
- it sends them through your real edge and reads each result from your WAF's log;
- it runs the draft's newest test vectors through this release's verifier.

It needs Bun and `curl`. The draft vectors also need `lua` and `openssl`, and are skipped without them. Every run prints the upstream versions it used. Exit 0 means every case came out as expected. Each run installs the newest `web-bot-auth` from npm on the host that runs it, so run it on a host with nothing sensitive on it.

1. **Once:** `lua/tests/interop/interop.sh init /etc/wba-interop` creates your interop key (`/etc/wba-interop` is an example; any directory works). The private key stays on that host.
2. **Publish the public half:**
   - Serve `/etc/wba-interop/interop.jwks.json` from an https URL you control.
   - Add that URL to `agents.txt`, for example `https://www.example.com/.well-known/wba-interop.jwks.json type=jwks_uri`. Key sync picks it up.
   - **Never put it in `tx.wba_grant_agents`.** The interop agent must unlock nothing, so a leaked key is only a nuisance. To change the key, run `init` again and replace the file.
3. **Run it** from cron:

```bash
TARGET=https://www.example.com \
INTEROP_KEY=/etc/wba-interop/interop-key.json \
INTEROP_AGENT=https://www.example.com/.well-known/wba-interop.jwks.json \
LOGS='finch logs --since 2m waf' \
lua/tests/interop/interop.sh
```

`LOGS` is any command that prints your WAF's log for the last few minutes. For example: `docker logs --since 2m waf`, `kubectl logs deploy/waf --since=2m`, `journalctl -u nginx --since -2min -o cat` or `tail -n 5000 /var/log/nginx/wba.log`.

The run sends 7 requests to `/.well-known/wba-interop/<run>/…`: genuine ones, which must verify, and a tampered one, an expired one and one signed with an unpublished key, which must not. Your rules may refuse some of them: the check reads only the logged result.

You can serve the key set at a site's well-known directory instead, and list it as that origin. Then two more cases run: the legacy `Signature-Agent` form and Stytch's recipe.

A failure names the case and the upstream version. Read it, then upgrade or hold.

## Logs

### What is written, and when

Every request with a Web Bot Auth signature writes one line of JSON in phase 5, after the response. So the line records the final outcome however the request ended: refused by CRS, refused by your rules, or passed. A request whose signature header could not be parsed and was ignored (`not-signed/unparsable-field`) also writes one. Unsigned requests write nothing, and so does a request that carries only other kinds of signature (`not-signed/no-wba-signature`). The line goes to `/dev/stdout`, which is the container's log:

```bash
finch logs waf 2>&1 | grep -F '{"event":"web-bot-auth"'
```

A verified request (shown wrapped; each is one line):

```json
{"event":"web-bot-auth","time":1790922501,"unique_id":"179092250669.094052","client_ip":"192.0.2.7",
 "method":"GET","uri":"/agents/x","host":"example.com","status":"verified","reason":"","agent":"https://bot.example/.well-known/http-message-signatures-directory",
 "agent_proof":"valid","keyid":"eTnUpXZYhQFajMO2QSWeganNyW1dkGV58okMu-2NJLY","label":"sig1","created":1790922496,"expires":1790922556,
 "granted":false,"sighash":"<64 hex>","uses":1,"nonce_uses":null,"covered":"@authority signature-agent"}
```

A failed one. Every field taken from the signature is `null`, because nothing in it can be trusted:

```json
{"event":"web-bot-auth","time":1790922507,"unique_id":"179092250734.118020","client_ip":"198.51.100.4",
 "method":"GET","uri":"/agents/x","host":"example.com","status":"invalid","reason":"bad-signature","agent":null,"agent_proof":null,
 "keyid":null,"label":null,"created":null,"expires":null,"granted":false,"sighash":null,"uses":null,"nonce_uses":null,"covered":null}
```

### Fields

| Field | Value | When `null` |
|---|---|---|
| `event` | always `web-bot-auth` | never |
| `time` | Unix seconds the line was written | never |
| `unique_id` | ModSecurity's transaction id: the same request in the audit log | never |
| `client_ip`, `method`, `uri` | as the access log has them; `uri` is raw, cut to 1024 bytes | never |
| `host` | the request's `Host` header, cut to 256 bytes: the site the signature was checked against. With a full URL in the request line, nginx serves the request-line host, which ModSecurity never sees | never |
| `status`, `reason` | the outcome ([Outcomes and reasons](#outcomes-and-reasons)) | never |
| `agent` | the bot the request is attributed to | not verified, or URL-less |
| `agent_proof` | `valid`, `invalid`, `expired`, `none` | not verified, or URL-less |
| `keyid`, `label`, `created`, `expires` | the verified signature's key and window | not verified |
| `granted` | `true` when `tx.wba_granted` is `1` | never (`false`) |
| `sighash` | SHA-256 of the signature's bytes | not verified |
| `uses`, `nonce_uses` | this host's counts | not verified, accounting off, or no nonce |
| `covered` | what the signature signed | not verified |

Every value is JSON-escaped, and every field is capped after escaping. So a line is always one valid JSON object under 4096 bytes, and a pipe never mixes it with another worker's line. **The log never holds the signature itself.** Until it expires, anyone who has the signature can use it, so `sighash` identifies it instead.

### Reading them

These examples need `jq`:

```bash
L() { finch logs waf 2>&1 | grep -F '{"event":"web-bot-auth"'; }
L | jq -r '.status + "/" + .reason' | sort | uniq -c | sort -rn           # outcomes
L | jq -r 'select(.status=="verified") | .agent' | sort | uniq -c       # who signs
L | jq -c 'select((.uses // 0) > 1 or (.nonce_uses // 0) > 1)'          # replays on this host
L | jq -r 'select(.sighash) | .sighash' | sort | uniq -d                  # a signature seen twice
```

The same `sighash` twice is a replay, or, for the deterministic Ed25519 and RSA PKCS #1 v1.5, possibly an identical retry. An ECDSA replay can arrive with a new `sighash`; `uses` still counts it ([Replay accounting](#replay-accounting)). Across hosts, compare `sighash` in your log search system (SIEM).

**Sessions belong in your SIEM.** Group verified lines by `agent`, then `keyid`, with an idle gap. A key stands for a bot operator, never a person (draft 7.2).

### Other logs

- **The audit log holds raw signatures.** Its request headers (part B) carry each `Signature`, as they carry any `Authorization` or `Cookie`: treat it as sensitive for at least your longest signature window. With the CRS image's defaults, it gets a request whose final status is a 5xx or a 4xx other than 404, or that a `log` rule matched; a signed request answered with 200 is usually not there.
- **Finding a bot you do not know yet.** The JSON line for `unverified/unknown-agent` does not name the bot, since nothing from a signature that did not verify is trusted. Add this rule to your `*-after.conf` for a while:

  ```
  SecRule TX:wba_reason "@streq unknown-agent" \
      "id:9534139,phase:5,pass,log,t:none,tag:'web-bot-auth',ver:'web-bot-auth-plugin/0.1.0',severity:'NOTICE',msg:'Web Bot Auth: unknown agent'"
  ```

  It refuses nothing. Each such request gets an audit entry whose headers show its `Signature-Agent`, for example `sig1="https://newbot.example"`, and its raw `Signature`, so remove the rule once you know which bots they are.
- **The debug log says why.** Set `MODSEC_DEBUG_LOG` to a file and `MODSEC_DEBUG_LOGLEVEL` to 2 or more (the image's defaults are `/dev/null` and 0). It shows `[wba] bad configuration: ...` for a rejected setting, `[wba] log line not written: ...` (for example `No space left on device`), and `Failed to execute lua script: ...` with the Lua error when the plugin's Lua could not start.
- **nginx's error log shows refusals only**, at `error` level, with the rule's id and message and the request's `unique_id` (the same as in the JSON line and the audit log): `ModSecurity: Access denied with code 460 (phase 2). ... [id "9534130"] ...`. A `pass,log` rule is written at `info`, below the CRS image's `warn`, so its message goes only to the audit log. Lines appear here once you switch a rule to `deny`, or your bots file to `policy_mode: enforce`.
- **Why a JSON line of its own:** the error log shows only refusals, and the audit log only some requests; the JSON line covers every signed request. To turn it off, remove rule 9534121 with `SecRuleRemoveById` in your `*-after.conf`.

## Troubleshooting

| You see | Likely cause | Do |
|---|---|---|
| `unverified/no-site-names` | `tx.wba_site_names` is not set | list your site's host names ([settings](#controls-and-defaults)) |
| `invalid/foreign-authority` | the request's Host is not one of your site names: a signature made for another site, or a name you forgot to list | add the name if it is yours |
| `unverified/unknown-agent` | the request names a bot that is not in your key store; the log line does not say which | find it with the audit rule in [Other logs](#other-logs); then add it to your bots file and run `agents.ts` (or add it to `agents.txt`), then key sync |
| `unverified/unknown-key` | the bot is listed, the key is not: it changed, or key sync has not run since | check the timer, and key sync's exit code and output |
| `unverified/key-not-current` | the bot's directory dates the key outside now (`nbf`, `exp`) | nothing on your side |
| `unverified/bad-agent-url`, `unsupported-agent-type` | the bot's `Signature-Agent` is not a valid URL of a known type, or names a key directory by more than its origin (the draft says to ignore such a member) | the bot's to fix ([FOR-BOT-OPERATORS.md](FOR-BOT-OPERATORS.md)) |
| `invalid/expired`, `not-yet-valid`, `too-old` | an old request replayed, or a clock off here or at the bot (60 s allowed ahead; none past `expires` unless `tx.wba_expiry_grace`) | check NTP on the WAF |
| `invalid/window-too-long` | the signature's window is longer than `tx.wba_max_window`, or longer than a day with `tx.wba_max_age` off | raise or remove the cap, turn the maximum age back on, or ask the bot for shorter windows |
| `invalid/bad-signature` | forged, or something between the bot and you changed a part it signed (a CDN rewriting `Host` or the path) | check what sits in front of nginx |
| `unverified/digest-pending` at the end | request body access is off, so phase 2 never ran | turn it on for those paths |
| `unverified/body-too-large` | a SHA-256 body over 128 KiB, or a coded body over the decode budget | ask the bot for `sha-512`, or raise the limit ([DESIGN.md](DESIGN.md#body-digests)) |
| `unverified/body-incomplete` | the body was cut at `SecRequestBodyLimit` | raise the limit for those paths |
| `unverified/insufficient-coverage`, `missing-nonce` | your settings ask for more than the signature has | ask the bot, or relax the setting for that path |
| `unverified/bad-config` | a setting is malformed | the debug log names it |
| `unverified/keystore-unavailable` | the store is missing or unreadable, its first line is not a version header such as `# wba-keys v2`, or a line for this bot's keys is malformed (a bad line for another bot does not count) | mount the directory, not the file; read key sync's output |
| `unverified/replay-unavailable` | the replay directory is not writable by uid 101, or is full | check the mount's owner and its inode budget |
| `unverified/engine-error` | lua-openssl or another module did not load, or has a syntax error (nginx checks only the two `SecRuleScript` files when it starts) | the debug log at level 2 ([Other logs](#other-logs)) shows the Lua error. Rebuild the image; on your own nginx, check Lua's C path and the module files |
| `400` for a signed request | a covered body digest header that cannot be parsed (`invalid/malformed-digest`), or, with `tx.wba_malformed=reject`, an unparsable signature header | the client's to fix |
| clients get `460` or `461` | the Accept-Signature nginx file is not included | include it, or use `status:403` and `status:429` |
| no log lines | unsigned traffic writes none; for signed traffic, rule 9534121 was removed or `CONFIG.path` is not writable | check with the [Quick start](#quick-start) request |
| CRS 4.30.0 refuses ordinary paths such as `/recipes/chef-salad` with rule 932260 | a CRS 4.30.0 false positive ([coreruleset#4840](https://github.com/coreruleset/coreruleset/issues/4840)): the rule now reads the URL path; fixed by [#4842](https://github.com/coreruleset/coreruleset/pull/4842), not yet released | add `SecRuleUpdateTargetById 932260 "!REQUEST_FILENAME"` (the change #4842 makes) to your own `*-after.conf`; remove it once a CRS release has the fix |

## Outcomes and reasons

| Status | Reasons | Meaning |
|---|---|---|
| `verified` | (empty), `url-less` | As defined in [What every request gets](#what-every-request-gets). |
| `invalid` | `foreign-authority`, `bad-signature`, `expired`, `too-old`, `not-yet-valid`, `window-too-long`, `missing-param`, `bad-param`, `bad-keyid`, `unsupported-alg`, `alg-mismatch`, `alg-undetermined`, `authority-not-covered`, `agent-not-covered`, `ambiguous-agent`, `agent-not-https`, `missing-component`, `unsupported-component`, `duplicate-component`, `bad-component-value`, `malformed-headers`, `unparsable-agent`, `orphan-label`, `test-key`, `digest-mismatch`, `malformed-digest`, `bad-content-coding` | A check failed. `malformed-headers` and `malformed-digest` also get 400 (rule 9534107). With the default `tx.wba_malformed=ignore`, an unparsable signature header gives `not-signed/unparsable-field` or `invalid/unparsable-agent` instead of `malformed-headers`. |
| `unverified` | `no-site-names`, `unknown-agent`, `unknown-key`, `key-not-current`, `bad-agent-url`, `unsupported-agent-type`, `agent-absent`, `digest-pending`, `digest-algorithm-unsupported`, `digest-coding-unsupported`, `digest-partial`, `body-incomplete`, `body-too-large`, `insufficient-coverage`, `too-many-signatures`, `missing-nonce`, `bad-config`, `keystore-unavailable`, `replay-unavailable`, `crypto-error`, `engine-error`, `internal-error` | Could not decide: key not held, agent URL ignored, body not (yet) checkable, a setting not met, or an infrastructure fault. Never treated as success. `too-many-signatures` happens only if you set a cap, `CONFIG.policy.max_signatures` in `modsecurity_entry.lua`: there is none by default. |
| `not-signed` | `no-signature`, `no-wba-signature`, `unparsable-field` | No Web Bot Auth signature on the request (by default, an unparsable signature header counts as none). |

A request with several signatures gets the best outcome among them. [DESIGN.md](DESIGN.md#several-signatures-on-one-request) has the ranking.

## For bot operators

What a bot has to do to be `verified` here, from publishing its keys to signing each request, is on its own page: [FOR-BOT-OPERATORS.md](FOR-BOT-OPERATORS.md).

## CRS paranoia levels

The plugin works at every CRS paranoia level (PL). [`lua/tests/live/paranoia.sh`](../tests/live/paranoia.sh) sends every signer shape (each algorithm, `jwks_uri` and `cimd` agents, a proof, URL-less, an ActivityPub header) over HTTP/1.1 and HTTP/2 at PL 1 to 4, on the image the [Dockerfile](Dockerfile) pins. Each verifies and passes every CRS rule, with two exceptions that need an exclusion of your own ([evidence](evidence/crs-paranoia-levels.md)).

| PL | Signed requests |
|---|---|
| 1 | Pass, except the 941120 false positive below. |
| 2 | Pass, except the 941120 false positive (level 1). |
| 3 | Pass, except the 941120 false positive (level 1) and a percent-encoded `Signature-Agent` URL (rule 920272, below). |
| 4 | Pass, except the 941120 false positive (level 1) and the level 3 exception. `wba.conf` exempts `Signature-Input`, `Signature` and `Signature-Agent` from rule 920274 only, whose strict character set would refuse every signed request (`(`, `)`, `@`); every other CRS check on them still runs. |

**Rule 941120, at every level.** This XSS rule reads every request header and takes a digit, `/` or `+` followed by `on`, letters and `=` for an HTML event handler such as `onload=`. About 1 in 2,000 random 32-byte values in padded base64 (ending in one `=`) match, and CRS answers 403. Signed requests carry such values in three headers; if it hits you, exclude the one that carries yours from this rule: `Content-Digest` or `Repr-Digest` for a sha-256 body digest (any client's, signed or not), `Signature-Input` for a 32-byte nonce, `Signature` for an RSA-4096 signature. A sha-512 digest, a 64-byte nonce, and Ed25519, ECDSA, RSA-2048 and RSA-3072 signatures end in `==` or no padding and cannot match. CRS tracks this class in issue [#1867](https://github.com/coreruleset/coreruleset/issues/1867). For example, `Content-Digest: sha-256=:hmsi6PXNOrqyV/Ur95FJQD1JwJVcrTr/OnzWOarQXAM=:` matches on `/OnzWOarQXAM=:`; in your own `*-after.conf`:

```
SecRuleUpdateTargetById 941120 "!REQUEST_HEADERS:/^content-digest$/"
```

**Rule 920272, at levels 3 and 4.** It decodes every `%XX` in every header, then allows only printable ASCII other than `%`. A `jwks_uri` or `cimd` URL with a non-ASCII character (`https://bot.example/café/keys.json`, sent as `caf%C3%A9`) or a literal `%` (`%25`) is verified by the plugin and then refused by CRS. A key directory member is an origin and can hold neither. If a bot you accept uses one, exclude the header from this one rule:

```
SecRuleUpdateTargetById 920272 "!REQUEST_HEADERS:/^signature-agent$/"
```

`paranoia.sh` pins both exclusions and the PL 4 exemption both ways (the same value under any other header name is still refused), so it fails when a CRS release changes any of them.

## Known limits

What this release does not do, or does in a way you should know before you rely on it:

- **Rule IDs are not yet reserved.** IDs 9534000-9534999 are free in the CRS plugin registry but not yet reserved; check for overlap before loading another third-party plugin.
- **Your key store can be probed.** Recipe F refuses `bad-signature`, which needs a key you hold, but passes `unknown-key`, so anyone can learn which bots you list. Their key directories are public: this reveals your list of bots, not a secret.
- **Shared platform keys.** Some services sign every customer's traffic with one key (for example AWS AgentCore Browser and Cloudflare Browser Run). `verified` then names the platform and cannot tell its customers apart.
- **Recipes decide in phase 2**, which needs request body access on, the CRS default ([Writing rules](#writing-rules)).
- **Site names are one list for the whole plugin**, compared with the `Host` header, not the port or the nginx `server` block. If one nginx serves different apps under one name on different ports, set `tx.wba_site_names`, port included, per `server` block, and remove any `X-Forwarded-Host` a client sent before the request reaches the backend.
- **Debian images only.** The Alpine CRS images do not work ([What you need](#what-you-need)).
- **Plain HTTP is not refused.** ModSecurity cannot see whether the client used TLS, so a signed request over plain HTTP is verified like any other. Serve signed traffic over HTTPS ([step 5](#5-tls-and-load-balancers)).
- **A full URL in the request line.** nginx serves the host written in the request line, but ModSecurity sees only the `Host` header. So `GET http://other.example/ HTTP/1.1` sent with `Host: example.com` reaches ModSecurity as `/` on example.com: a signature made for example.com verifies, while nginx serves the request as other.example. It matters whenever a request-line host other than the `Host` header can reach an application: several server blocks, a wildcard or default block, or `proxy_set_header Host $host` (nginx takes `$host` from the request line first) in front of an application that serves several names. The catch-all server in [step 5](#5-tls-and-load-balancers) answers 421 when the request-line host is a name this nginx does not serve; add it in every deployment. For a name this nginx does serve, [Replay accounting](#replay-accounting) counts the copy together with the bot's own request, but only a recipe refuses it, and only the second copy to arrive. So turn it on (`tx.wba_replay_dir`, rule 9534014) and do one of two things:
  - widen recipe D (rule 9534133), which as shipped covers `/agents` only, to every path where `verified` or a grant matters, and set `tx.wba_require_components=@method @path` (rule 9534011);
  - or require a nonce (`tx.wba_require_nonce=1`, rule 9534015) and use recipe E (rule 9534134).

  A full URL with no `/` after the host (`GET http://example.com?evil=1`) gives ModSecurity no path and no query, so a signature that covers `@path` or `@query` is `invalid/missing-component` ([DESIGN.md](DESIGN.md#what-modsecurity-cannot-see)).
- **Replay accounting counts per host.** Several WAFs behind one load balancer do not share their counts ([Replay accounting](#replay-accounting)).
- **Some compressed bodies cannot be checked.** An `Unencoded-Digest` over a `br`, `zstd` or `compress` body is `unverified/digest-coding-unsupported`; `Content-Digest`, which covers the bytes as sent, works for every coding.
- **An unreadable covered digest header gets 400** ([Controls and defaults](#controls-and-defaults)).
- **A returned `Accept-Signature` nonce is not checked** against the ones nginx handed out ([Asking for a signature](#asking-for-a-signature)).
- **DNS rebinding at key sync.** A key URL's name that changes its DNS answer between key sync's address check and its fetch is not caught; TLS for the bot's name still has to succeed. Run key sync on a host that cannot reach anything sensitive ([DESIGN.md](DESIGN.md#wba-keysync-in-detail)).
- **Reverse DNS is not checked**, and an IP list is checked only for the bot a request claims ([Bot lists and policies](#bot-lists-and-policies)).
- **Bun only** for `validate.ts`, `agents.ts`, `report.ts`, `lists.ts`, `robots.ts` and `interop.sh`; the other tools also run on Node 26 ([What you need](#what-you-need)).
- **CRS 4.30.0** refuses some ordinary paths with rule 932260, a CRS bug with a workaround ([Troubleshooting](#troubleshooting)).

## Running the tests

```bash
JOBS=2 lua/tests/run_all.sh       # every suite and planted bug, a test for every documented reason, key sync on Bun and Node
lua/tests/run_all.sh --live       # plus the image: live suite, Quick start, registry, real IP, bot lists, GETTING-STARTED.md on Debian 13 (needs network), go-ftw
bash lua/tests/live/paranoia.sh   # CRS paranoia levels 1 to 4
```

Add `DOCKER=docker` for Docker. A missing tool is reported as SKIP, never as a pass. CI runs the same suites; [TESTING.md](TESTING.md#run-the-tests) says what each needs and what is proven.
