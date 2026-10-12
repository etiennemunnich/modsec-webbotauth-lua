# Web Bot Auth for ModSecurity

> **Preview: do not use this in production yet.** Test it on a test site first. Rule IDs, settings and log fields may still change before the first release ([Known limits](#known-limits)). Licensed under the Apache License 2.0.

This project tells your WAF which bots a request really comes from. It runs inside ModSecurity v3 with the OWASP Core Rule Set (CRS), and has two parts:

- **Signatures ([Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/)).** A bot signs each request with a private key and publishes the matching public key on its own site. This plugin checks the signature. It is Lua, run by ModSecurity.
- **Bot lists.** Most bots do not sign yet, but their operators publish the addresses they send from. [Bot lists](#bot-lists-and-policies) check a request that names a bot in its User-Agent against that bot's list. They are plain ModSecurity rules, written by a script.

**How it works.** Ahead of time, a cron job downloads the signing bots' public keys and the bots' IP lists. Then, for each request:

1. **Is it signed?** The signature is checked with that bot's key: `verified`, or not.
2. **Does the User-Agent name a bot?** The address is checked against that bot's list: on it, `verified`; off it, only `claimed`.
3. **What did you decide?** Your rules, or a `policy` per bot, let it through, refuse it or log it.

For example: OpenAI's ChatGPT agent, signed, is `verified`. "GPTBot" from one of OpenAI's addresses is `verified`. "GPTBot" from anywhere else is only `claimed`, and `policy: allow` refuses it as a fake. A normal browser gets nothing, and CRS treats it as usual.

Nothing is refused unless you say so: the plugin and the lists set ModSecurity variables, write a log line for every signed request, and leave the decisions to your rules. [`recipes.conf`](recipes.conf) has six example rules.

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
| Make your bot verifiable | [For bot operators](#for-bot-operators) |
| Know how it works, and why | [DESIGN.md](DESIGN.md) |
| See what is proven | [TESTING.md](TESTING.md), [CONFORMANCE.md](CONFORMANCE.md) |

## Quick start

Run these steps from the repository root. You need [Finch](https://github.com/runfinch/finch) or Docker, and [Bun](https://bun.sh) or Node 26. The commands use `finch` and `bun`.

- With Docker, type `docker` in place of `finch`.
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
- TLS for signed traffic (draft 6.1). The image serves TLS on port 8443.
- Bun 1.3 or Node 26 wherever the `wba-keysync` tools run. Node 26 runs `cli.ts` (key sync), `sign.ts` and `sweep.ts`. `validate.ts`, `agents.ts`, `report.ts`, `lists.ts`, `robots.ts` and [`lua/tests/interop/interop.sh`](../tests/interop/interop.sh) need Bun.
- A clock kept in sync by NTP, on the WAF and on the key sync host. A signature may be dated up to 60 seconds ahead of your clock. It expires exactly at its `expires` time, unless you set a grace period. It counts for at most an hour after it was made.

### The files

Every file you set up or may change, in the order you meet them. "Plugins" is the CRS plugins directory, `/etc/modsecurity.d/owasp-crs/plugins/` in the image.

| File | What it does | Who writes it | Where it goes |
|---|---|---|---|
| `bots.yaml` | Your list of bots: each one's key source (`wba`), IP lists, reverse DNS and User-Agent tokens, and your policy for it ([Bot lists and policies](#bot-lists-and-policies)). Start from [`bots.seed.yaml`](../../wba-keysync/bots.seed.yaml), whose top explains every field | you | anywhere on the key sync host |
| `agents.txt` | The key sources key sync may fetch, one per line ([step 2](#2-list-the-bots-you-recognise)) | `agents.ts`, from `bots.yaml`; or you, by hand | the key sync host, given with `--origins` |
| `wba-keys.tsv` | The key store: every public key key sync accepted. The plugin reads it for each signed request | key sync | its directory, mounted at `/etc/modsecurity.d/wba/keys/` |
| `wba-keys.tsv.cache.json`, `wba-keys.tsv.history` | Key sync's HTTP cache, and a record of every key added or removed, for attributing a signature later | key sync | next to the key store |
| `web-bot-auth-bots-before.conf`, `web-bot-auth-bots/`, `versions.json`, `status.json`, `ids.json` | The bot list rules and their data, each list's version, what the last run did, and each bot's rule ids ([Bot lists and policies](#bot-lists-and-policies)) | `lists.ts`, from `bots.yaml` | the plugins directory, or mounted and included from it |
| [`web-bot-auth-config.conf`](web-bot-auth-config.conf) | The settings: your site names (required), grants and limits ([Controls and defaults](#controls-and-defaults)). Every setting is commented out until you set it | you, from the shipped copy | plugins, over the image's copy |
| your `*-after.conf` | Your rules: what `verified` allows, and what is refused. Start from [`recipes.conf`](recipes.conf), six examples | you | plugins (CRS loads it after its own rules) |
| [`wba.conf`](wba.conf) | The plugin's own rules: they run the verifier, set the `tx.wba_*` variables, write the JSON log line, and send 400 for broken protocol. Do not edit it. To remove one of its rules, put `SecRuleRemoveById` in your `*-after.conf`, with the rest of your changes (ModSecurity v3 applies a removal wherever it is placed; only ModSecurity v2 needed it after the rule) | the project | plugins, as `web-bot-auth-before.conf` |
| [`nginx/web-bot-auth-guard.conf`](nginx/web-bot-auth-guard.conf), [`-server.conf`](nginx/web-bot-auth-guard-server.conf) | The guard: 400 for a signed request that is not over TLS or not origin-form. Edit its `$wba_tls` map behind a load balancer that ends TLS ([step 5](#5-tls-load-balancers-and-the-guard)) | the project; you, behind such a load balancer | `/etc/nginx/conf.d/`; the second in every `server` block |
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

On top of the CRS image, the build adds:

- [lua-openssl](https://github.com/zhaozg/lua-openssl) 0.11.1, compiled in a separate build stage against the image's own OpenSSL. No compiler ends up in the image you run;
- the rules, as a CRS "before" plugin ([`wba.conf`](wba.conf)), and the settings file with every setting commented out ([`web-bot-auth-config.conf`](web-bot-auth-config.conf));
- two nginx files: the request guard ([step 5](#5-tls-load-balancers-and-the-guard)) and the `Accept-Signature` responses ([Asking for a signature](#asking-for-a-signature));
- `/var/lib/wba/replay`, used only if you turn on [replay accounting](#replay-accounting).

### 2. List the bots you recognise

You keep your list of bots in a bots file, `bots.yaml`. Key sync reads a simpler file made from it, `agents.txt`, with one key source per line. An agent is a bot, or an AI agent that acts for a person. Only keys from the agents in `agents.txt` can ever produce `verified`. Listing an agent gives it no extra access.

Start from the project's list, check it, and write `agents.txt` from it:

```bash
cp wba-keysync/bots.seed.yaml bots.yaml                        # 1. copy it, then delete the bots you do not recognise
bun wba-keysync/validate.ts bots.yaml                          # 2. check it: exit 1 on any failure; --strict also fails on warnings
bun wba-keysync/agents.ts bots.yaml --out /srv/wba/agents.txt  # 3. write agents.txt from it
```

**The project's list.** [`wba-keysync/bots.seed.yaml`](../../wba-keysync/bots.seed.yaml) uses the operators' own sources only. Its fields are explained at the top of the file. [`wba-keysync/BOTS.md`](../../wba-keysync/BOTS.md) is generated from it. For each bot, it records the category and why, the operator's own description, every source and what it answered, and whether the bot is confirmed or only a claim. Confirmed means its keys or IP list were fetched from the operator and checked. BOTS.md calls that status `verified`; it is not the plugin's `verified`, which means a request's signature checked out. Most bots do not sign yet: only the few with a `wba` key source end up in `agents.txt`.

**Check a list of bots before you trust it**, this one or any you are offered. [`wba-keysync/validate.ts`](../../wba-keysync/validate.ts) checks every entry against the bot operator's own sources:
- its key directory, fetched the same way key sync fetches it, with its proof (a signature the directory carries to show it holds each key; see [DESIGN.md](DESIGN.md#possession-proofs));
- its published IP lists;
- any hand-kept copy of those IP ranges. It reports which ranges are stale, which are missing, and how much of the live list the copy covers.

**Write `agents.txt`.** [`wba-keysync/agents.ts`](../../wba-keysync/agents.ts) writes one line for each bot with a `wba` key source, and leaves the others out. It checks every line with key sync's own parser, so key sync accepts all of them. A bad entry stops it, and then nothing is written. Bots that share a key source share one line. `--only name,name` writes only the bots you name. Run it again whenever you change `bots.yaml`: key sync picks up the new list on its next run.

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

Copy each decision into the bot's entry in `bots.yaml` as `policy:`. [`lists.ts`](#bot-lists-and-policies) writes the rules for IP lists, User-Agent claims and policies from there. You act on signing bots through your own rules and grants too ([Use it](#use-it)). Key sync reads `agents.txt`, not the bots file. Reverse DNS is not checked.

### 3. Keep their keys current

[`wba-keysync`](../../wba-keysync/cli.ts) (key sync) fetches the keys of each agent in `agents.txt`. It writes them to the key store, the file of public keys the verifier reads. Run it every minute. It fetches a directory again only when its HTTP cache lifetime has run out, so most runs send no request at all. It never runs while a request waits, and it fetches only the URLs in your `agents.txt`.

The examples below are for a Linux host. The repository is at `/opt/web-bot-auth`, the files are in `/srv/wba`, and key sync runs as the user `wba`. Use your own paths and user. Cron's `PATH` does not include Bun's default install directory (`~/.bun/bin`), so give the full path that `command -v bun` prints.

With cron:

```
# /etc/cron.d/wba-keysync
* * * * * wba cd /opt/web-bot-auth && /usr/local/bin/bun wba-keysync/cli.ts --origins /srv/wba/agents.txt --out /srv/wba/keys/wba-keys.tsv >> /var/log/wba-keysync.log 2>&1
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
| 2 | some agent failed (an `agents.txt` line that does not parse counts as one), or has no usable key. The store was still written, and failed agents keep their last good keys | read the output: it names the agent and why. Alert on this |
| 1 | usage error, or `agents.txt` is missing or lists nothing. The store was not touched | fix the command or the file |

Key sync keeps three files in the store's directory:
- the store itself, `wba-keys.tsv`. Key sync writes a new file and renames it over the old one in one step (an atomic rename), so a reader never sees half a file;
- its HTTP cache, `wba-keys.tsv.cache.json`;
- a history of every key added or removed, `wba-keys.tsv.history`. It answers "was this key listed for that bot at that time?" when you need to attribute a signature later.

[DESIGN.md](DESIGN.md#wba-keysync-in-detail) says what key sync checks on every fetch.

**Your own bots on your own network.** Key sync never fetches from a private, loopback or link-local address (draft 6.7), so no list can point it at your internal network. If you run a bot whose keys are reachable only inside, name its exact origin on the command line: `--allow-private-origin https://bot.internal:8443`, once for each. Only that origin is excepted, each such fetch is printed as a warning, and `agents.txt` or a bots file can never turn it on. TLS is still checked: give key sync your own CA with `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`.

### 4. Run the WAF

This is a Linux production example. `/srv/wba` stands for your own directory, and `BACKEND=http://your-app:8080` for the URL of your application. On macOS, use a directory under `$HOME` instead of `/srv`: Finch's VM can see your home directory.

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

### 5. TLS, load balancers and the guard

The image installs an nginx guard. It refuses a **signed** request with 400 in two cases:
- the request arrives over plain HTTP (draft 6.1: over plain HTTP, anyone on the path can change the parts a signature does not cover);
- its request target is not origin-form, that is, it does not start with `/` (for example `GET http://other.example/`).

The guard never touches unsigned requests. It is part of the security boundary: without it, a signature for one host verified a request that nginx served for another ([DESIGN.md](DESIGN.md#the-nginx-guard)).

Behind a load balancer that ends TLS, nginx sees plain HTTP and would refuse every signed request. Replace the `$wba_tls` map in [`nginx/web-bot-auth-guard.conf`](nginx/web-bot-auth-guard.conf) with one built from a header that your load balancer always sets and that clients cannot send through it. The file shows how. In the image, the file is `/etc/nginx/conf.d/web-bot-auth-guard.conf`: mount your edited copy over it. Never build the map from a header a client can set.

**The visitor's address behind a load balancer or CDN.** The connection comes from your proxy, which passes the visitor's address in a header (`X-Forwarded-For`, `X-Real-IP`, or a CDN's own such as `CF-Connecting-IP`). nginx's real-IP module swaps it in, but only for requests from addresses you trust. **Where you put the settings decides what ModSecurity sees.** At http or server level, nginx swaps the address before ModSecurity reads it. Inside a `location` block, it swaps it afterwards, and ModSecurity (connector 1.0.4) keeps the proxy's address. The CRS image's `SET_REAL_IP_FROM` and `REAL_IP_HEADER` settings sit inside `location /`, so on their own ModSecurity logs and matches the proxy (tested: `lua/tests/live/real-ip.sh`). Add an http-level file instead, for example mounted as `/etc/nginx/conf.d/00-real-ip.conf`:

```nginx
set_real_ip_from 192.0.2.10;   # your load balancer's or CDN's addresses, and nothing else
real_ip_header X-Forwarded-For;
real_ip_recursive on;          # read the list from the right, skipping your own proxies
```

List only your own proxies. Anyone you list can claim any address, and address-based rules (including published bot address lists) would then believe them.

**Hosts you do not serve.** A signature made for a host name outside `tx.wba_site_names` never verifies (`invalid/foreign-authority`). If your nginx has several `server` blocks, also add a catch-all. Then a request for a name you do not serve reaches no application at all:

```nginx
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_reject_handshake on;   # TLS for a name no server lists: no certificate, no handshake
    return 421;                # any other request for an unknown Host: Misdirected Request (RFC 9110 15.5.20)
}
```

### Your own nginx

The image is the tested path. To install into an nginx you build and run yourself, put the same files where the [`Dockerfile`](Dockerfile) puts them. [GETTING-STARTED.md](GETTING-STARTED.md) does this on Debian 13 with Debian's own nginx and ModSecurity, every command tested:

| File | Goes | Notes |
|---|---|---|
| lua-openssl's `openssl.so` | Lua 5.3's C path, e.g. `/usr/local/lib/lua/5.3/` | build 0.11.1 at commit `bd640c2` against your OpenSSL 3 and Lua 5.3 headers, as the Dockerfile's `build` stage does |
| [`modsecurity_entry.lua`](modsecurity_entry.lua) | `/etc/modsecurity.d/wba/lua/` | its `CONFIG` names the module path and the key store |
| `base64`, `structured_fields`, `components`, `sigbase`, `keys`, `identifier`, `sha256`, `digest`, `algorithms`, `crypto`, `verify`, `coding`, `replay` (`.lua`) | `/etc/modsecurity.d/wba/lua/wba/` | |
| [`wba_log.lua`](wba_log.lua) | `/etc/modsecurity.d/wba/lua/` | its `CONFIG.path` is where log lines go |
| [`wba.conf`](wba.conf) | CRS plugins directory, as `web-bot-auth-before.conf` | its `SecRuleScript` paths must match |
| [`web-bot-auth-config.conf`](web-bot-auth-config.conf) | CRS plugins directory | |
| [`nginx/web-bot-auth-guard.conf`](nginx/web-bot-auth-guard.conf) | `http` context | |
| [`nginx/web-bot-auth-guard-server.conf`](nginx/web-bot-auth-guard-server.conf), [`nginx/web-bot-auth-accept-signature.conf`](nginx/web-bot-auth-accept-signature.conf) | every `server` block that runs ModSecurity | the second only if you use recipes A, D or E |
| key store directory | `/etc/modsecurity.d/wba/keys/` | readable by the nginx workers |

If you change any path, change it in `modsecurity_entry.lua`, `wba_log.lua` and `wba.conf` together. If nginx runs as a daemon, point `wba_log.lua`'s `CONFIG.path` at a file the worker user can append to. `/dev/stdout` is right only in a container.

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

A signature's window is the time from its `created` to its `expires`. By default there is no cap on it, because the maximum age already limits how long any signature counts. The draft's 24 hours is advice to signers (draft 5.2: RECOMMENDED). If you turn the maximum age off (`tx.wba_max_age=0`), the window may be at most a day (86400 seconds). You can set your own cap with `tx.wba_max_window` either way.

Every other control is off until you turn it on.

Installing the plugin changes no request's outcome, except broken protocol, which gets 400:
- the guard refuses signed requests that are not over TLS or not origin-form;
- rule 9534107 refuses a signature from a key you list whose covered body digest header cannot be parsed. It also refuses an unparsable signature header, but only with `tx.wba_malformed=reject`.

One CRS check also changes: at paranoia level 4, CRS rule 920274 no longer checks the `Signature-Input`, `Signature` and `Signature-Agent` headers, because their normal characters would make it refuse every signed request ([CRS paranoia levels](#crs-paranoia-levels)).

Settings live in [`web-bot-auth-config.conf`](web-bot-auth-config.conf). Each one is a commented-out rule to copy and edit. Set one for the whole site there. Or set it for some paths only, with a rule of your own placed before the plugin (the file shows how).

| Setting | Variable | Default | Effect |
|---|---|---|---|
| **Site names (required)** | `tx.wba_site_names` | none: nothing verifies | this site's own `Host` values (`host` or `host:port`). A signed request for any other is `invalid/foreign-authority`: a signature a bot made for another site, replayed here |
| Grants | `tx.wba_grant_agents` | none | origins or identifiers, exact match, that get `tx.wba_granted=1` when verified. Write an origin with no `:443` and no path. Keep it narrower than `agents.txt` |
| What a grant needs | `tx.wba_grant_require_components` | `@method @path` | a verified signature that leaves one out is not granted (one over `@authority` alone works for any method and path); `@target-uri` counts as `@path`; `none` turns it off |
| Minimum coverage | `tx.wba_require_components` | none | a signature that leaves out one of these (e.g. `@method @path`) is `unverified/insufficient-coverage`; `@target-uri` counts as `@path`, as for a grant |
| Longest window | `tx.wba_max_window` | none; 86400 when `tx.wba_max_age` is 0 | seconds from `created` to `expires`; longer is `invalid/window-too-long`. Not needed while the maximum age is on: that already bounds how long a signature counts |
| Maximum age | `tx.wba_max_age` | 3600 | seconds a signature counts after its `created`, never past its `expires`; older is `invalid/too-old` (RFC 9421 3.2.1). `0` turns it off |
| Expiry grace | `tx.wba_expiry_grace` | 0 (strict) | seconds past `expires` still accepted, up to 60, for clocks a little behind the bot's |
| Unparsable headers | `tx.wba_malformed` | `ignore` | RFC 9651 4.2. Covers `Signature-Input`, `Signature` and `Signature-Agent` only. `ignore` (default): an unparsable `Signature-Input` or `Signature` counts as unsigned (Mastodon's `Signature` is one); an unparsable `Signature-Agent` is `invalid/unparsable-agent`. `reject`: each is `invalid/malformed-headers` and gets 400 |
| Replay accounting | `tx.wba_replay_dir` | off | counts each signed statement and nonce per host ([Replay accounting](#replay-accounting)) |
| Require a nonce | `tx.wba_require_nonce` | 0 | `1`: a signature without a `nonce` is `unverified/missing-nonce` |
| Strict field lines | `tx.wba_strict_field_lines` | 0 | `1`: a signature header sent as several lines, one of which does not parse alone, is unparsable (handled as `tx.wba_malformed` says); a covered digest header's line that does not parse is `invalid/malformed-digest` and 400 |
| On or off | `tx.web-bot-auth-plugin_enabled` | 1 (on) | `0`: the plugin does nothing, and every request reads `not-signed` ([Turning the plugin off](#turning-the-plugin-off)) |

**A covered body digest header that cannot be parsed** (`Content-Digest`, `Repr-Digest` or `Unencoded-Digest`) is always `invalid/malformed-digest`. Rule 9534107 then answers 400, whatever `tx.wba_malformed` says. Only a good signature from a key you list gets that far. Ignoring the header would leave the body unchecked while the signature says it covers it.

A malformed setting value makes every signed request `unverified/bad-config`. So a typo shows in every log line instead of silently falling back to a default. Some limits are set in code, not in settings: published test keys are refused, and body digest sizes are capped. Their defaults are in `verify.lua`'s `DEFAULT_POLICY`. Override them in `modsecurity_entry.lua`'s `CONFIG.policy` ([DESIGN.md](DESIGN.md#body-digests) says what each costs).

### Turning the plugin off

There are two ways, and they do different things. Both go in a rule that runs before the plugin: in your settings file, or in another `*-config.conf`. The ids below (1000, 1001) stand for ids from your own range.

**The switch, `tx.web-bot-auth-plugin_enabled=0`, stops the plugin and keeps your rules running.** No Lua runs and no log line is written. The plugin's variables still exist with their starting values, so every request reads `not-signed`, and your rules treat it as unsigned. Recipe A still refuses a bot on `/agents/`, even one with a valid signature. To turn the plugin off everywhere, uncomment the switch in [`web-bot-auth-config.conf`](web-bot-auth-config.conf). To turn it off for one site, set it from the `Host` header:

```
SecRule REQUEST_HEADERS:Host "@streq static.example.com" \
    "id:1000,phase:1,pass,nolog,t:none,setvar:tx.web-bot-auth-plugin_enabled=0"
```

**The tag, `ctl:ruleRemoveByTag=web-bot-auth`, removes every Web Bot Auth rule for the request.** Every rule in `wba.conf` and `recipes.conf` carries `tag:'web-bot-auth'`, so this removes the plugin and any recipes you copied. Nothing is verified and none of those recipes refuses anything. Use it where Web Bot Auth does not matter, such as static files:

```
SecRule REQUEST_FILENAME "@beginsWith /static/" \
    "id:1001,phase:1,pass,nolog,t:none,ctl:ruleRemoveByTag=web-bot-auth"
```

With the tag form, no `tx.wba_*` variable is set at all. A rule of your own that reads them and has no `web-bot-auth` tag never matches there. So a rule that refuses anything not verified does not refuse on those paths. Give such rules the tag too, or use the switch.

**`ctl:ruleRemoveById` does not turn the plugin off.** The CRS way to turn a plugin off, `ctl:ruleRemoveById=9534100-9534199`, removes only `SecRule` rules in ModSecurity v3. The plugin's `SecAction` and `SecRuleScript` rules, which set the variables and run the verifier, keep running. The plugin copes with this: a signature checked in phase 1 keeps its outcome. But nothing is switched off, and your recipes are removed. Use the switch or the tag instead.

### Writing rules

Every Web Bot Auth rule needs four things:

- **Decide in phase 2.** ModSecurity checks a request in phases: phase 1 sees the headers, phase 2 the body. A signature that covers the body is settled in phase 2. In phase 1 it is still `unverified/digest-pending`, so a phase 1 rule would refuse a good body-signed request and could never grant it. Phase 2 needs request body access on, which is the CRS default.
- **Compare with `@streq`.** `@eq` compares integers: `"verified"` and `"invalid"` both become 0, so `@eq verified` matches everything.
- **Only `verified` may grant or exempt anything.** `invalid`, `unverified` and `not-signed` all mean "not verified". Grant only on `tx.wba_granted`. It is `1` only for a bot in `tx.wba_grant_agents` whose signature covered `@method` and `@path` (the default), so a copied signature cannot be reused on other paths. Test `tx.wba_agent` only to refuse (recipe B). Never grant on `tx.wba_status`: a URL-less signature is verified and names no bot.
- **Do not punish most failures.** Anyone can strip the signature headers and get the unsigned treatment. So refusing a failed signature mostly hurts honest bots whose clock is off or whose key just changed. The draft leaves each outcome to local policy (Appendix C.1). [Cloudflare](https://blog.cloudflare.com/verified-bots-with-cryptography/) "falls back to existing bot identification and mitigation mechanisms" when a signature fails. [AWS WAF Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html) labels the failure (`web_bot_auth:invalid`) and acts on it only through rules you write. Recipe F refuses the few failures that say the signature itself is forged or broken.

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

**D. A signed statement may be used once on recipe A's paths** (needs [replay accounting](#replay-accounting)). A second use gets 429 with a fresh `Accept-Signature`.

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
   - or **a tmpfs inside the container** (tested): add `--tmpfs /var/lib/wba/replay:rw,size=64m,nr_inodes=200000,uid=101,gid=101,mode=0700` to `finch run`.
2. Set it in your settings file: `setvar:tx.wba_replay_dir=/var/lib/wba/replay` (the commented-out rule 9534014).
3. Add recipes D and E.
4. Sweep the directory on the key sync timer, as root or uid 101. The sweep removes files that can no longer matter:
   - **host directory:** `bun wba-keysync/sweep.ts --dir /srv/wba/replay --max-window 3600`. Give `--max-window` your `tx.wba_max_age` (3600 by default), or your `tx.wba_max_window` if you set a smaller one. With `tx.wba_max_age` off, give it the window (a day, 86400, unless you set `tx.wba_max_window`). It removes a statement's file five minutes after the last second its signature can verify (when it expires, or reaches the maximum age). It removes a nonce's file once the nonce has gone unused for the window plus five minutes. It touches nothing else.
   - **tmpfs in the container:** `finch exec waf find /var/lib/wba/replay -type f -mmin +65 -delete` (the image has no Bun). This removes files untouched for the maximum age plus five minutes. With `tx.wba_max_age` off, use the window instead (`-mmin +1445` for 24 hours).

What you get, and the limits:

- **It counts the signed statement, not the signature bytes.** Anyone holding an ECDSA signature can make a second valid one for the same request. Both count as one signed statement, and so does a fresh ECDSA signature over the same request. Every verified signature on a request is counted.
- **Exact under load.** When 20 requests use one signature at the same moment, exactly one gets through (a live test case).
- **Per host.** Behind a load balancer, a signature can be used once on each host. Pin a bot to one host, or treat the limit as per host.
- **Fails closed.** If the directory is not writable or is full, every request that would have verified is `unverified/replay-unavailable`.
- **Sizing.** There is one file per new statement and one per new nonce, each kept for at most `tx.wba_max_age` (an hour by default). That is roughly 2 × verified requests per second × 3600 files, or fewer where bots sign with shorter windows. A bot that signs each request at 10 requests a second needs at most 72,000 files. The `nr_inodes=200000` above holds about 28 such requests a second. Lower `tx.wba_max_age` before you raise the budget. Only a key you hold can add files. If one fills the store, every request that would have verified is `unverified/replay-unavailable` until the sweep runs, and the ModSecurity debug log (level 2 or more, `MODSEC_DEBUG_LOGLEVEL`) says `[wba] replay accounting unavailable` ([Troubleshooting](#troubleshooting) shows how to turn it on).

[DESIGN.md](DESIGN.md#sessions-and-replay) says why it works this way: ModSecurity's own persistent collections were tested and cannot count.

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

For example, `User-Agent: ... GPTBot/1.3` from 20.171.206.10, which is on OpenAI's list, gets `gptbot`, `verified`, `ip-list`. The same User-Agent from 203.0.113.9 gets `gptbot`, `claimed`, `not-in-list`. A request whose User-Agent names no bot gets nothing: a list is only checked for the bot a request claims. The address checked is the one ModSecurity sees, so behind a load balancer or CDN set up the real-IP file in [step 5](#5-tls-load-balancers-and-the-guard) first.

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

Keep the name `web-bot-auth-bots-before.conf`. CRS loads the plugin files of each kind in name order, so this file runs right after the plugin's own `web-bot-auth-before.conf`, when a signature has been fully checked, and before every `*-after.conf`. Your own rules in, for example, `site-wba-rules-after.conf` then see a bot that signed as `verified`, never `claimed`. Renamed to an `*-after.conf`, it would run after every one of your files whose name sorts earlier, and those would still read `claimed`. Under a name that sorts before `web-bot-auth-before.conf`, a signature that covers the request body would not have been checked yet when these rules read it.

**Upgrading from a lists.ts that wrote `web-bot-auth-bots-after.conf`.** The next run removes that file (only one that lists.ts wrote) and writes the new one. In a container, rename your one-line plugin file to `web-bot-auth-bots-before.conf` and make it include the new name, or `nginx -t` fails because the old file is gone. With `--check`, that failure puts every file back, the old rules keep working, and the run says why.

**Updates and failures.** The WAF reads the files when it starts or reloads. `--check 'nginx -t' --reload 'nginx -s reload'` checks the new files and then reloads; if the check or the reload fails, every file goes back to what it was, so the next run tries again. A list keeps its previous version, and the run exits 2, when it cannot be fetched, is empty, holds a range wider than an IPv4 /8 or IPv6 /16, or touches private, loopback, link-local or multicast space. `status.json` says which and why. A range inside another range on the same list is left out: the wider one already covers it, and ModSecurity's address lookup can miss addresses when one range sits inside another. If a list has `192.0.2.0/24` and `192.0.2.8/29`, only `192.0.2.0/24` is written. Ranges side by side are written as they are. A bot whose list has never been fetched gets `no-list`, which no policy refuses as an impostor. `versions.json` records each list's version, when it was fetched and when it last changed, so you can tell later which list a decision used. Exit codes: 0 every list fetched; 2 the rules were written but a list kept its previous version or has none; 1 nothing changed. Rule ids are 9534150 and four per bot from 9534200; `ids.json` keeps each bot's ids the same between runs.

**robots.txt.** `bun wba-keysync/robots.ts bots.yaml` prints a suggested robots.txt that asks every `deny` bot not to crawl. It only asks; the rules refuse. Merge it into your own as you see fit.

[`lua/tests/live/bot-lists.sh`](../tests/live/bot-lists.sh) runs all of this in the image: lists from HTTPS servers, every status and reason, each policy in both modes, a list update through `--check` and `--reload`, and a list server that breaks.

### Check your deployment against the latest upstream

Bots sign with libraries that keep changing, and so does the draft. You run this check on your own schedule: weekly, and before every upgrade. [`lua/tests/interop/interop.sh`](../tests/interop/interop.sh) does three things:
- it signs requests with the **newest** release of Cloudflare's reference signer (npm `web-bot-auth`) and with Stytch's example recipe;
- it sends them through your real edge and reads each result from your WAF's log;
- it runs the draft's newest test vectors through this release's verifier.

It needs Bun and `curl`. The draft vectors also need `lua` and `openssl`, and are skipped without them. Every run prints the upstream versions it used. Exit 0 means every case came out as expected.

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

The run sends 7 requests to `/.well-known/wba-interop/<run>/…`:
- genuine ones, which must verify;
- a tampered one, an expired one and one signed with an unpublished key, which must not.

Your rules may refuse some of them. That is fine: the check reads only the logged result.

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
 "method":"GET","uri":"/agents/x","status":"verified","reason":"","agent":"https://bot.example/.well-known/http-message-signatures-directory",
 "agent_proof":"valid","keyid":"eTnUpXZYhQFajMO2QSWeganNyW1dkGV58okMu-2NJLY","label":"sig1","created":1790922496,"expires":1790922556,
 "granted":false,"sighash":"<64 hex>","uses":1,"nonce_uses":null,"covered":"@authority signature-agent"}
```

A failed one. Every field taken from the signature is `null`, because nothing in it can be trusted:

```json
{"event":"web-bot-auth","time":1790922507,"unique_id":"179092250734.118020","client_ip":"198.51.100.4",
 "method":"GET","uri":"/agents/x","status":"invalid","reason":"bad-signature","agent":null,"agent_proof":null,
 "keyid":null,"label":null,"created":null,"expires":null,"granted":false,"sighash":null,"uses":null,"nonce_uses":null,"covered":null}
```

### Fields

| Field | Value | When `null` |
|---|---|---|
| `event` | always `web-bot-auth` | never |
| `time` | Unix seconds the line was written | never |
| `unique_id` | ModSecurity's transaction id: the same request in the audit log | never |
| `client_ip`, `method`, `uri` | as the access log has them; `uri` is raw, cut to 1024 bytes | never |
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

Ed25519 and RSA PKCS #1 v1.5 signatures are deterministic: the same key and input always give the same bytes. So the same `sighash` twice is a replay or an identical retry. ECDSA and RSA-PSS signatures are randomised, so the same `sighash` twice is a replay. An ECDSA replay can also arrive with a new `sighash`: anyone holding an ECDSA signature can make a second valid one for the same request. Both count as one signed statement, so `uses` catches it. Across hosts, compare `sighash` in your log search system (SIEM).

**Sessions belong in your SIEM.** Group verified lines by `agent`, then `keyid`, with an idle gap. A key stands for a bot operator, never a person (draft 7.2).

### Other logs

- **The audit log holds raw signatures.** Its part B is the request headers (the CRS image's `MODSEC_AUDIT_LOG_PARTS` default is `ABIJDEFHZ`). So every signed request in the audit log carries its `Signature`, as it carries any `Authorization` or `Cookie`. Treat the audit log as sensitive for at least as long as your longest signature window.
- **Which requests reach the audit log.** With the CRS image's defaults, a request is written there when its final status is a 5xx or a 4xx other than 404, or when a rule with `log` matched it. So a signed request that your site answers with 200 is usually not there.
- **Finding a bot you do not know yet.** For `unverified/unknown-agent`, the JSON line does not name the bot, because the line holds nothing from a signature that did not verify. To see which bot it is, add this rule to your `*-after.conf` for a while:

  ```
  SecRule TX:wba_reason "@streq unknown-agent" \
      "id:9534139,phase:5,pass,log,t:none,tag:'web-bot-auth',msg:'Web Bot Auth: unknown agent'"
  ```

  It refuses nothing. It writes one audit entry for every request with an unknown bot, and the entry's request headers show the bot's `Signature-Agent`, for example `sig1="https://newbot.example"`. Each entry also holds the raw `Signature` (see above), and a busy unknown bot writes one entry per request, so remove the rule once you know which bots they are.
- **The debug log says why.** Set `MODSEC_DEBUG_LOG` to a file and `MODSEC_DEBUG_LOGLEVEL` to 2 or more (the image's defaults are `/dev/null` and 0). You then see `[wba] bad configuration: ...` for a rejected setting, `[wba] log line not written: ...` when the JSON line could not be written (for example `No space left on device`), `Failed to execute lua script: ...` with the Lua error when the plugin's Lua could not start (a module with a syntax error, or lua-openssl missing), and other plugin messages.
- **nginx's error log shows refusals, not other rule messages.** ModSecurity-nginx writes each refusal at nginx's `error` level, with the rule's id and message and the request's `unique_id` (the same id as in the JSON line and the audit log), for example:

  ```
  ... ModSecurity: Access denied with code 460 (phase 2). ... [id "9534130"] [msg "Web Bot Auth: a verified signature is required here"] ... [unique_id "179092250734.118020"] ...
  ```

  So refusals by the recipes, by rule 9534107 (400 for a header the plugin cannot read) and by CRS appear there. A rule that only logs (`pass,log`) is written at nginx's `info` level, and the CRS image runs nginx at `warn`, so its message never appears in the error log; it goes to the audit log with its request. That is why lines start to appear in the error log when you switch a rule from `pass,log` to `deny`, or your bots file from `policy_mode: log` to `enforce`.
- **Why a JSON line of its own:** the error log shows only refusals, and the audit log only some requests. The JSON line is written for every signed request, whatever those settings. To turn it off, remove rule 9534121 with `SecRuleRemoveById` in your `*-after.conf`.

## Troubleshooting

| You see | Likely cause | Do |
|---|---|---|
| `unverified/no-site-names` | `tx.wba_site_names` is not set | list your site's host names ([settings](#controls-and-defaults)) |
| `invalid/foreign-authority` | the request's Host is not one of your site names: a signature made for another site, or a name you forgot to list | add the name if it is yours |
| `unverified/unknown-agent` | the request names a bot that is not in your key store. The log line does not name it. The audit log shows its `Signature-Agent` only if the request was refused or failed (a 4xx or 5xx status): a request your site answered with 200 is not there | to find the bot, add the audit rule in [Other logs](#other-logs) for a while; then add the bot to your bots file and run `agents.ts` (or add it to `agents.txt`), then key sync |
| `unverified/unknown-key` | the bot is listed, the key is not: it changed, or key sync has not run since | check the timer, and key sync's exit code and output |
| `unverified/key-not-current` | the bot's directory dates the key outside now (`nbf`, `exp`) | nothing on your side |
| `unverified/bad-agent-url`, `unsupported-agent-type` | the bot's `Signature-Agent` is not a valid URL of a known type, or names a key directory by more than its origin (the draft says to ignore such a member) | the bot's to fix ([For bot operators](#for-bot-operators)) |
| `invalid/expired`, `not-yet-valid`, `too-old` | an old request replayed, or a clock off here or at the bot (60 s allowed ahead; none past `expires` unless `tx.wba_expiry_grace`) | check NTP on the WAF |
| `invalid/window-too-long` | the signature's window is longer than `tx.wba_max_window`, or longer than a day with `tx.wba_max_age` off | raise or remove the cap, turn the maximum age back on, or ask the bot for shorter windows |
| `invalid/bad-signature` | forged, or something between the bot and you changed a part it signed (a CDN rewriting `Host` or the path) | check what sits in front of nginx |
| `unverified/digest-pending` at the end | request body access is off, so phase 2 never ran | turn it on for those paths |
| `unverified/body-too-large` | a SHA-256 body over 128 KiB, or a coded body over the decode budget | ask the bot for `sha-512`, or raise the limit ([DESIGN.md](DESIGN.md#body-digests)) |
| `unverified/body-incomplete` | the body was cut at `SecRequestBodyLimit` | raise the limit for those paths |
| `unverified/insufficient-coverage`, `missing-nonce` | your settings ask for more than the signature has | ask the bot, or relax the setting for that path |
| `unverified/bad-config` | a setting is malformed | the debug log names it |
| `unverified/keystore-unavailable` | the store is missing or unreadable, its first line is not a version header (`# wba-keys v2`, or `v1` from an older key sync), or a line for this bot's keys is malformed (a bad line for another bot does not count) | mount the directory, not the file; read key sync's output |
| `unverified/replay-unavailable` | the replay directory is not writable by uid 101, or is full | check the mount's owner and its inode budget |
| `unverified/engine-error` | lua-openssl (or another module) did not load. A module with a syntax error does this too: only the two files named on `SecRuleScript` lines are checked when nginx starts | the debug log at level 2 ([Other logs](#other-logs)) says why: `Failed to execute lua script: ...`, followed by the Lua error. Rebuild the image; on your own nginx, check Lua's C path and the module files |
| `400` for every signed request | they reach nginx over plain HTTP | behind a load balancer that ends TLS, change the guard's `$wba_tls` map ([step 5](#5-tls-load-balancers-and-the-guard)) |
| `400` for one signed request | a target that is not origin-form; a covered body digest header that cannot be parsed (`invalid/malformed-digest`); or, with `tx.wba_malformed=reject`, an unparsable signature header | the client's to fix |
| clients get `460` or `461` | the Accept-Signature nginx file is not included | include it, or use `status:403` and `status:429` |
| no log lines | unsigned traffic writes none; for signed traffic, rule 9534121 was removed or `CONFIG.path` is not writable | check with the [Quick start](#quick-start) request |
| CRS 4.30.0 refuses ordinary paths such as `/recipes/chef-salad` with rule 932260 | a CRS 4.30.0 false positive ([coreruleset#4840](https://github.com/coreruleset/coreruleset/issues/4840)): the rule now reads the URL path; fixed upstream by [#4842](https://github.com/coreruleset/coreruleset/pull/4842), not yet released | after CRS (in the CRS image, `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf`) add `SecRuleUpdateTargetById 932260 "!REQUEST_FILENAME"`, the same change as #4842; remove it once a CRS release has the fix |

## Outcomes and reasons

| Status | Reasons | Meaning |
|---|---|---|
| `verified` | (empty), `url-less` | As defined in [What every request gets](#what-every-request-gets). |
| `invalid` | `foreign-authority`, `bad-signature`, `expired`, `too-old`, `not-yet-valid`, `window-too-long`, `missing-param`, `bad-param`, `bad-keyid`, `unsupported-alg`, `alg-mismatch`, `alg-undetermined`, `authority-not-covered`, `agent-not-covered`, `ambiguous-agent`, `agent-not-https`, `missing-component`, `unsupported-component`, `duplicate-component`, `bad-component-value`, `malformed-headers`, `unparsable-agent`, `orphan-label`, `test-key`, `digest-mismatch`, `malformed-digest`, `bad-content-coding` | A check failed. `malformed-headers` and `malformed-digest` also get 400 (rule 9534107). With the default `tx.wba_malformed=ignore`, an unparsable signature header gives `not-signed/unparsable-field` or `invalid/unparsable-agent` instead of `malformed-headers`. |
| `unverified` | `no-site-names`, `unknown-agent`, `unknown-key`, `key-not-current`, `bad-agent-url`, `unsupported-agent-type`, `agent-absent`, `digest-pending`, `digest-algorithm-unsupported`, `digest-coding-unsupported`, `digest-partial`, `body-incomplete`, `body-too-large`, `insufficient-coverage`, `too-many-signatures`, `missing-nonce`, `bad-config`, `keystore-unavailable`, `replay-unavailable`, `crypto-error`, `engine-error`, `internal-error` | Could not decide: key not held, agent URL ignored, body not (yet) checkable, a setting not met, or an infrastructure fault. Never treated as success. `too-many-signatures` happens only if you set a cap, `CONFIG.policy.max_signatures` in `modsecurity_entry.lua`: there is none by default. |
| `not-signed` | `no-signature`, `no-wba-signature`, `unparsable-field` | No Web Bot Auth signature on the request (by default, an unparsable signature header counts as none). |

A request with several signatures gets the best outcome among them. [DESIGN.md](DESIGN.md#several-signatures-on-one-request) has the ranking.

## For bot operators

- **Publish your keys** at `https://<your-origin>/.well-known/http-message-signatures-directory`:
  - Answer `200` with the media type `application/http-message-signatures-directory+json`. Do not redirect.
  - The body is a JWK Set of Ed25519 (`OKP`/`Ed25519`), EC (`P-256`, `P-384`) or RSA (2048 to 16384 bits) public keys, with no private members. An RSA key's public exponent must be odd, at least 3 and at most 256 bits. Above 3072 bits it may be at most 64 bits, because OpenSSL verifies nothing with a wider one. The usual 65537 fits both.
  - Set `kid` to the key's RFC 7638 thumbprint (draft 5.5).
  - If your JWK has `alg`, use `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `rsa-pss-sha512` or `rsa-v1_5-sha256`; the JOSE names `EdDSA`, `Ed25519`, `ES256`, `ES384`, `PS512` and `RS256` also work. Any other value makes the key unusable here. Pinning an RSA key to `PS512` or `rsa-pss-sha512` stops anyone verifying a PKCS #1 v1.5 signature with it (RFC 9421 7.3.6).
  - If you publish `nbf`/`exp`, use Unix seconds. `wba-keysync` reads a value of 10^12 or more as milliseconds, converts it and logs a warning, because at least one live directory publishes milliseconds.
  - You may also sign the response (draft Appendix B): one signature per key, `keyid` its thumbprint, tag `http-message-signatures-directory`, covering `("@authority";req "content-digest")` with `created` and `expires`, and a `Content-Digest` of the body. Sites see it as `tx.wba_agent_proof=valid`.
- **Or publish them elsewhere** (draft 5.5): at a JWK Set URL (`Signature-Agent: sig1="https://your-origin.example/jwks.json";type=jwks_uri`), or in an OAuth Client ID Metadata Document whose `client_id` is its own URL and which carries `jwks` or `jwks_uri` (`;type=cimd`). Either way, use `https`, answer `200` and do not redirect. The draft sets no media type there, so any `Content-Type` is read, but the body must parse as JSON and its keys must pass the same checks. `kid` may be any label there; sites index keys by thumbprint.
- **Sign every request** under a label (e.g. `sig1`):
  - Cover `"@authority"` and `"signature-agent";key="sig1"`. Also cover `"@method"` and `"@path"`: by default, sites grant only signatures that cover them, and the plugin's `Accept-Signature` asks for them. They also tie a signature to one request line, which narrows replay.
  - Include `created`, `expires` (keep it short: the draft recommends at most 24 h, and by default a site counts a signature for only an hour after `created`), `keyid` (the thumbprint), `alg` (for example `alg="ed25519"`; required for an RSA key whose JWK has no `alg`) and `tag="web-bot-auth"`.
  - ECDSA signatures are r ‖ s at fixed width (RFC 9421 3.3.4, 3.3.5), not the DER that most libraries return.
- **Send `Signature-Agent` in dictionary form:** `Signature-Agent: sig1="https://your-origin.example"`. For a key directory, send the origin only: a member that is more than an origin (one with a path, say) is ignored (`unverified/bad-agent-url`), and an origin that is not `https` is `invalid/agent-not-https`. The legacy bare-string form is accepted, but the draft says signers MUST send the dictionary.
- **Bodies:** cover `Content-Digest`, with `sha-512` (draft 5.2: "An Agent that needs one MUST send and cover Content-Digest"). `Unencoded-Digest` is checked over `gzip` and `deflate` bodies. `br` and `zstd` bodies are not decoded here, so an `Unencoded-Digest` over them is `unverified`.
- **Ask the site to add your origin** (or your `jwks_uri` / `cimd` URL, with its type) to its allowlist. Never sign with a published test key.
- **Check your headers** against a known-good request: [`wba-keysync/sign.ts`](../../wba-keysync/sign.ts) `curl` prints one. The [Quick start](#quick-start) runs this verifier on your machine to check yours.

## CRS paranoia levels

The plugin works at every CRS paranoia level (PL). [`lua/tests/live/paranoia.sh`](../tests/live/paranoia.sh) proves it on each release: every signer shape (each algorithm, `jwks_uri` and `cimd` agents, a proof, URL-less, an ActivityPub header), over HTTP/1.1 and over HTTP/2, at PL 1 to 4. Each one passes every CRS rule and verifies. Two cases need an exclusion of your own, both below: some random base64 values (rule 941120, every level), and a `Signature-Agent` URL that holds a non-ASCII character or a literal `%` (rule 920272, levels 3 and 4). Tested with CRS 4.30.0, libmodsecurity 3.0.17, ModSecurity-nginx 1.0.4 and nginx 1.30.5 (the image in the [Dockerfile](Dockerfile)). The requests, responses and matched rules are in [`evidence/`](evidence/): [before](evidence/crs-paranoia-before-fix.md) and [after](evidence/crs-paranoia-after-fix.md) the fix to the PL 4 exemption.

What each level is for, in [CRS's own words](https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/), and what it means for signed requests:

| PL | CRS: what it is for | What it adds for headers | Signed requests |
|---|---|---|---|
| 1 | Baseline security with a minimal need to tune away false positives: "CRS for everybody running an HTTP server on the internet". | Attack patterns in every header (XSS, path traversal, PHP, Java, shellshock), CR/LF injection, NUL bytes. | Pass, except the 941120 false positive below. |
| 2 | "Adequate when real user data is involved", such as an online shop; expect false positives. | Regex SQL injection and more Java checks in headers; only tab, CR, LF and printable bytes allowed. | Pass. |
| 3 | "Online banking level security"; false positives are "accepted and expected". | Base64-encoded Java payloads; printable ASCII only, and no `%`, after decoding `%XX` (rule 920272). | Pass, unless a `Signature-Agent` URL holds a non-ASCII character or a literal `%` (below). |
| 4 | Protects the "crown jewels", "at one's own risk": a large number of false positives. | A very strict character set in headers (rule 920274), escape sequences, `${`. | Pass, because of the plugin's one exemption below; the level 3 exception still applies. |

**The one exemption (PL 4).** Rule 920274 allows only letters, digits, space and `" & * + , - . / : ; = _` in a header. `Signature-Input` always needs `(`, `)` and `@`, for example `sig1=("@authority" "signature-agent";key="agent1")`. A `Signature-Agent` URL may need other characters, and an ActivityPub `Signature` header carries `(request-target)`. CRS itself exempts `User-Agent`, `Referer`, `Cookie`, `Sec-Fetch-User`, `Sec-CH-UA` and `Sec-CH-UA-Mobile` from this rule for the same kind of reason. So `wba.conf` exempts those three headers from 920274 only; every other CRS check on them still runs. The test checks both directions: the names match in any letter case (HTTP/2 sends them in lower case), and the same value under any other header name is still refused.

**A CRS false positive at every level (rule 941120).** Rule 941120, "XSS Filter - Category 2: Event Handler Vector", reads every request header at PL 1. It treats a digit, `/` or `+` followed by `on`, letters and `=` as an HTML event handler such as `onload=`. A random base64 value can look like that. Example, a sha-256 `Content-Digest`:

```
Content-Digest: sha-256=:hmsi6PXNOrqyV/Ur95FJQD1JwJVcrTr/OnzWOarQXAM=:
```

`/OnzWOarQXAM=:` matches, and CRS answers 403. It needs a value of 32 random bytes in padded base64, which ends in exactly one `=`; about 1 in 2,000 such values match. Signed requests carry these in three places: a sha-256 `Content-Digest` or `Repr-Digest` (RFC 9530) on a signed body, a 32-byte nonce in standard base64, and an RSA-4096 signature. A 64-byte nonce, a sha-512 digest, and Ed25519, ECDSA, RSA-2048 and RSA-3072 signatures end in `==` or no padding and cannot match. This is not specific to Web Bot Auth: any header in which such a value is followed by another character can hit it, such as a sha-256 `Content-Digest` from any client. A value that ends the header cannot, because the rule needs a character after the `=`: an `Authorization: Basic` credential never matches. CRS has known about the class since [issue #1867](https://github.com/coreruleset/coreruleset/issues/1867) (2021). It moved 941120 to PL 2 for CRS 4.0 ([#2306](https://github.com/coreruleset/coreruleset/pull/2306)), then back to PL 1 with a new expression in 4.23.0 ([#4291](https://github.com/coreruleset/coreruleset/pull/4291)), which also made it read every header ([#4327](https://github.com/coreruleset/coreruleset/pull/4327)). If it affects you, exclude the header from 941120 with CRS's usual [rule exclusion](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), for example in your own `*-after.conf`:

```
SecRuleUpdateTargetById 941120 "!REQUEST_HEADERS:/^content-digest$/"
```

`paranoia.sh` pins this behaviour, so the test fails when a CRS release changes it.

**Percent-encoded `Signature-Agent` URLs at levels 3 and 4 (rule 920272).** Rule 920272 first decodes every `%XX` in every header, then allows only printable ASCII other than `%`. Most `Signature-Agent` URLs are plain ASCII, and `%7E` (`~`) or `%20` (a space) decode to characters it allows. But a `jwks_uri` or `cimd` URL whose path holds a non-ASCII character, such as `https://bot.example/café/keys.json`, has to be sent percent-encoded as `caf%C3%A9`, and a literal `%` as `%25`. Both are refused at levels 3 and 4: the plugin verifies the request, and CRS then refuses it. A key directory member is an origin, so it can hold neither. The plugin's exemption covers rule 920274 only, not this one; CRS applies 920272 to every header, `Referer` included. If a bot you accept uses such a URL, exclude the header from this one rule, for example in your own `*-after.conf`:

```
SecRuleUpdateTargetById 920272 "!REQUEST_HEADERS:/^signature-agent$/"
```

`paranoia.sh` pins both: which URLs are refused at each level, and that this exclusion lets them through while the same value in any other header is still refused.

## Known limits

What this release does not do, or does in a way you should know before you rely on it:

- **Rule IDs are not yet registered.** The plugin uses IDs 9534000 to 9534999, which are free in the CRS plugin registry (they moved from 9530xxx, which another plugin holds, on 2026-10-11). The registry entry is filed once the repository is public; until then, check the registry before loading other third-party plugins.
- **Your key store can be probed.** Recipe F refuses `bad-signature`, which needs a key you hold, but passes `unknown-key`. So someone can learn which bot keys your store holds. Key directories are public, so this reveals your list of bots, not a secret.
- **Shared platform keys.** Some services sign every customer's traffic with one key (for example AWS AgentCore Browser and Cloudflare Browser Run). `verified` then names the platform and cannot tell its customers apart.
- **Recipes decide in phase 2.** Never turn request body access off on a path a recipe guards ([Writing rules](#writing-rules)).
- **Site names are one list for the whole plugin.** They are compared with the `Host` header, not with the port the request arrived on or the nginx `server` block. If one nginx serves different apps under the same name on different ports, set `tx.wba_site_names` per `server` block (ModSecurity rules in that block), including the port, and remove any `X-Forwarded-Host` a client sent before the request reaches the backend.
- **Debian images only.** The Alpine CRS images do not work: the Dockerfile uses `apt-get`.
- **Absolute URLs.** A signed request whose request line holds a full URL (`GET https://host/path`) gets 400 from the guard. Requests that start with `/` are not affected. This is a declared deviation from RFC 9112 3.2.2 ([CONFORMANCE.md](CONFORMANCE.md)).
- **A load balancer that ends TLS** needs an edit to the guard ([step 5](#5-tls-load-balancers-and-the-guard)).
- **Replay accounting counts per host.** Several WAFs behind one load balancer do not share their counts.
- **Some compressed bodies cannot be checked.** An `Unencoded-Digest` over a `br`, `zstd` or `compress` body is `unverified/digest-coding-unsupported`. Only gzip and deflate are decoded. `Content-Digest`, which covers the bytes as sent, works for every coding.
- **An unreadable covered digest header gets 400** ([Controls and defaults](#controls-and-defaults)).
- **A returned `Accept-Signature` nonce is not checked** against the ones nginx handed out ([Asking for a signature](#asking-for-a-signature)).
- **Key sync and DNS.** Key sync checks that a key URL's address is public, then fetches it, and the fetch looks the name up again. A DNS answer that changes between the two lookups can get past the check. TLS still has to succeed for the bot's name, which an internal host rarely can. Run key sync on a host that cannot reach anything sensitive.
- **Reverse DNS is not checked**, and an IP list is checked only for the bot a request claims: a request from a listed address whose User-Agent names no bot gets no bot variables ([Bot lists and policies](#bot-lists-and-policies)).
- **Bun only:** `validate.ts`, `agents.ts`, `report.ts`, `lists.ts`, `robots.ts` and `interop.sh`. The other tools also run on Node 26.
- **CRS 4.30.0** refuses some ordinary paths with rule 932260, a CRS bug with a workaround ([Troubleshooting](#troubleshooting)).

## Running the tests

```bash
lua/tests/run_all.sh              # every suite, mutants, a test for every documented reason, fixture freshness, key-sync; one exit code
lua/tests/run_all.sh --live       # plus the image test stage, the live suite, the Quick start, the registry path, the real-IP checks and the bot lists path (Finch; DOCKER=docker for Docker; DOCKER="sudo finch" on Linux)
lua/tests/live/matrix.sh          # the live suite on every CRS image in crs-images.txt
```

The Lua suites need `lua` (5.3 or later) and `openssl`. Key sync and the fixture checks need Bun and Node; `run_all.sh` reports a missing tool as SKIP, never as a pass. `test_crypto`, the Wycheproof vectors and `crypto.lua`'s mutants need lua-openssl, so they run in the image's test stage. The development repository runs the same suites in CI, on Finch and on Docker. [TESTING.md](TESTING.md) lists every suite and its results.
