# Getting started: nginx, ModSecurity, CRS and Web Bot Auth

> **Preview: do not use this in production yet.** The plugin is a preview ([README](README.md)). Try it on a test server first.

At the end of this page you have nginx on Debian 13 (trixie) with ModSecurity v3, the OWASP Core Rule Set (CRS) 4.30.0 and this plugin. An unsigned request to a bot-only path is refused and asked for a signature. A request signed by a test bot is verified, passed to your application and logged.

There are two ways to run the plugin:

- **The CRS container image (recommended).** The official CRS nginx image plus this plugin, built from the [`Dockerfile`](Dockerfile). It is the tested route: the live suite runs on every CRS release of the last 12 months ([TESTING.md, Version matrix](TESTING.md#version-matrix)). See the README's [Quick start](README.md#quick-start) and [Set up](README.md#set-up).
- **Your own nginx on Debian 13 (this page).** Debian's own nginx and ModSecurity packages, CRS from the CRS release, and the plugin's files where the image puts them. [`lua/tests/live/getting-started.sh`](../tests/live/getting-started.sh) runs this page as written in a clean `debian:trixie` container, so the page cannot drift from what works.

## What you get on Debian

| | The image | Debian 13 (this page) |
|---|---|---|
| nginx | 1.30.5 | 1.26.3 (`nginx` 1.26.3-3+deb13u9) |
| libmodsecurity | 3.0.17 | 3.0.14 (`libmodsecurity3t64` 3.0.14-1+deb13u1) |
| ModSecurity-nginx (the connector) | 1.0.4 | 1.0.3 (`libnginx-mod-http-modsecurity` 1.0.3-2+b3) |
| CRS | 4.30.0 | 4.30.0, from the CRS release (not Debian's `modsecurity-crs` 3.3.7) |
| Lua | 5.3 | 5.3.6 (`liblua5.3-0`, linked by libmodsecurity) |
| lua-openssl | 0.11.1, commit `bd640c2` | the same, built in step 2 |

**Security fixes.** ModSecurity fixed bugs upstream after 3.0.14. On Debian you get those fixes only when Debian backports them. On 11 October 2026 the [Debian security tracker](https://security-tracker.debian.org/tracker/source-package/modsecurity) listed ten open issues as unfixed in trixie's package, for example CVE-2026-104269 (a multipart `filename*` parameter that gets past filename rules). Read that page before you choose this route, and again with each Debian update. The image route takes ModSecurity from the CRS image instead: 3.0.17 in the build the Dockerfile pins.

**What is tested here.** The test runs this page at CRS paranoia level 1: an unsigned `GET`, a signed `GET` over HTTP/1.1 and over HTTP/2, a signed request over plain HTTP, and an unknown host name. It also sends a signed `POST` whose signature covers its body (through `Content-Digest`), over HTTP/1.1 and HTTP/2, and the same request with one byte of the body changed, which is refused. It then sends the signed requests again at level 4, rotates the logs, and runs [Behind a load balancer](#behind-a-load-balancer). The full live suite and every signer shape in [`paranoia.sh`](../tests/live/paranoia.sh) run on the image only. The version matrix includes images with libmodsecurity 3.0.14, but with connector 1.0.4, not Debian's 1.0.3.

## Before you start

- **A server and your machine.** A Debian 13 server where you are root, with a copy of this repository at `/opt/web-bot-auth` (the commands use that path). Your own machine needs this repository and [Bun](https://bun.sh) (or Node 26: type `node` for `bun`) to sign test requests.
- **Your site's name.** The page uses `example.com`. Replace it everywhere with your own name.
- **TLS.** The plugin's nginx guard refuses a signed request over plain HTTP with 400 (draft 6.1: anyone on the path could change what the signature does not cover). Step 6 makes a self-signed certificate so you can test now. Production uses a real certificate, for example from your CA or Let's Encrypt.
- **The clock.** Keep the server's clock in sync with NTP (for example `systemd-timesyncd` or `chrony`). A signature may be dated up to 60 seconds ahead of your clock and expires exactly at its `expires` time.
- **CRS 4, not Debian's CRS 3.** Debian's `modsecurity-crs` package is CRS 3.3.7. CRS 3 has no plugin mechanism, and this plugin is a CRS plugin: CRS 4 loads it from its `plugins/` directory. Step 3 installs CRS 4.30.0 from the CRS release instead, and step 1 keeps Debian's CRS 3 off the server.
- **Request body access stays on.** It is ModSecurity's recommended setting and what CRS expects. The plugin finishes body-signed requests in phase 2, and the example rules decide there. Never turn it off.
- **The plugin's log.** `wba_log.lua` writes to `/dev/stdout`, which is right only in a container. Step 5 points it at `/var/log/nginx/wba.log`, a file the nginx workers (`www-data` on Debian) can append to.
- **The key store.** `/etc/modsecurity.d/wba/keys/` must be readable by `www-data`. Once you run key sync for real bots, it must also be writable by the user key sync runs as ([Go live](#go-live)).
- **Behind a load balancer or CDN** that ends TLS, nginx sees plain HTTP and the visitor's address is in a header. Follow the steps below, then [Behind a load balancer](#behind-a-load-balancer).

### How this page is tested

Each `bash` block's first line says where it runs:

- `# On the server`: as root on the server. The test runs these in a `debian:trixie` container, in page order.
- `# On your machine`: on your own machine, from the repository root. The test runs these on the test host.
- `# On the server (optional)`: only if you want it. The test runs these after the blocks above.
- `# On the server (behind a load balancer)`: only if a load balancer or CDN ends TLS in front of nginx. The test runs these last.

Other blocks are examples for your own site and are not run. The test stands in for five things this page leaves to you: your application (a stub on `127.0.0.1:8080` that answers 200), DNS (`example.com` reaches the container), systemd (the container has none), `scp` (a copy into the container), and your load balancer (an nginx server in the container that ends TLS and connects to nginx from `192.0.2.10`).

## 1. Install nginx, ModSecurity and Lua

```bash
# On the server
apt-get update
apt-get install -y --no-install-recommends nginx libnginx-mod-http-modsecurity lua5.3 \
  ca-certificates curl gnupg gpgv openssl
dpkg-query -W nginx libnginx-mod-http-modsecurity libmodsecurity3t64 liblua5.3-0
ldd /usr/lib/*/libmodsecurity.so.3 | grep -F liblua5.3
```

What each package is for:

- `nginx`: the web server. Its workers run as `www-data`.
- `libnginx-mod-http-modsecurity`: the connector, ModSecurity-nginx 1.0.3. It pulls in libmodsecurity 3.0.14, and Debian enables the module in `/etc/nginx/modules-enabled/`.
- `lua5.3`: the Lua interpreter, used only to check in step 2 that Lua finds lua-openssl. ModSecurity itself uses the Lua library.
- `ca-certificates`, `curl`, `gnupg`, `gpgv`: download CRS and check its signature (step 3). Debian 13's apt checks its own signatures with `sqv`, so `gpgv` may not be installed yet.
- `openssl`: the test certificate (step 6).

`--no-install-recommends` matters here: the connector package recommends `modsecurity-crs`, Debian's CRS 3.3.7.

The last command must print a line with `liblua5.3.so.0`. That shows libmodsecurity was built with Lua, which the plugin needs: its rules run the Lua verifier with `SecRuleScript`. If it prints nothing, stop: this libmodsecurity cannot run the plugin.

The connector package also installs `/etc/nginx/modsecurity.conf` (ModSecurity's recommended settings, in detection-only mode) and `/etc/nginx/modsecurity_includes.conf`. This page does not use them. Step 4 writes the configuration in full under `/etc/modsecurity.d/`, the paths the image uses, so none of the plugin's files needs editing for paths.

## 2. Build lua-openssl

The plugin checks Ed25519, ECDSA and RSA signatures through [lua-openssl](https://github.com/zhaozg/lua-openssl), a binding to OpenSSL. Debian does not package it. Debian's `lua-luaossl` is a different binding, and it cannot verify Ed25519 ([TESTING.md, Why lua-openssl](TESTING.md#why-lua-openssl)). Build the release the image uses, 0.11.1, with the same commit and `make` command as the [`Dockerfile`](Dockerfile)'s build stage:

```bash
# On the server
apt-get install -y --no-install-recommends build-essential liblua5.3-dev libssl-dev git
git clone https://github.com/zhaozg/lua-openssl.git /usr/local/src/lua-openssl
cd /usr/local/src/lua-openssl
git checkout bd640c240708c77d7b4193906adf4cef30e09dca
git submodule update --init
make LUA_CFLAGS=-I/usr/include/lua5.3 OPENSSL_LIBS="-lssl -lcrypto"
install -D -m 644 openssl.so /usr/local/lib/lua/5.3/openssl.so
lua5.3 -e 'print(require("openssl").version())'
```

- `OPENSSL_LIBS="-lssl -lcrypto"` links only Debian's own OpenSSL libraries. The Makefile's default would also link zlib and zstd, for no use here. Because it links Debian's OpenSSL, Debian's OpenSSL updates cover it too; restart nginx after one, as nginx's own TLS needs anyway.
- `/usr/local/lib/lua/5.3/` is the first directory on Debian's Lua 5.3 module path (`lua5.3 -e 'print(package.cpath)'` shows it). libmodsecurity uses the same Lua library, so nginx's workers load `openssl.so` from there.
- The last command prints something like `0.11.1  Lua 5.3  OpenSSL 3.5.7 ...`. If it fails, the plugin cannot verify anything: every signed request would be `unverified/engine-error`.

The compilers are needed only for the build. You can remove them now:

```bash
# On the server
apt-get purge -y build-essential liblua5.3-dev libssl-dev git
apt-get autoremove -y
```

## 3. Install CRS 4.30.0, checked

CRS signs each release with its GPG key, fingerprint `3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72` ([CRS installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/)). This step downloads the release's minimal archive (the rules, the plugins directory and `crs-setup.conf.example`, uploaded with the release) and its signature. It unpacks the archive only if `gpgv` accepts the signature as made by that exact key:

```bash
# On the server
cd "$(mktemp -d)"
curl -fsSLO https://github.com/coreruleset/coreruleset/releases/download/v4.30.0/coreruleset-4.30.0-minimal.tar.gz
curl -fsSLO https://github.com/coreruleset/coreruleset/releases/download/v4.30.0/coreruleset-4.30.0-minimal.tar.gz.asc
curl -fsSL -o crs-key.asc https://coreruleset.org/security.asc
export GNUPGHOME="$PWD/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import crs-key.asc
gpg --batch --export 36006F0E0BA167832158821138EEACA1AB8A6E72 > crs.gpg
mkdir -p /etc/modsecurity.d/owasp-crs
gpgv --keyring ./crs.gpg coreruleset-4.30.0-minimal.tar.gz.asc coreruleset-4.30.0-minimal.tar.gz \
  && tar -xzf coreruleset-4.30.0-minimal.tar.gz --strip-components 1 -C /etc/modsecurity.d/owasp-crs
cp /etc/modsecurity.d/owasp-crs/crs-setup.conf.example /etc/modsecurity.d/owasp-crs/crs-setup.conf
ls /etc/modsecurity.d/owasp-crs/plugins/
```

- `gpg --export` writes out only the key with CRS's published fingerprint. If `security.asc` held any other key, a signature made with it would still be refused. If the file does not hold CRS's key at all, `crs.gpg` is empty and every signature is refused.
- `gpgv` must print `Good signature from "OWASP Core Rule Set <security@coreruleset.org>"`. On a bad or unknown signature it prints `BAD signature` or `Can't check signature`, exits non-zero, and `tar` does not run. The next command then fails, because `crs-setup.conf.example` is not there. Stop and find out why before you go on.
- `crs-setup.conf` is CRS's own settings file, copied from the example as CRS's documentation says. Its defaults are a good start: paranoia level 1, refuse at an anomaly score of 5.
- The last command lists `README.md empty-after.conf empty-before.conf empty-config.conf`. Keep the three `empty-*.conf` files. ModSecurity stops nginx loading when an `Include` pattern matches no file (`Not able to open file`), and these files make sure each plugin pattern in step 4 always matches one.

The [CRS documentation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/) checks the full source archive (`archive/refs/tags/v4.30.0.tar.gz` with `coreruleset-4.30.0.tar.gz.asc`) the same way. Both archives are signed with the same key.

## 4. Configure ModSecurity

Debian has no main ModSecurity configuration for this layout, so write it in full. The settings below come from [`modsecurity.conf-recommended`](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/modsecurity.conf-recommended) of ModSecurity v3.0.14, with these changes: the rule engine is on; the regular expression limits are the CRS image's; the audit log is JSON, in `/var/log/nginx`; temporary files go in a private directory; the Unicode table is named by its full path; and `SecStatusEngine` is left out.

```bash
# On the server
install -d -o www-data -g www-data -m 700 /var/cache/modsecurity
install -o root -g adm -m 640 /dev/null /var/log/nginx/modsec_audit.json
cat > /etc/modsecurity.d/modsecurity.conf <<'EOF'
# ModSecurity engine settings, from ModSecurity v3.0.14's
# modsecurity.conf-recommended. Each line says why it is set.

# Refuse what the rules refuse. (The recommended file says DetectionOnly.)
SecRuleEngine On

# Read request bodies, so CRS and the plugin can inspect them. Never turn off.
SecRequestBodyAccess On

# Parse XML and JSON bodies with their own parsers, so rules see their fields.
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
    "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
    "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# Largest request body: 12.5 MiB with file uploads, 128 KiB without.
# A larger body is refused, not passed on unread.
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# Deepest JSON nesting and most arguments parsed; rule 200007 refuses a
# request that reaches the argument limit, since the rest would go unparsed.
SecRequestBodyJsonDepthLimit 512
SecArgumentsLimit 1000
SecRule &ARGS "@ge 1000" \
    "id:'200007',phase:2,t:none,log,deny,status:400,msg:'Failed to fully parse request body due to large argument count',severity:2"

# Refuse a body the parser could not read: no rule could inspect it.
SecRule REQBODY_ERROR "!@eq 0" \
    "id:'200002',phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"

# Refuse multipart bodies that parsers could read in different ways.
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200003',phase:2,t:none,log,deny,status:400, \
    msg:'Multipart request body failed strict validation: \
    PE %{REQBODY_PROCESSOR_ERROR}, \
    BQ %{MULTIPART_BOUNDARY_QUOTED}, \
    BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
    DB %{MULTIPART_DATA_BEFORE}, \
    DA %{MULTIPART_DATA_AFTER}, \
    HF %{MULTIPART_HEADER_FOLDING}, \
    LF %{MULTIPART_LF_LINE}, \
    SM %{MULTIPART_MISSING_SEMICOLON}, \
    IQ %{MULTIPART_INVALID_QUOTING}, \
    IP %{MULTIPART_INVALID_PART}, \
    IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
    FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" \
    "id:'200004',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"

# Cap the work one regular expression match may do. A match that reaches the
# cap counts as no match, and ModSecurity sets TX:MSC_PCRE_LIMITS_EXCEEDED.
# 100000 is the CRS image's value. The recommended file's 1000 refused none
# of the signed or ordinary requests tested on this setup, at paranoia levels
# 1 and 4 (lua/wba/evidence/pcre-match-limit.md in the plugin's repository);
# 100000 leaves more room.
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000
# Refuse a request where the cap was hit. This rule runs at the start of
# phase 2, so it sees a hit in a phase 1 rule only: a hit in a CRS rule that
# runs later in phase 2 is not refused (tested). ModSecurity knows this:
# https://github.com/owasp-modsecurity/ModSecurity/issues/3415
SecRule TX:/^MSC_/ "!@streq 0" \
    "id:'200005',phase:2,t:none,log,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"

# Inspect text response bodies up to 512 KiB (CRS's data leakage rules read
# them); past that, inspect the first 512 KiB and pass the rest.
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial

# Temporary files (large uploads) and persistent data: a directory only the
# nginx workers can use. The recommended /tmp/ is shared with every user.
SecTmpDir /var/cache/modsecurity
SecDataDir /var/cache/modsecurity

# Audit log: one JSON object per line for each request a rule flagged, or
# that ended with a 5xx or a 4xx other than 404. Parts: request headers (B)
# and body (I, J), response headers (F) and body (E), and the rules that
# matched (H). It holds raw Signature headers, so it is readable by root
# and adm only (created 0640 above).
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog /var/log/nginx/modsec_audit.json

# Arguments are separated by "&"; cookies are read as version 0 cookies.
SecArgumentSeparator &
SecCookieFormat 0

# The table t:urlDecodeUni uses to turn %uXXXX into a byte (code page 20127,
# US-ASCII). Debian's connector package ships it.
SecUnicodeMapFile /etc/nginx/unicode.mapping 20127
EOF
cat > /etc/modsecurity.d/setup.conf <<'EOF'
# Everything ModSecurity loads, in CRS's plugin order: CRS settings, plugin
# settings, plugin rules that run before CRS, CRS, plugin rules after CRS.
Include /etc/modsecurity.d/modsecurity.conf
Include /etc/modsecurity.d/owasp-crs/crs-setup.conf
Include /etc/modsecurity.d/owasp-crs/plugins/*-config.conf
Include /etc/modsecurity.d/owasp-crs/plugins/*-before.conf
Include /etc/modsecurity.d/owasp-crs/rules/*.conf
Include /etc/modsecurity.d/owasp-crs/plugins/*-after.conf
EOF
```

- **The include order** is the one [CRS's plugin documentation](https://coreruleset.org/docs/4-about-plugins/4-1-plugins/) gives. The plugin's rules are a "before" file, so the variables they set exist before any CRS rule runs. Your own rules are "after" files, so they run after CRS and see what it and the plugin decided.
- **The audit log is named `.json`, not `.log`, on purpose.** Debian's `/etc/logrotate.d/nginx` rotates `/var/log/nginx/*.log` by renaming each file and creating a new one. ModSecurity keeps writing to the file it opened, even after `nginx -s reopen` and `nginx -s reload` (tested), so a renamed audit log would stop growing in its new place. [Go live](#go-live) rotates it with `copytruncate` instead.

## 5. Install the plugin

Copy the plugin's files where the image puts them ([README, Your own nginx](README.md#your-own-nginx)), so no path in them needs changing:

```bash
# On the server
cd /opt/web-bot-auth/lua/wba
install -d -m 755 /etc/modsecurity.d/wba/lua/wba /etc/modsecurity.d/wba/keys
install -m 644 modsecurity_entry.lua wba_log.lua /etc/modsecurity.d/wba/lua/
install -m 644 base64.lua structured_fields.lua components.lua sigbase.lua keys.lua identifier.lua \
  sha256.lua digest.lua algorithms.lua crypto.lua verify.lua coding.lua replay.lua \
  /etc/modsecurity.d/wba/lua/wba/
install -m 644 wba.conf /etc/modsecurity.d/owasp-crs/plugins/web-bot-auth-before.conf
install -m 644 web-bot-auth-config.conf /etc/modsecurity.d/owasp-crs/plugins/web-bot-auth-config.conf
install -m 644 recipes.conf /etc/modsecurity.d/owasp-crs/plugins/wba-recipes-after.conf
cat > /etc/modsecurity.d/owasp-crs/plugins/wba-site-config.conf <<'EOF'
# Your site's own host names (required): a signature made for any other name
# never verifies. Separate several names with spaces.
SecAction "id:9534017,phase:1,pass,nolog,t:none,setvar:'tx.wba_site_names=example.com'"
EOF
sed -i 's|path = "/dev/stdout"|path = "/var/log/nginx/wba.log"|' /etc/modsecurity.d/wba/lua/wba_log.lua
grep -F 'path = "/var/log/nginx/wba.log"' /etc/modsecurity.d/wba/lua/wba_log.lua
install -o www-data -g adm -m 640 /dev/null /var/log/nginx/wba.log
```

What goes where, and why:

| File | Installed as | Why |
|---|---|---|
| `modsecurity_entry.lua`, `wba_log.lua` and the modules | `/etc/modsecurity.d/wba/lua/` and its `wba/` | where `wba.conf`'s `SecRuleScript` lines and `modsecurity_entry.lua`'s `CONFIG` look for them |
| [`wba.conf`](wba.conf) | `plugins/web-bot-auth-before.conf` | the plugin's own rules. They set the `tx.wba_*` variables and write the log line, and refuse nothing except broken protocol. Do not edit it |
| [`web-bot-auth-config.conf`](web-bot-auth-config.conf) | `plugins/web-bot-auth-config.conf` | the settings, every one commented out, with what each does ([Controls and defaults](README.md#controls-and-defaults)) |
| `wba-site-config.conf` | `plugins/` | the one required setting, your site names, in a file of its own as in the Quick start. An upgrade can then replace the shipped settings file. Writing it into `web-bot-auth-config.conf` works too |
| [`recipes.conf`](recipes.conf) | `plugins/wba-recipes-after.conf` | the six example rules, so you can see a refusal: recipe A refuses an unverified request to `/agents/` and asks for a signature. Replace them with your own rules before you go live |

**The one edit: where the log goes.** `wba_log.lua`'s `CONFIG.path` is `/dev/stdout`, the container's log in the image. For nginx run as a daemon, `sed` points it at `/var/log/nginx/wba.log`, and `grep` prints the changed line (it fails if the line did not change). The file is created owned by `www-data`, because the nginx workers write it. `wba_log.lua` opens the file for each line it writes, so after log rotation the next line goes to the new file with no signal to nginx. Debian's `/etc/logrotate.d/nginx` already rotates `/var/log/nginx/*.log`, this file included, and creates the new one as `www-data`.

## 6. Make a test certificate

Signed requests must arrive over TLS. This certificate is self-signed, for testing only: browsers and `curl` do not trust it, which is why the checks below pass `-k` or `--insecure`. In production use a real certificate for your name, and the same two nginx lines point at it.

```bash
# On the server
install -d -m 755 /etc/nginx/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj /CN=example.com -addext subjectAltName=DNS:example.com \
  -keyout /etc/nginx/tls/example.com.key -out /etc/nginx/tls/example.com.crt
chmod 600 /etc/nginx/tls/example.com.key
```

## 7. Configure nginx

```bash
# On the server
install -m 644 /opt/web-bot-auth/lua/wba/nginx/web-bot-auth-guard.conf /etc/nginx/conf.d/
install -m 644 /opt/web-bot-auth/lua/wba/nginx/web-bot-auth-guard-server.conf \
  /opt/web-bot-auth/lua/wba/nginx/web-bot-auth-accept-signature.conf /etc/nginx/snippets/
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-available/example.com <<'EOF'
# Names this server does not serve: no TLS handshake, and 421 Misdirected
# Request over plain HTTP. Without this, nginx would pass a request for any
# name to the first server below.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_reject_handshake on;
    return 421;
}

# Plain HTTP for your name. The guard comes first, so a signed request gets
# 400 (draft 6.1); everything else is redirected to HTTPS.
server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    include snippets/web-bot-auth-guard-server.conf;
    return 301 https://$host$request_uri;
}

# Your site: TLS and HTTP/2, through ModSecurity, CRS and the plugin, to
# your application.
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name example.com;

    ssl_certificate     /etc/nginx/tls/example.com.crt;
    ssl_certificate_key /etc/nginx/tls/example.com.key;

    modsecurity on;
    modsecurity_rules_file /etc/modsecurity.d/setup.conf;

    include snippets/web-bot-auth-guard-server.conf;
    include snippets/web-bot-auth-accept-signature.conf;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
ln -sf /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/example.com
nginx -t
systemctl reload nginx
```

`nginx -t` must end with `test is successful`. Before that it prints the connector's line, for example `ModSecurity-nginx v1.0.3 (rules loaded inline/local/remote: 0/890/0)`; the count may differ.

What each part does:

- **`conf.d/web-bot-auth-guard.conf`** (http level: Debian's `nginx.conf` includes `conf.d/*.conf` inside `http`) defines when a signed request must be refused. **`snippets/web-bot-auth-guard-server.conf`** does the refusing, in every server block that can see a signed request. Together they answer 400 to a signed request that arrives over plain HTTP, or whose request target does not start with `/` (for example `GET http://other.example/`). Without the guard, a signature made for one host could verify a request nginx served for another ([README, step 5](README.md#5-tls-load-balancers-and-the-guard)). Unsigned requests are never touched.
- **`snippets/web-bot-auth-accept-signature.conf`** turns the status 460 that recipe A refuses with into 403 with an `Accept-Signature` header, which asks the client to sign ([Asking for a signature](README.md#asking-for-a-signature)). Keep `proxy_intercept_errors` off, nginx's default, as the file's comments explain.
- **Debian's default site is removed** because it also claims `default_server` on port 80. With both enabled, `nginx -t` fails with `a duplicate default server for 0.0.0.0:80`.
- **The catch-all server** refuses names you do not serve ([README, step 5](README.md#5-tls-load-balancers-and-the-guard)). `ssl_reject_handshake on` means a TLS client that asks for any other name, or for none, gets no certificate and no handshake. So check your site by its name, not by its address.
- **`modsecurity on` and `modsecurity_rules_file`** sit in the TLS server block: ModSecurity runs only for your site. If you serve several sites, add those two lines and both `include` lines to each one, and list every name in `tx.wba_site_names`.
- **`proxy_pass http://127.0.0.1:8080`** stands for your application. Change it to where yours listens. If nothing listens there, a request that passes every rule gets 502 from nginx instead of 200.

## Check it works

The commands on your machine reach the server as `example.com`. If the name does not point at the server yet, add a line to `/etc/hosts` on your machine with the server's address, for example:

```text
203.0.113.10 example.com
```

Make a test bot on your machine and give the server its public key. `sign.ts init` makes an Ed25519 key, keeps the private half in `~/wba-test` (outside the repository, so it never lands in git), and writes a key store that lists the public half under the test agent `https://test-agent.example`. Real bots are listed differently ([Go live](#go-live)).

```bash
# On your machine
bun wba-keysync/sign.ts init ~/wba-test
scp ~/wba-test/keys/wba-keys.tsv root@example.com:/etc/modsecurity.d/wba/keys/wba-keys.tsv
```

The plugin reads the key store for each signed request, so nginx needs no reload. Check that the nginx workers can read it:

```bash
# On the server
runuser -u www-data -- head -n 1 /etc/modsecurity.d/wba/keys/wba-keys.tsv
```

It prints the store's version line, `# wba-keys v2`.

**An unsigned request to the bot-only path `/agents/`** is refused by recipe A, with a header that asks for a signature:

```bash
# On your machine
curl -sk -o /dev/null -D - https://example.com/agents/hello | grep -iE '^(HTTP/|accept-signature)'
```

```text
HTTP/2 403
accept-signature: sig1=("@authority" "@method" "@path" "signature-agent";key="sig1");created;expires;nonce="...";tag="web-bot-auth"
```

**CRS is active.** CRS's own check, a request that looks like an attack, gets 403:

```bash
# On your machine
curl -sk -o /dev/null -w '%{http_code}\n' 'https://example.com/?foo=/etc/passwd&bar=/bin/sh'
```

**A request signed by the test bot** passes every rule. `sign.ts curl` prints a `curl` command for one signed request; `sed` adds `--http1.1` or `--http2`, and `sh` sends it:

```bash
# On your machine
bun wba-keysync/sign.ts curl https://example.com/agents/hello --dir ~/wba-test --insecure | sed 's/^curl /curl --http1.1 /' | sh
bun wba-keysync/sign.ts curl https://example.com/agents/hello --dir ~/wba-test --insecure | sed 's/^curl /curl --http2 /' | sh
```

Both print `200` from your application (502 if nothing listens on `127.0.0.1:8080` yet). `--insecure` is there only because the test certificate is self-signed. Leave off `| sh` to read the signed headers.

**The same signed request over plain HTTP** gets 400 from the guard:

```bash
# On your machine
bun wba-keysync/sign.ts curl http://example.com/agents/hello --dir ~/wba-test | sh
```

**A name you do not serve** gets 421 from the catch-all:

```bash
# On your machine
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: other.example' http://example.com/
```

**What the server logged.** One JSON line in `wba.log` for each signed request ModSecurity saw (the plain HTTP one never reached it); nginx's access log, which shows the protocol of each request; and nginx's error log, which names the rule behind each refusal:

```bash
# On the server
tail -n 2 /var/log/nginx/wba.log
tail -n 6 /var/log/nginx/access.log
grep -F 'ModSecurity: Access denied' /var/log/nginx/error.log | tail -n 2
```

```text
{"event":"web-bot-auth","time":1791709295,...,"uri":"/agents/hello","status":"verified","reason":"","agent":"https://test-agent.example/.well-known/http-message-signatures-directory",...}
{"event":"web-bot-auth","time":1791709295,...,"uri":"/agents/hello","status":"verified","reason":"","agent":"https://test-agent.example/.well-known/http-message-signatures-directory",...}
... "GET /agents/hello HTTP/2.0" 403 ...
... "GET /?foo=/etc/passwd&bar=/bin/sh HTTP/2.0" 403 ...
... "GET /agents/hello HTTP/1.1" 200 ...
... "GET /agents/hello HTTP/2.0" 200 ...
... "GET /agents/hello HTTP/1.1" 400 ...
... "GET / HTTP/1.1" 421 ...
... ModSecurity: Access denied with code 460 (phase 2). ... [id "9534130"] [msg "Web Bot Auth: a verified signature is required here"] ...
... ModSecurity: Access denied with code 403 (phase 2). ... [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 15)"] ...
```

Recipe A refused with status 460, and `web-bot-auth-accept-signature.conf` turned it into the 403 with `Accept-Signature` that the client saw. Both refused requests are also in the audit log, `/var/log/nginx/modsec_audit.json`, one JSON object per line, with status 403. CRS's entry lists the rules that matched. Recipe A's entry lists none on Debian (an empty `messages`): with Debian's ModSecurity 3.0.14 and connector 1.0.3, a refusal answered through that file loses its rule list, where the image's audit log keeps it. Read the error log for those. [README, Logs](README.md#logs) explains every field of the `wba.log` line.

When you are done with the test bot, delete `~/wba-test` on your machine. Never list `https://test-agent.example` in `tx.wba_grant_agents`.

## Paranoia levels

CRS's paranoia level (PL) decides how strict CRS is, from 1 (the default) to 4. It is set in `crs-setup.conf` by rule 900000, `tx.blocking_paranoia_level`, which is commented out there, so CRS runs at PL 1. The plugin works at every level ([README, CRS paranoia levels](README.md#crs-paranoia-levels)). At PL 4 it exempts its three headers from CRS rule 920274 only, and CRS rule 941120 has a false positive at every level for some base64 values. That section shows the exclusion to use.

To raise the level, add rule 900000 at the end of `crs-setup.conf` (here PL 4), check the configuration and reload:

```bash
# On the server (optional)
cat >> /etc/modsecurity.d/owasp-crs/crs-setup.conf <<'EOF'

# Paranoia level (see rule 900000 above, commented out).
SecAction \
    "id:900000,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.30.0',\
    setvar:tx.blocking_paranoia_level=4"
EOF
nginx -t && systemctl reload nginx
```

Add it once. To change the level later, edit that rule's last line. Expect false positives from your own traffic at higher levels, and tune them as [CRS describes](https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/). The test runs this block after the page's other blocks (all but the load balancer's) and signs the requests again: both still pass at PL 4, over HTTP/1.1 and HTTP/2.

## Behind a load balancer

When a load balancer or CDN sits in front of nginx and ends TLS, three things change: your site's traffic reaches nginx over plain HTTP, the guard must learn which requests arrived over TLS, and the visitor's address arrives in a header. The three blocks below set this up. Run them only if you have a load balancer. The test runs them last, with an nginx server in the same container standing in for a load balancer at `192.0.2.10`.

**1. Your site on port 80.** The load balancer sends your site's traffic to nginx's port 80, so that server must now do what the port 443 server did: run ModSecurity, CRS and the plugin, and pass requests to your application. This replaces the site from step 7. Make sure only your load balancer can reach nginx, for example with a firewall rule or security group that lets in only its addresses. A client that reaches nginx directly could send its own `X-Forwarded-Proto` and `X-Forwarded-For`.

```bash
# On the server (behind a load balancer)
cat > /etc/nginx/sites-available/example.com <<'EOF'
# Names this server does not serve: 421 Misdirected Request.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    return 421;
}

# Your site, as your load balancer sends it: plain HTTP, through ModSecurity,
# CRS and the plugin, to your application.
server {
    listen 80;
    listen [::]:80;
    server_name example.com;

    modsecurity on;
    modsecurity_rules_file /etc/modsecurity.d/setup.conf;

    include snippets/web-bot-auth-guard-server.conf;
    include snippets/web-bot-auth-accept-signature.conf;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
    }
}
EOF
```

**2. The guard's TLS check.** nginx now receives plain HTTP, so the guard would refuse every signed request with 400. Build its `$wba_tls` map from a header that your load balancer always sets, replacing any value the client sent, as the comment in `web-bot-auth-guard.conf` shows. Most load balancers set `X-Forwarded-Proto` to `https` for a request that came in over TLS. The `sed` below changes the map's two lines, and `grep` prints the result:

```bash
# On the server (behind a load balancer)
sed -i -e 's/^map \$https \$wba_tls {$/map $http_x_forwarded_proto $wba_tls {/' \
  -e 's/^    on 1;$/    https 1;/' /etc/nginx/conf.d/web-bot-auth-guard.conf
grep -A 3 '^map $http_x_forwarded_proto $wba_tls' /etc/nginx/conf.d/web-bot-auth-guard.conf
```

It prints:

```nginx
map $http_x_forwarded_proto $wba_tls {
    default 0;
    https 1;
}
```

If it prints nothing, the file did not have the lines `sed` looks for: make the change by hand. Never build the map from a header a client can set: that would undo the check.

**3. The visitor's address.** nginx's real-IP module swaps in the address your load balancer passes, but only for requests from addresses you trust. Put the settings at http level, as here in `/etc/nginx/conf.d/00-real-ip.conf`, so nginx swaps the address before ModSecurity reads it ([README, step 5](README.md#5-tls-load-balancers-and-the-guard)):

```bash
# On the server (behind a load balancer)
cat > /etc/nginx/conf.d/00-real-ip.conf <<'EOF'
set_real_ip_from 192.0.2.10;   # your load balancer's or CDN's addresses, and nothing else
real_ip_header X-Forwarded-For;
real_ip_recursive on;
EOF
nginx -t
systemctl reload nginx
```

Anyone you list in `set_real_ip_from` can claim any address, so list only your own load balancers. With `real_ip_recursive on`, nginx reads `X-Forwarded-For` from the right and takes the first address that is not one you trust. So a visitor who sends their own `X-Forwarded-For: 203.0.113.66` still shows up with their real address.

**Check it.** Send the signed requests from [Check it works](#check-it-works) to your site's name, through the load balancer. They print `200`, and the `client_ip` in each new `wba.log` line is your machine's address, not the load balancer's. A signed request sent straight to nginx's port 80, around the load balancer, gets 400 from the guard. The test checks all of this, and that a signature made for another host name is refused there (`invalid/bad-signature`).

## Go live

**Verify real bots.** The test bot's key store was hand-made. For real bots you list the bots you recognise, and key sync fetches their keys: follow README [Set up step 2](README.md#2-list-the-bots-you-recognise) (`bots.yaml` and `agents.txt`) and [step 3](README.md#3-keep-their-keys-current) (key sync from cron or a systemd timer). On this server, key sync writes straight into the plugin's key store: give it `--out /etc/modsecurity.d/wba/keys/wba-keys.tsv`. It replaces the store by writing a new file and renaming it over the old one, and keeps its cache and history next to it. So the directory must be writable by the user key sync runs as (`wba` in the README's examples) and readable by `www-data`:

```bash
# On the server
useradd --system --no-create-home --shell /usr/sbin/nologin wba
chown wba:www-data /etc/modsecurity.d/wba/keys
chmod 750 /etc/modsecurity.d/wba/keys
runuser -u www-data -- head -n 1 /etc/modsecurity.d/wba/keys/wba-keys.tsv
```

Key sync's first run replaces the test bot's store with the keys of the bots you listed. For bots that do not sign yet, [Bot lists and policies](README.md#bot-lists-and-policies) checks them against their operators' address lists: on your own nginx, give `lists.ts` the plugins directory, `/etc/modsecurity.d/owasp-crs/plugins`, as `--out`. Its rules land there as `web-bot-auth-bots-before.conf`, a "before" file, so they have set `tx.bot_*` by the time your own `*-after.conf` rules run.

**Your own rules.** `recipes.conf` is examples. Remove `plugins/wba-recipes-after.conf` and put the rules you want in your own file, for example `plugins/site-wba-rules-after.conf`. Start from [Rule examples](README.md#rule-examples) and the four points in [Writing rules](README.md#writing-rules). Try a refusing rule with `pass,log` first, and watch what it matches before you switch it to `deny`. After each change, run `nginx -t && systemctl reload nginx`.

**Rotate the logs.** `wba.log` needs nothing more: Debian's nginx logrotate covers it (step 5). The audit log needs `copytruncate`, because ModSecurity keeps writing to the file it opened (step 4): logrotate copies the file, then empties it in place.

```bash
# On the server
apt-get install -y --no-install-recommends logrotate
cat > /etc/logrotate.d/modsecurity-audit <<'EOF'
# ModSecurity keeps its audit log open across nginx reloads, so rotate it in
# place. A few lines written between the copy and the truncation can be lost.
/var/log/nginx/modsec_audit.json {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
```

The audit log holds raw `Signature` headers ([README, Other logs](README.md#other-logs)): keep it, and its rotated copies, no longer than you need.

**Check from outside.** Run the [Check it works](#check-it-works) requests against the real name and certificate, without `-k` and `--insecure`. To check your deployment against the newest signing libraries, see [Check your deployment against the latest upstream](README.md#check-your-deployment-against-the-latest-upstream): on this server its `LOGS` is `tail -n 5000 /var/log/nginx/wba.log`.

## Troubleshooting

Specific to a hand-built nginx. The README's [Troubleshooting](README.md#troubleshooting) covers every outcome and reason.

| You see | Likely cause | Do |
|---|---|---|
| `nginx -t`: `Failed to load script: Failed to compile script '/etc/modsecurity.d/wba/lua/modsecurity_entry.lua: cannot open ...: No such file or directory` | a Lua file is not where `wba.conf`'s `SecRuleScript` lines look | install it there (step 5). If you move the files, change the paths in `wba.conf`, `modsecurity_entry.lua` and `wba_log.lua` together |
| `nginx -t`: `Not able to open file. Looking at: '/etc/modsecurity.d/owasp-crs/plugins/*-after.conf'` | no file matches one of the plugin patterns | put back CRS's `plugins/empty-*.conf` files (step 3) |
| `nginx -t`: `a duplicate default server for 0.0.0.0:80` | Debian's default site is still enabled | `rm /etc/nginx/sites-enabled/default` (step 7) |
| `wba.log` says `unverified/engine-error` for every signed request | lua-openssl did not load | `lua5.3 -e 'require("openssl")'` must work; `openssl.so` belongs in `/usr/local/lib/lua/5.3/` (step 2) |
| `wba.log` says `unverified/keystore-unavailable` | the key store is missing, or `www-data` cannot read it | `runuser -u www-data -- head -n 1 /etc/modsecurity.d/wba/keys/wba-keys.tsv` must print `# wba-keys v2` |
| signed requests pass, but no line appears in `wba.log` | `www-data` cannot append to it | `chown www-data:adm /var/log/nginx/wba.log`. To see the reason, add `SecDebugLog /var/log/nginx/modsec_debug.log` and `SecDebugLogLevel 2` to `modsecurity.conf` and reload: it says `[wba] log line not written: ... Permission denied`. Remove both lines afterwards |
| `400` for every signed request | they reach nginx over plain HTTP: over port 80, or from a load balancer that ends TLS | use HTTPS, or change the guard's `$wba_tls` map ([Behind a load balancer](#behind-a-load-balancer)) |
| `curl` fails the TLS handshake (status `000`) | the catch-all refuses names it does not know, and an IP address sends no name | use the site's name; for a test, map it in `/etc/hosts` |
| clients get `460` | `web-bot-auth-accept-signature.conf` is not included in that server block | include it (step 7), or change recipe A to `status:403` |
| a recipe A refusal is in the audit log with no rules listed | expected with Debian's ModSecurity 3.0.14 and connector 1.0.3, for refusals answered through `web-bot-auth-accept-signature.conf` | find the rule in nginx's error log: `grep -F 'Access denied' /var/log/nginx/error.log` |
| the audit log stops growing after rotation | it was rotated by renaming, and ModSecurity still writes to the renamed file | rotate it with `copytruncate` ([Go live](#go-live)); a restart of nginx makes ModSecurity open the new file |
| CRS 4.30.0 refuses ordinary paths with rule 932260 | a CRS 4.30.0 false positive (README Troubleshooting) | put the README's `SecRuleUpdateTargetById 932260 "!REQUEST_FILENAME"` in a `plugins/*-after.conf` file |
