# How Web Bot Auth works here

This page explains, with diagrams, how a bot signs a request, what happens when that request reaches your site, how the bots' keys get onto your WAF, and how the result reaches CRS and your own rules. It describes what the plugin does today; [Protections added on 2026-10-09](#protections-added-on-2026-10-09) lists the newest settings and what is still planned. For commands and settings, see the [README](README.md); for the reasoning behind each choice, see [DESIGN.md](DESIGN.md).

## Words used on this page

| Word | Meaning here |
|---|---|
| **Bot operator** | The company that runs a bot or AI agent, for example OpenAI for ChatGPT's agent. |
| **Key pair** | Two linked keys. The bot keeps the **private key** secret and signs with it; anyone can check a signature with the matching **public key**. |
| **Signature** | A short value the bot computes over parts of its request with its private key. Only the private key's holder can produce it, and changing a signed part breaks it. |
| **Key directory** | A file the bot operator publishes on its own website, at `https://<their site>/.well-known/http-message-signatures-directory`, listing its public keys. |
| **`Signature-Agent`** | A request header in which the bot names its key directory. |
| **`agents.txt`** | The list of the bots you recognise, one key source per line. You keep your list in `bots.yaml`, and `agents.ts` writes `agents.txt` from it. Keys from bots not on it are never trusted. |
| **Key sync** | `wba-keysync`, a small program you run on a timer. It fetches the key directories of the bots in `agents.txt` and writes their public keys to the key store. |
| **Key store** | `wba-keys.tsv`, the file of public keys the WAF reads. |
| **Verifier** | This plugin's checking code. It runs inside ModSecurity, in front of your application, and decides whether a request's signature is genuine. |
| **Outcome** | The verifier's verdict, written into ModSecurity variables: `tx.wba_status` (`verified`, `invalid`, `unverified` or `not-signed`) and `tx.wba_reason` (why). |
| **Recipe** | A ready-made rule in [`recipes.conf`](recipes.conf) that acts on the outcome, for example "refuse unsigned requests on `/agents/`". |
| **CRS** | The OWASP Core Rule Set, the attack-detection rules that run in the same ModSecurity. |

## The big picture

Two things happen at different times. **Ahead of time**, your key sync copies the public keys of the bots you recognise onto your WAF. **On each request**, the verifier checks the signature against those copied keys, gives the request an outcome, and your rules and CRS act on it. The verifier never fetches anything while a request waits.

```mermaid
flowchart LR
    subgraph BotSide["Bot operator (e.g. chatgpt.com)"]
        PK["Private key<br/>(kept secret)"]
        DIR["Key directory<br/>(public keys, on their website)"]
    end
    subgraph YourSide["Your site"]
        AG["agents.txt<br/>(bots you recognise)"]
        KS["Key sync<br/>(cron, every minute)"]
        STORE["Key store<br/>wba-keys.tsv"]
        WAF["nginx + ModSecurity<br/>verifier, then CRS and your rules"]
        APP["Your application"]
    end
    AG --> KS
    DIR -- "fetched ahead of time" --> KS
    KS -- "writes" --> STORE
    STORE -- "read on each signed request" --> WAF
    PK -- "signs each request" --> REQ["Signed request"]
    REQ --> WAF
    WAF -- "allowed requests" --> APP
```

## 1. How a bot signs a request

The bot chooses which parts of its request to sign. Draft -00 requires at least the site it is talking to (`@authority`, from the Host header, or the full `@target-uri`) and, when it sends one, the `Signature-Agent` entry naming its key directory. Many bots also sign the method and path. It adds a creation time, an expiry time and a tag, and signs the whole thing with its private key.

```mermaid
sequenceDiagram
    autonumber
    participant B as Bot
    participant S as Your site
    Note over B: Choose the parts to sign: the site name,<br/>the Signature-Agent entry, often the method and path
    Note over B: Add created and expires times,<br/>an optional nonce and the tag web-bot-auth
    Note over B: Build the signature base: one line per signed part,<br/>exactly as RFC 9421 section 2.5 lays it out
    Note over B: Sign the signature base with the private key
    B->>S: GET /agents/x with three extra headers:<br/>Signature-Agent names the key directory,<br/>Signature-Input lists what was signed and when,<br/>Signature carries the signature itself
```

What the three headers look like (one signature, labelled `sig1`):

```
Signature-Agent: sig1="https://bot.example"
Signature-Input: sig1=("@authority" "signature-agent";key="sig1");created=1790922496;expires=1790922556;keyid="eTnUpXZYhQFajMO2QSWeganNyW1dkGV58okMu-2NJLY";tag="web-bot-auth"
Signature: sig1=:<base64 signature>:
```

The `keyid` is the key's [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint, a hash of the public key, so the verifier can find the right key in the bot's directory.

## 2. How the bots' keys reach your WAF

Key sync runs on a timer (cron or systemd, every minute). It only fetches the bots listed in `agents.txt`, only over HTTPS, and only when its cached copy has expired, so most runs make no request at all. It never runs while a request waits.

```mermaid
sequenceDiagram
    autonumber
    participant T as Timer (cron or systemd)
    participant K as Key sync (wba-keysync)
    participant D as Bot's key directory (https)
    participant F as Key store files
    T->>K: run every minute
    K->>K: read agents.txt
    loop each bot in agents.txt whose cached copy has expired
        K->>D: GET /.well-known/http-message-signatures-directory
        D-->>K: public keys (JSON), plus an optional signed proof
        K->>K: check the response: HTTPS, size limits, key types,<br/>no published test keys, thumbprints, the optional proof
    end
    K->>F: write the new key store, then rename it over the old one
    Note over K,F: A bot whose fetch failed keeps its last good keys.<br/>Exit 0 = all good, 2 = some bot failed (alert on it), 1 = config error.
```

Because the store is replaced in one rename, the verifier never reads a half-written file. It reads the store on every signed request, so a new key works without restarting the WAF.

## 3. What happens when a request arrives

Every request passes through nginx and ModSecurity. Unsigned requests cost almost nothing: one rule sees there is neither a `Signature-Input` nor a `Signature` header and skips the verifier. Signed requests go through the checks below, in ModSecurity's phase 1 (headers), with a second step in phase 2 (body) only when the signature covers the body.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (bot or anyone)
    participant N as nginx and the guard
    participant V as Verifier (Lua, in ModSecurity)
    participant R as Your rules and CRS
    participant A as Your application
    C->>N: request
    alt signed, but over plain HTTP or with an absolute URL
        N-->>C: 400 (the guard)
    else everything else
        N->>V: phase 1: headers
        alt no Signature-Input and no Signature header
            V->>V: outcome not-signed, skip the verifier
        else signed
            V->>V: parse the headers, check the times, coverage,<br/>key and signature (next diagram)
            V->>V: outcome verified, invalid or unverified, with a reason
        end
        opt the signature covers the body
            V->>V: phase 2: hash the body and compare
        end
        V->>R: outcome in tx.wba_status, tx.wba_reason, tx.wba_agent ...
        alt a rule refuses the request
            R-->>C: 403, 429 or 400
        else allowed
            R->>A: request
            A-->>C: response
        end
        Note over V: phase 5: one JSON log line for every signed request
    end
```

A signature header that cannot be parsed at all is ignored by default, so the request counts as unsigned (RFC 9651 section 4.2); with `tx.wba_malformed=reject` it gets **400** from rule 9534107 instead. A body digest header that the signature covers is different: if it cannot be parsed, the request is always `invalid/malformed-digest` and gets **400** from the same rule. Only a good signature from a bot you list gets that far, and ignoring the header would leave the body unchecked while the signature says it covers it.

## 4. How the verifier decides

The verifier checks each signature tagged `web-bot-auth` on its own, and the request gets the best result among them.

```mermaid
flowchart TD
    S([Signed request]) --> P{Headers parse?}
    P -- no --> M["not-signed / unparsable-field (default)<br/>or invalid / malformed-headers and 400<br/>(tx.wba_malformed=reject)"]
    P -- yes --> T{A signature tagged<br/>web-bot-auth?}
    T -- no --> NS[not-signed]
    T -- yes --> H{"Host is one of<br/>your site names?"}
    H -- no --> I0["invalid / foreign-authority<br/>(unverified / no-site-names if none set)"]
    H -- yes --> W{"signed at most 1 h ago,<br/>not expired,<br/>window within any cap you set?"}
    W -- no --> I1["invalid / expired, too-old, not-yet-valid,<br/>window-too-long, missing-param"]
    W -- yes --> CV{"Covers the site name and<br/>its Signature-Agent entry?"}
    CV -- no --> I2["invalid / authority-not-covered,<br/>agent-not-covered"]
    CV -- yes --> K{"Key store holds this bot's key,<br/>looked up by (bot URL, keyid)?"}
    K -- no --> U1["unverified / unknown-agent, unknown-key<br/>(a bot you don't list, or a stale store)"]
    K -- yes --> SIG{"Signature matches the<br/>rebuilt signature base?"}
    SIG -- no --> I3[invalid / bad-signature]
    SIG -- yes --> D{Covers a body digest?}
    D -- no --> OK([verified])
    D -- yes --> B{"Body matches the digest?<br/>(phase 2)"}
    B -- yes --> OK
    B -- no --> I4[invalid / digest-mismatch]
    D -- "yes, but the digest<br/>header does not parse" --> I5["invalid / malformed-digest<br/>and 400 (phase 1)"]
```

What the four outcomes mean for your rules:

| Outcome | Means | Typical use |
|---|---|---|
| `verified` | A bot you listed signed this request with a current key, and the signature is genuine. It says who signed, not that the request is harmless: CRS still inspects it. | Grant or exempt (recipes A and C). |
| `invalid` | A check failed. `foreign-authority` (made for another site), `bad-signature`, `digest-mismatch` and `test-key` mean the signature cannot be genuine for this request; the rest are usually a misconfigured bot. | Refuse only the "cannot be genuine" reasons (recipe F). |
| `unverified` | The verifier could not decide: the bot is not in your `agents.txt`, its key is new, or your site names are not set (`no-site-names`). | Treat as unsigned. |
| `not-signed` | No Web Bot Auth signature. | Your normal bot handling. |

The full list of reasons is in the [README](README.md#outcomes-and-reasons).

## 5. How the outcome reaches CRS and your rules

The verifier runs as CRS's **before** plugin, so its outcome exists before any CRS rule runs. Your own rules go in a `*-after.conf` file and run after CRS in the same phase. The plugin itself blocks nothing except broken protocol: the guard's 400, and rule 9534107's 400. That rule answers a covered body digest header that cannot be parsed, always, and an unparsable signature header only if you choose `tx.wba_malformed=reject`.

```mermaid
flowchart LR
    subgraph P1["Phase 1: headers"]
        G["Guard<br/>(nginx, before ModSecurity)"] --> V1["Verifier<br/>web-bot-auth-before.conf"]
    end
    subgraph P2["Phase 2: body"]
        V2["Body digest check<br/>(only if signed over the body)"] --> CRS["CRS attack rules<br/>(phases 1 and 2, always run)"]
        CRS --> YR["Your rules and recipes<br/>*-after.conf"]
    end
    subgraph P5["Phase 5: after the response"]
        LOG["One JSON log line<br/>per signed request"]
    end
    V1 -- "tx.wba_status, tx.wba_reason,<br/>tx.wba_agent, tx.wba_granted" --> V2
    YR -- "e.g. recipe C sets<br/>tx.bot_management_exempt=1" --> BM["Your bot management"]
    YR --> LOG
```

The recipes, in one line each:

| Recipe | Does |
|---|---|
| A | On paths reserved for bots, refuse anything not `verified` and ask for a signature (403 with `Accept-Signature`). |
| B | If the User-Agent claims to be a given bot, require that bot's signature. |
| C | Mark granted bots so your own bot management can exempt them (never CRS attack detection). |
| D | With replay accounting on, allow a signed statement once on the bot paths. |
| E | With replay accounting on, allow a nonce once anywhere. |
| F | Refuse signatures that cannot be genuine: `foreign-authority`, `bad-signature`, `digest-mismatch`, `test-key`. |

## 6. Asking a bot to sign

When recipe A refuses an unsigned request, nginx answers 403 with an `Accept-Signature` header that tells the bot what to sign, including a fresh nonce. ModSecurity cannot add response headers, so the rule uses the private status 460 and an nginx file turns it into the 403.

```mermaid
sequenceDiagram
    autonumber
    participant B as Bot
    participant N as nginx
    participant M as ModSecurity (recipe A)
    B->>N: GET /agents/x (unsigned)
    N->>M: check
    M-->>N: deny with status 460
    N-->>B: 403 with Accept-Signature: what to sign, a nonce, tag web-bot-auth
    Note over B: signs the request as asked
    B->>N: GET /agents/x (signed)
    N->>M: check: verified
    M->>N: allow
    N-->>B: 200 from your application
```

The verifier does not check that the nonce returned is the one nginx issued; [DESIGN.md](DESIGN.md#asking-for-a-signature-in-detail) explains why.

## Protections added on 2026-10-09

Decided after a point-by-point review of RFC 9421 and draft -00 against this code and confirmed by an independent review. Each is a setting in [web-bot-auth-config.conf](web-bot-auth-config.conf).

1. **Your site names** (`tx.wba_site_names`, required). A signature names the site it was made for, from the Host the bot sent. You list your own names once; a signature made for any other name is `invalid/foreign-authority`. Until the list is set, nothing verifies.
2. **One hour** (`tx.wba_max_age`, default 3600). A signature counts for at most an hour after the bot signed it, and never past its own expiry, whatever window the bot declared. Because this bounds every signature, the window the bot declares has no cap by default (with `tx.wba_max_age=0`, the cap is a day).
3. **Expiry, strict or graceful** (`tx.wba_expiry_grace`, default 0). Strict by default; up to 60 seconds of leeway for clocks a little behind the bot's.
4. **Unparsable signature headers** (`tx.wba_malformed`, default `ignore`). RFC 9651 section 4.2 allows ignoring the header or treating the request as malformed. Ignoring it is the default, so other signature formats, such as ActivityPub's, pass as unsigned; `reject` gives the 400. This setting covers `Signature-Input`, `Signature` and `Signature-Agent` only, not a covered body digest header (section 3).
5. **What a grant needs** (`tx.wba_grant_require_components`, default `@method @path`). A signature over the site name alone works for any page, so it is not granted.

Bot lists sit beside the signature check: `wba-keysync/lists.ts` fetches each bot operator's published IP ranges and writes plain SecRules from them and the User-Agent tokens, so a request carries `tx.bot_status` next to the signature outcome (claimed by its User-Agent; verified by the bot's IP list or its signature) and your policy for the bot can act on it. The ranges are compiled when the WAF starts, so a request never waits on a fetch or a DNS lookup. Reverse DNS, for the few operators that publish only host names, comes later and runs offline in the sync tool, never inside a request (`wba-keysync/BOTS.md` says why this project does not use CRS's fake-bot plugin).

How the first change stops the replay:

```mermaid
sequenceDiagram
    autonumber
    participant B as Real bot
    participant E as evil.example (attacker's site)
    participant Y as Your site (example.com)
    B->>E: signed request, site name evil.example
    Note over E: the attacker keeps a copy of the signature headers
    E->>Y: the same headers, with Host: evil.example
    alt without site names checked
        Y->>Y: signature genuine, outcome verified (wrong)
    else your site names are example.com and www.example.com
        Y->>Y: evil.example is not one of your names: invalid / foreign-authority
    end
```
