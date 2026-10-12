/**
 * interop.ts: the verifier against the LATEST third-party signer, Cloudflare's
 * npm package web-bot-auth (the reference implementation), and Stytch's
 * example recipe. Driven by interop.sh, which installs web-bot-auth@latest.
 * Steps, chosen by the first argument:
 *
 *   init     create an operator's own interop key: KEY_DIR/interop-key.json
 *            (private, keep it on the test host) and KEY_DIR/interop.jwks.json
 *            (public, to serve from an https URL you control)
 *   prepare  write OUT/cases.json: requests signed by web-bot-auth now (and,
 *            against the test container, OUT/keys/wba-keys.tsv, written by
 *            wba-keysync's own code as in production)
 *   send     send every case in OUT/cases.json to TARGET
 *   check    match OUT/log.txt (the WAF's JSON log lines) with each case's
 *            expected outcome; exit 1 on any mismatch
 *
 * Two modes:
 *   - test container (TARGET unset): a fresh key, a key store written here,
 *     https://127.0.0.1:TLS_PORT;
 *   - a deployed WAF (TARGET=https://www.example.com): the operator's interop
 *     key (INTEROP_KEY, from init), listed in agents.txt as INTEROP_AGENT and
 *     never granted anything, and the operator's own log (interop.sh LOGS).
 * Every case goes to a unique path under /.well-known/wba-interop/<run>/, so
 * its log line is found by its uri.
 */
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_LIMITS, format, identifier, keysFromDirectory, type StoreEntry } from "../../../wba-keysync/keysync.ts";

const step = process.argv[2];
const env = (name: string) => process.env[name] || undefined;
function must(name: string): string {
  const v = env(name);
  if (!v) throw new Error(`${name} is required`);
  return v;
}

interface Case { name: string; method: string; path: string; headers: Record<string, string>; expect: string; note: string }

async function newKey() {
  const kp = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  // A key directory needs only {kty, crv, x} (RFC 8037 2).
  return { priv, pub: { kty: pub.kty!, crv: pub.crv!, x: pub.x! } };
}

async function init() {
  const dir = must("KEY_DIR");
  mkdirSync(dir, { recursive: true });
  const k = await newKey();
  const privPath = join(dir, "interop-key.json"), pubPath = join(dir, "interop.jwks.json");
  writeFileSync(privPath, JSON.stringify(k.priv));
  chmodSync(privPath, 0o600);
  writeFileSync(pubPath, JSON.stringify({ keys: [k.pub] }, null, 1) + "\n");
  console.log(`private key: ${privPath} (mode 600; keep it on the host that runs interop.sh)
public key set: ${pubPath}

Serve the public key set from an https URL you control, as JSON, then add
that URL to agents.txt and let key sync pick it up:

  https://www.example.com/.well-known/wba-interop.jwks.json type=jwks_uri

Never add it to tx.wba_grant_agents: the interop agent must be granted nothing.`);
}

async function upstream() {
  const dir = must("NPM_DIR");
  const lib = await import(Bun.resolveSync("web-bot-auth", dir));
  const cryptoLib = await import(Bun.resolveSync("web-bot-auth/crypto", dir));
  const version = JSON.parse(readFileSync(join(dir, "node_modules/web-bot-auth/package.json"), "utf8")).version as string;
  return { lib, cryptoLib, version };
}

async function prepare() {
  const OUT = must("OUT");
  const { lib, cryptoLib, version } = await upstream();
  const deployed = !!env("TARGET");
  const target = new URL(env("TARGET") ?? `https://127.0.0.1:${must("TLS_PORT")}`);
  const run = env("RUN_ID") ?? crypto.randomUUID().slice(0, 8);
  const base = `/.well-known/wba-interop/${run}`;
  const now = Math.floor(Date.now() / 1000);

  // The listed key and the agent it is published under.
  let listedPriv: JsonWebKey, agent: string, type: "directory" | "jwks_uri";
  if (deployed) {
    listedPriv = JSON.parse(readFileSync(must("INTEROP_KEY"), "utf8"));
    agent = must("INTEROP_AGENT");
    const p = new URL(agent).pathname;
    type = (env("INTEROP_AGENT_TYPE") as "directory" | "jwks_uri") ?? (p === "/" || p === "" ? "directory" : "jwks_uri");
  } else {
    const k = await newKey();
    listedPriv = k.priv;
    agent = "https://interop.example";
    type = "directory";
    const warnings: string[] = [];
    const entries = await keysFromDirectory({ keys: [k.pub] }, DEFAULT_LIMITS, now, (m) => warnings.push(m), true);
    if (entries.length !== 1) throw new Error(`key-sync kept ${entries.length} keys: ${warnings.join("; ")}`);
    const id = identifier(agent);
    if (!id) throw new Error(`no identifier for ${agent}`);
    const store: StoreEntry[] = entries.map((e) => ({ ...e, identifier: id }));
    mkdirSync(join(OUT, "keys"), { recursive: true });
    writeFileSync(join(OUT, "keys", "wba-keys.tsv"), format(store, new Date()));
  }
  const listed = await cryptoLib.signerFromJWK(listedPriv);
  const unlisted = await cryptoLib.signerFromJWK((await newKey()).priv);
  const dictionary = `sig1="${agent}";type=${type}`;
  const t = (s: number) => new Date((now + s) * 1000);

  const cases: Case[] = [];
  async function add(name: string, expect: string, note: string, o: {
    agentHeader?: string; signer?: unknown; created?: Date; expires?: Date; nonce?: boolean;
    target?: "@authority" | "@target-uri"; extra?: string[]; sendAs?: string;
  } = {}) {
    const path = `${base}/${name}`;
    const agentHeader = o.agentHeader ?? dictionary;
    const req = new Request(new URL(path, target), { headers: { "Signature-Agent": agentHeader } });
    let fields: { signature: string; signatureInput: string };
    try {
      fields = await lib.sign(req, {
        signer: o.signer ?? listed, created: o.created ?? t(0), expires: o.expires ?? t(300),
        ...(o.nonce === false ? {} : { nonce: lib.generateNonce() }),
        ...(o.target ? { target: o.target } : {}),
        ...(o.extra ? { additionalComponents: o.extra } : {}),
      });
    } catch (e) {
      cases.push({ name, method: "GET", path, headers: {}, expect: "skip", note: `web-bot-auth cannot sign this: ${(e as Error).message}` });
      return;
    }
    cases.push({
      name, method: "GET", path: o.sendAs ? `${base}/${o.sendAs}` : path, expect, note,
      headers: { "Signature-Agent": agentHeader, "Signature-Input": fields.signatureInput, Signature: fields.signature },
    });
  }

  await add("default", "verified/", "the library's defaults: @authority and the Signature-Agent member, 300 s, 64-byte nonce");
  await add("no-nonce", "verified/", "no nonce (draft -00 5.2.3 sets no nonce requirement)", { nonce: false });
  await add("target-uri", "verified/", "@target-uri in place of @authority", { target: "@target-uri" });
  await add("method-path", "verified/", "also covers @method and @path", { extra: ["@method", "@path"] });
  await add("tampered-path", "invalid/bad-signature", "covers @path, sent to another path", { extra: ["@path"], sendAs: "tampered-path-elsewhere" });
  await add("expired", "invalid/expired", "expired 300 s ago", { created: t(-600), expires: t(-300) });
  await add("unknown-key", "unverified/unknown-key", "signed with a key the agent never published", { signer: unlisted });

  if (type === "directory") {
    // The legacy sf-string form names an origin's well-known directory, as
    // does Stytch's example, so these need a directory-type agent.
    await add("legacy-agent", "verified/", "legacy sf-string Signature-Agent (draft 5.2.1 MAY)", { agentHeader: `"${agent}"` });

    // Stytch's example (github.com/stytchauth/web-bot-auth-example, MIT): its
    // createWebBotAuthHeaders is not exported and runs inside a Puppeteer
    // script, so its recipe is reproduced exactly: @authority is the hostname
    // alone (port dropped), a UUID nonce, a 24 h window, the legacy
    // Signature-Agent, standard base64. interop.sh reports when it changes.
    const keyid = (await keysFromDirectory({ keys: [publicOf(listedPriv)] }, DEFAULT_LIMITS, now, () => {}, true))[0]?.keyid;
    async function stytch(name: string, expect: string, note: string, host?: string) {
      const params = ['("@authority" "signature-agent")', `keyid="${keyid}"`, 'alg="ed25519"',
        `created=${now}`, `expires=${now + 86400}`, `nonce="${crypto.randomUUID()}"`, 'tag="web-bot-auth"'].join(";");
      const signed = `"@authority": ${target.hostname}\n"signature-agent": "${agent}"\n"@signature-params": ${params}`;
      const key = await crypto.subtle.importKey("jwk", listedPriv, { name: "Ed25519" }, false, ["sign"]);
      const sig = Buffer.from(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(signed)))).toString("base64");
      cases.push({
        name, method: "GET", path: `${base}/${name}`, expect, note,
        headers: { ...(host ? { Host: host } : {}), "Signature-Agent": `"${agent}"`, "Signature-Input": `sig1=${params}`, Signature: `sig1=:${sig}:` },
      });
    }
    if (!target.port) await stytch("stytch-recipe", "verified/", "Stytch's recipe on the default port");
    else {
      await stytch("stytch-recipe", "verified/", "Stytch's recipe, Host without a port as on 443", target.hostname);
      await stytch("stytch-recipe-port", "invalid/bad-signature", "Stytch's recipe on a non-default port: it signs the hostname without the port (its defect, RFC 9421 2.2.3)");
    }
  }

  writeFileSync(join(OUT, "cases.json"), JSON.stringify({ upstream: `web-bot-auth@${version}`, target: target.origin, run, cases }, null, 1));
  console.log(`prepared ${cases.length} cases with web-bot-auth@${version} for ${target.origin} (run ${run})`);
}

/** The public members of a private Ed25519 JWK. */
const publicOf = (j: JsonWebKey) => ({ kty: j.kty!, crv: j.crv!, x: j.x! });

function send() {
  const OUT = must("OUT");
  const { target, cases } = JSON.parse(readFileSync(join(OUT, "cases.json"), "utf8")) as { target: string; cases: Case[] };
  for (const c of cases) {
    if (c.expect === "skip") continue;
    // curl, as the live suite does. -k only for the local test container,
    // whose certificate is self-signed; a deployed site is verified as usual.
    const args = ["curl", "-s", "-o", "/dev/null", "--max-time", "10", "-X", c.method];
    if (!env("TARGET")) args.push("-k");
    for (const [k, v] of Object.entries(c.headers)) args.push("-H", `${k}: ${v}`);
    args.push(`${target}${c.path}`);
    const r = Bun.spawnSync(args);
    if (r.exitCode !== 0) console.error(`send ${c.name}: curl exit ${r.exitCode}`);
  }
}

function check() {
  const OUT = must("OUT");
  const { upstream: up, target, run, cases } = JSON.parse(readFileSync(join(OUT, "cases.json"), "utf8")) as
    { upstream: string; target: string; run: string; cases: Case[] };
  // The WAF's own log: one JSON line per signed request (wba_log.lua),
  // possibly behind a prefix your log pipeline adds.
  const byUri = new Map<string, { status: string; reason: string }>();
  for (const line of readFileSync(join(OUT, "log.txt"), "utf8").split("\n")) {
    const at = line.indexOf('{"event":"web-bot-auth"');
    if (at < 0) continue;
    try {
      const j = JSON.parse(line.slice(at));
      byUri.set(j.uri, { status: j.status, reason: j.reason ?? "" });
    } catch { /* a line cut by the log pipeline */ }
  }
  let failed = 0;
  console.log(`== interop: ${target} against ${up} (run ${run})`);
  for (const c of cases) {
    if (c.expect === "skip") { console.log(`SKIP  ${c.name}: ${c.note}`); continue; }
    const hit = byUri.get(c.path);
    const got = hit ? `${hit.status}/${hit.reason}` : "no log line";
    const ok = got === c.expect;
    if (!ok) failed++;
    console.log(`${ok ? "PASS" : "FAIL"}  ${c.name}: expected ${c.expect}, got ${got} (${c.note})`);
  }
  const ran = cases.filter((c) => c.expect !== "skip").length;
  console.log(`== ${ran - failed} of ${ran} as expected, against ${up}`);
  if (failed) process.exit(1);
}

if (step === "init") await init();
else if (step === "prepare") await prepare();
else if (step === "send") send();
else if (step === "check") check();
else { console.error("usage: bun interop.ts init|prepare|send|check"); process.exit(2); }
