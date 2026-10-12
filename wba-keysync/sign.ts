// wba-sign: a test bot, for trying the verifier and checking a deployment.
// Not a production signer: the key sits in a file beside the store.
//
//   bun wba-keysync/sign.ts init <dir> [--agent https://test-agent.example]
//     Makes an Ed25519 key (<dir>/test-agent-key.json, mode 600), its public
//     JWK Set (<dir>/test-agent.jwks.json) and a key store that lists it
//     under the agent (<dir>/keys/wba-keys.tsv), for a WAF that mounts
//     <dir>/keys. A real deployment lists the agent in agents.txt and lets
//     wba-keysync fetch the JWK Set from where you serve it instead.
//
//   bun wba-keysync/sign.ts curl <url> --dir <dir> [--host example.com] [--method GET] [--insecure]
//                                [--agent URL] [--expires SECONDS]
//     Prints a curl command for one signed request: @method, @authority,
//     @path and the Signature-Agent member, with created, expires (300 s
//     by default), keyid, alg, a nonce and tag="web-bot-auth" (draft 5.2).
//     --host signs that name as @authority and sends it as Host, so a test
//     against https://localhost:8443 can stand for your site. Pipe the
//     output to sh to send it; it prints the HTTP status.
//
//   node wba-keysync/sign.ts ...  (as cli.ts: needs native type stripping)

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DEFAULT_LIMITS, format, identifier, keysFromDirectory } from "./keysync.ts";

const DEFAULT_AGENT = "https://test-agent.example";

function fail(msg: string): never {
  console.error(`wba-sign: ${msg}
usage: wba-sign init <dir> [--agent URL]
       wba-sign curl <url> --dir <dir> [--host NAME] [--method GET] [--agent URL] [--expires SECONDS] [--insecure]`);
  process.exit(1);
}

/** POSIX shell single-quoting. */
const q = (s: string) => `'${s.replaceAll("'", `'\\''`)}'`;
const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");

/** The key store for one Ed25519 public key, listed under the agent's directory. */
export async function storeFor(pub: JsonWebKey, agent: string, now: number): Promise<{ text: string; keyid: string }> {
  const id = identifier(agent);
  if (!id) throw new Error(`${agent} is not an https origin`);
  const warnings: string[] = [];
  const entries = await keysFromDirectory({ keys: [pub] }, DEFAULT_LIMITS, now, (m) => warnings.push(m), true);
  if (entries.length !== 1) throw new Error(`key not usable: ${warnings.join("; ")}`);
  return { text: format([{ ...entries[0], identifier: id }], new Date(now * 1000)), keyid: entries[0].keyid };
}

export interface Signed { authority: string; headers: Record<string, string>; base: string }

/** RFC 9421 2.5: the signature base and headers for one request. */
export async function signRequest(o: {
  priv: JsonWebKey; keyid: string; agent: string; url: URL; method: string; host?: string; now: number; expires: number;
}): Promise<Signed> {
  // RFC 9421 2.2.3: lowercase host, and the port unless it is the scheme's default.
  const authority = (o.host ?? o.url.host).toLowerCase();
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const member = JSON.stringify(o.agent); // an sf-string: the URL has no '"' or '\' (identifier() checked)
  const comps = `("@method" "@authority" "@path" "signature-agent";key="sig1")`;
  const params = `${comps};created=${o.now};expires=${o.now + o.expires};keyid="${o.keyid}";alg="ed25519"`
    + `;nonce="${nonce}";tag="web-bot-auth"`;
  const base = [
    `"@method": ${o.method}`,
    `"@authority": ${authority}`,
    `"@path": ${o.url.pathname}`,
    `"signature-agent";key="sig1": ${member}`,
    `"@signature-params": ${params}`,
  ].join("\n");
  const key = await crypto.subtle.importKey("jwk", o.priv, { name: "Ed25519" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(base)));
  const headers: Record<string, string> = {
    "Signature-Agent": `sig1=${member}`,
    "Signature-Input": `sig1=${params}`,
    Signature: `sig1=:${Buffer.from(sig).toString("base64")}:`,
  };
  if (o.host) headers.Host = o.host;
  return { authority, headers, base };
}

async function init(dir: string, agent: string) {
  const kp = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const full = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const pub = { kty: full.kty, crv: full.crv, x: full.x }; // RFC 8037 2: all a directory needs
  const { text, keyid } = await storeFor(pub, agent, Math.floor(Date.now() / 1000));
  mkdirSync(join(dir, "keys"), { recursive: true });
  const keyPath = join(dir, "test-agent-key.json");
  // Created 0600 under a new name, never readable by others even briefly, then
  // renamed into place: a symlink at keyPath is replaced, never written through.
  const tmp = `${keyPath}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ ...priv, agent }) + "\n", { mode: 0o600, flag: "wx" });
  renameSync(tmp, keyPath);
  writeFileSync(join(dir, "test-agent.jwks.json"), JSON.stringify({ keys: [pub] }, null, 1) + "\n");
  writeFileSync(join(dir, "keys", "wba-keys.tsv"), text);
  console.log(`test agent ${agent}, keyid ${keyid}
  private key  ${keyPath} (mode 600)
  JWK Set      ${join(dir, "test-agent.jwks.json")}
  key store    ${join(dir, "keys", "wba-keys.tsv")} (mount ${join(dir, "keys")} at /etc/modsecurity.d/wba/keys)
Never list this agent in tx.wba_grant_agents on a real site.`);
}

async function curl(url: string, opts: Map<string, string>) {
  const dir = opts.get("--dir") ?? fail("--dir is required");
  let target: URL;
  try { target = new URL(url); } catch { fail(`not a URL: ${url}`); }
  const stored = JSON.parse(readFileSync(join(dir, "test-agent-key.json"), "utf8"));
  const agent = opts.get("--agent") ?? stored.agent ?? DEFAULT_AGENT;
  const { agent: _, ...priv } = stored;
  const pub = { kty: priv.kty, crv: priv.crv, x: priv.x };
  const now = Math.floor(Date.now() / 1000);
  const { keyid } = await storeFor(pub, agent, now);
  const expires = Number(opts.get("--expires") ?? 300);
  if (!Number.isInteger(expires) || expires < 1 || expires > 86400) fail("--expires must be 1 to 86400 seconds");
  const method = (opts.get("--method") ?? "GET").toUpperCase();
  const s = await signRequest({ priv, keyid, agent, url: target, method, host: opts.get("--host"), now, expires });
  // -k only on request: the Quick start's certificate is self-signed, a real site's is not.
  const args = ["curl", "-s", ...(opts.has("--insecure") ? ["-k"] : []), "-o", "/dev/null", "-w", "%{http_code}\\n", "-X", method];
  for (const [k, v] of Object.entries(s.headers)) args.push("-H", `${k}: ${v}`);
  args.push(target.origin + target.pathname + target.search);
  console.log(args.map((a, i) => (i === 0 ? a : q(a))).join(" "));
}

async function main(argv: string[]) {
  const [cmd, first, ...rest] = argv;
  const opts = new Map<string, string>();
  for (let i = 0; i < rest.length; i += 2) {
    if (rest[i] === "--insecure") { opts.set(rest[i], ""); i--; continue; } // a flag, no value
    if (!rest[i].startsWith("--") || rest[i + 1] === undefined) fail(`bad option ${rest[i]}`);
    opts.set(rest[i], rest[i + 1]);
  }
  if (cmd === "init" && first) return init(first, opts.get("--agent") ?? DEFAULT_AGENT);
  if (cmd === "curl" && first) return curl(first, opts);
  fail("unknown command");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2)).catch((e) => fail((e as Error).message));
}
