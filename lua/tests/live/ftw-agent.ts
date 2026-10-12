// ftw-agent.ts: the test bot that go-ftw sends its requests through, so the
// YAML tests in tests/regression can make real signed requests. go-ftw copies
// header values as written (it templates only `data`), and a signature has to
// be made when the request is sent. A test asks for one with a header:
//
//   X-WBA-Sign: valid        signed now by the test bot (wba-keysync/sign.ts init)
//   X-WBA-Sign: expired      signed 10 minutes ago, expired 5 minutes ago
//   X-WBA-Sign: tampered     a valid signature with one byte changed
//   X-WBA-Sign: unknown-key  signed by a key the WAF's key store does not hold
//
// The agent drops that line, adds Signature-Agent, Signature-Input and
// Signature (@method, @authority from Host, @path and the Signature-Agent
// member, as sign.ts curl does) and sends the request on over TLS. It changes
// nothing else: every other byte, the log marker requests included, passes
// through as go-ftw wrote it. One request per connection, as go-ftw sends.
//
//   bun lua/tests/live/ftw-agent.ts <port> <WAF TLS port> <dir from sign.ts init>
//
// Prints "ready" once it listens. A request it cannot sign gets status 599.
import net from "node:net";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { signRequest, storeFor } from "../../../wba-keysync/sign.ts";

const [port, wafPort, dir] = process.argv.slice(2);
if (!port || !wafPort || !dir) { console.error("usage: ftw-agent.ts <port> <WAF TLS port> <dir>"); process.exit(1); }

const { agent, ...priv } = JSON.parse(readFileSync(join(dir, "test-agent-key.json"), "utf8"));
const now = () => Math.floor(Date.now() / 1000);
const keyid = (await storeFor({ kty: priv.kty, crv: priv.crv, x: priv.x }, agent, now())).keyid;
// A second key, made here and never written down: no key store can hold it.
const other = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
const otherPriv = await crypto.subtle.exportKey("jwk", other.privateKey);
const otherKeyid = (await storeFor({ kty: "OKP", crv: "Ed25519", x: otherPriv.x }, agent, now())).keyid;

const MODES = new Set(["valid", "expired", "tampered", "unknown-key"]);
const HEAD_MAX = 65536;

/** The request head with the X-WBA-Sign line swapped for the signature headers. */
async function sign(head: string): Promise<string> {
  const lines = head.split("\r\n");
  const i = lines.findIndex((l) => /^x-wba-sign:/i.test(l));
  if (i < 0) return head;
  const mode = lines[i].slice(lines[i].indexOf(":") + 1).trim();
  if (!MODES.has(mode)) throw new Error(`unknown X-WBA-Sign mode "${mode}"`);
  const [method, target] = lines[0].split(" ");
  const host = lines.find((l) => /^host:/i.test(l))?.replace(/^host:\s*/i, "").trim();
  if (!method || !target || !host) throw new Error("a signed request needs a request line and a Host");
  const t = now();
  const s = await signRequest({
    priv: mode === "unknown-key" ? otherPriv : priv, keyid: mode === "unknown-key" ? otherKeyid : keyid,
    agent, url: new URL(target, `https://${host}`), method, host,
    now: mode === "expired" ? t - 600 : t, expires: 300,
  });
  let signature = s.headers.Signature;
  if (mode === "tampered") { // flip one bit of the first signature byte: still base64, no longer valid
    const bytes = Buffer.from(signature.slice("sig1=:".length, -1), "base64");
    bytes[0] ^= 1;
    signature = `sig1=:${bytes.toString("base64")}:`;
  }
  lines.splice(i, 1, `Signature-Agent: ${s.headers["Signature-Agent"]}`,
    `Signature-Input: ${s.headers["Signature-Input"]}`, `Signature: ${signature}`);
  return lines.join("\r\n");
}

const server = net.createServer((client) => {
  let buf = Buffer.alloc(0);
  let upstream: tls.TLSSocket | undefined;
  const refuse = (why: string) => {
    console.error(`ftw-agent: ${why}`);
    client.end(`HTTP/1.1 599 ftw-agent\r\nContent-Type: text/plain\r\nContent-Length: ${why.length + 1}\r\nConnection: close\r\n\r\n${why}\n`);
  };
  const onData = async (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    const end = buf.indexOf("\r\n\r\n");
    if (end < 0) { if (buf.length > HEAD_MAX) refuse("request head over 64 KiB"); return; }
    client.off("data", onData);
    client.pause();
    let head: string;
    try { head = await sign(buf.subarray(0, end).toString("latin1")); } catch (e) { refuse((e as Error).message); return; }
    // rejectUnauthorized: false only because the peer is the local test
    // container's self-signed certificate on 127.0.0.1. Never copy this.
    upstream = tls.connect({ host: "127.0.0.1", port: Number(wafPort), servername: "localhost", rejectUnauthorized: false, ALPNProtocols: ["http/1.1"] }, () => {
      upstream!.write(Buffer.concat([Buffer.from(head, "latin1"), buf.subarray(end)]));
      client.pipe(upstream!);
      client.resume();
    });
    upstream.pipe(client);
    upstream.on("error", (e) => { console.error(`ftw-agent: WAF: ${e.message}`); client.destroy(); });
  };
  client.on("data", onData);
  client.on("error", () => upstream?.destroy());
  client.on("close", () => upstream?.end());
});
server.listen(Number(port), "127.0.0.1", () => console.log("ready"));
