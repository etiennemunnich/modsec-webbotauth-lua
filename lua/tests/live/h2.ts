// h2.ts: one HTTP/2 request with an explicit :authority and, optionally, a
// separate host header, for run.sh and paranoia.sh. curl cannot send both. The
// headers come from gen.lua (PRINT=1) on stdin, one "Name: value" per line,
// with its :method and :path; any Host line is dropped so only the arguments
// decide the authority.
//
//   ... | TLS_PORT=18896 node lua/tests/live/h2.ts <case> <:authority> [host]
//
// Prints "<case> <status>", or "<case> error <code>". Never waits more than 5 s.
import http2 from "node:http2";
import { readFileSync } from "node:fs";

const [name, authority, host] = process.argv.slice(2);
const done = (s: string) => { console.log(`${name} ${s}`); process.exit(0); };
setTimeout(() => done("error timeout"), 5000).unref();

// A User-Agent and an Accept, as real clients send (gen.lua's own, when it has them, replace these).
const headers: Record<string, string | string[]> = { ":method": "GET", ":path": "/", ":authority": authority, "x-wba-test": name, "user-agent": "wba-live-test", "accept": "*/*" };
// A name given twice is sent twice, in order (RFC 9421 2.1 combines them).
// gen.lua's :method and :path lines set those pseudo-headers.
const seen = new Set<string>();
for (const line of readFileSync(0, "utf8").split("\n")) {
  const i = line.indexOf(": ");
  const key = line.slice(0, i).toLowerCase();
  if (i <= 0 || key === "host") continue;
  const value = line.slice(i + 2), prev = headers[key];
  if (key.startsWith(":") || !seen.has(key)) headers[key] = value;
  else headers[key] = [...(Array.isArray(prev) ? prev : [prev ?? ""]), value];
  seen.add(key);
}
if (host) headers["host"] = host;

// rejectUnauthorized: false only because the peer is the local test container's
// self-signed certificate on 127.0.0.1 (curl -k, same reason). Never copy this.
const client = http2.connect(`https://127.0.0.1:${process.env.TLS_PORT}`, { rejectUnauthorized: false });
client.on("error", (e: NodeJS.ErrnoException) => done(`error ${e.code}`));
const req = client.request(headers);
req.on("response", (h) => done(String(h[":status"])));
req.on("error", (e: NodeJS.ErrnoException) => done(`error ${e.code}`));
req.end();
