// bot-server.ts: a test bot's key service, for registry.sh. Serves one JWK
// Set over HTTPS at the well-known key directory path, as a bot operator
// publishes it (draft 5.5), and logs each fetch on stdout so the test can see
// key sync come over the network. The JWK Set is read on every request, so
// replacing the file rotates the bot's keys. No caching (max-age=0): key sync
// revalidates on every run. A file <jwks.json>.ctl, when present, makes the
// server misbehave as a broken operator might: JSON with any of "status",
// "contentType" and "location" (a redirect). Read on every request too.
//   bun lua/tests/live/bot-server.ts <port> <jwks.json> <cert.pem> <key.pem> [path]
// With a path it serves the file there instead (bot-lists.sh: an operator's
// published IP list).
// Bun only (Bun.serve).

import { existsSync, readFileSync } from "node:fs";
import { MEDIA_TYPE, WELL_KNOWN } from "../../../wba-keysync/keysync.ts";

const [port, jwks, cert, key, at = WELL_KNOWN] = process.argv.slice(2);
if (!port || !jwks || !cert || !key) {
  console.error("usage: bot-server.ts <port> <jwks.json> <cert.pem> <key.pem> [path]");
  process.exit(1);
}
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: Number(port),
  tls: { cert: readFileSync(cert, "utf8"), key: readFileSync(key, "utf8") },
  fetch(req) {
    const path = new URL(req.url).pathname;
    console.log(`bot-server ${port}: ${req.method} ${path}`);
    if (path !== at) return new Response("not found", { status: 404 });
    const ctl = existsSync(`${jwks}.ctl`) ? JSON.parse(readFileSync(`${jwks}.ctl`, "utf8")) as { status?: number; contentType?: string; location?: string } : {};
    const headers: Record<string, string> = { "content-type": ctl.contentType ?? MEDIA_TYPE, "cache-control": "max-age=0" };
    if (ctl.location) headers.location = ctl.location;
    return new Response(ctl.status && ctl.status >= 300 && ctl.status < 400 ? null : readFileSync(jwks), { status: ctl.status ?? 200, headers });
  },
});
console.log(`bot-server ${port}: listening on https://localhost:${server.port}`);
