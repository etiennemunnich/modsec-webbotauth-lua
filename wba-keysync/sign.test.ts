// sign.test.ts: wba-keysync/sign.ts, checked by the Lua verifier itself (so
// a mistake shared by signer and test cannot pass). Runs unchanged under
// `bun test` and `node --test`; needs lua 5.3+ ($LUA, as run_all.sh sets it,
// else lua) and openssl on PATH, as the Lua suites do. Without that Lua the
// test is reported as skipped, never as a pass. test.skip, not the { skip }
// option: bun test 1.3 ignores the option and runs the test anyway.
import { test } from "node:test";
import assert from "node:assert/strict";
import { lstatSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { signRequest, storeFor } from "./sign.ts";

const REPO = new URL("..", import.meta.url).pathname;
const AGENT = "https://test-agent.example";
const LUA = process.env.LUA || "lua";
const HAVE_LUA = spawnSync(LUA, ["-v"]).status === 0;

// Reads the store and one request from files, prints status/reason agent.
const VERIFY = `
package.path = "${REPO}lua/tests/?.lua;${REPO}lua/?.lua;" .. package.path
local H, verify, keys, json = require("helpers"), require("wba.verify"), require("wba.keys"), require("json")
local function read(p) local f = assert(io.open(p)); local s = f:read("a"); f:close(); return s end
local store = assert(keys.parse(read(arg[1])))
local t = json.decode(read(arg[2]))
local headers = {}
for k, v in pairs(t.headers) do headers[#headers + 1] = { k, v } end
local req = H.request({ headers = headers, method = t.method, path = t.path, authority = t.authority })
local r = verify.verify(req, store, t.now, H.crypto_verify, { authorities = { ["example.com"] = true } })
print(r.status .. "/" .. r.reason .. " " .. tostring(r.agent))
`;

(HAVE_LUA ? test : test.skip)("a request signed by wba-sign verifies in the Lua verifier, and only as signed"
  + (HAVE_LUA ? "" : ` (skipped: no ${LUA} on PATH; set LUA)`), async () => {
  const kp = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const now = Math.floor(Date.now() / 1000);
  const { text, keyid } = await storeFor({ kty: priv.kty, crv: priv.crv, x: priv.x }, AGENT, now);
  const s = await signRequest({
    priv, keyid, agent: AGENT, url: new URL("https://localhost:8443/agents/hello?x=1"), method: "GET",
    host: "example.com", now, expires: 300,
  });
  assert.equal(s.headers.Host, "example.com");
  const dir = mkdtempSync(join(tmpdir(), "wba-sign-"));
  try {
    writeFileSync(join(dir, "verify.lua"), VERIFY);
    writeFileSync(join(dir, "store.tsv"), text);
    const run = (path: string, method = "GET") => {
      writeFileSync(join(dir, "req.json"), JSON.stringify({ headers: s.headers, method, path, authority: "example.com", now }));
      const out = spawnSync(LUA, [join(dir, "verify.lua"), join(dir, "store.tsv"), join(dir, "req.json")], { encoding: "utf8" });
      assert.equal(out.status, 0, out.stderr);
      return out.stdout.trim();
    };
    assert.equal(run("/agents/hello"), `verified/ ${AGENT}/.well-known/http-message-signatures-directory`);
    assert.equal(run("/agents/other"), "invalid/bad-signature nil", "@path is covered");
    assert.equal(run("/agents/hello", "POST"), "invalid/bad-signature nil", "@method is covered");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init: the private key is mode 600 and replaces a symlink rather than writing through it; curl -k only with --insecure", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-sign-init-"));
  try {
    const cli = new URL("./sign.ts", import.meta.url).pathname;
    const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
    const victim = join(dir, "victim");
    writeFileSync(victim, "untouched\n");
    symlinkSync(victim, join(dir, "test-agent-key.json"));
    const init = run("init", dir);
    assert.equal(init.status, 0, init.stderr);
    const key = join(dir, "test-agent-key.json");
    assert.equal(lstatSync(key).isSymbolicLink(), false, "the symlink was replaced");
    assert.equal(readFileSync(victim, "utf8"), "untouched\n", "nothing written through the symlink");
    assert.equal(statSync(key).mode & 0o777, 0o600);
    const plain = run("curl", "https://localhost:8443/", "--dir", dir);
    assert.equal(plain.status, 0, plain.stderr);
    assert.match(plain.stdout, /^curl '-s' '-o' /);
    assert.doesNotMatch(plain.stdout, / '-k' /);
    assert.match(run("curl", "https://localhost:8443/", "--dir", dir, "--insecure").stdout, /^curl '-s' '-k' '-o' /);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
