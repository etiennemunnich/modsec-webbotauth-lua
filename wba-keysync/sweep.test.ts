// sweep.test.ts: wba-keysync/sweep.ts, the replay-counter sweeper. Runs
// unchanged under `bun test` and `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { sweep } from "./sweep.ts";

const NOW = 1_790_990_000;
const HEX = (c: string) => c.repeat(64);

function layout() {
  const dir = mkdtempSync(join(tmpdir(), "wba-sweep-"));
  const put = (name: string, mtime = NOW) => { const p = join(dir, name); writeFileSync(p, "x"); utimesSync(p, mtime, mtime); return p; };
  put(`s.${NOW - 1000}.${HEX("a")}`);                // expired long ago: removed
  put(`s.${NOW - 200}.${HEX("b")}`);                 // expired, still inside the 300 s margin: kept
  put(`s.${NOW + 600}.${HEX("c")}`);                 // not expired: kept
  put(`n.${HEX("d")}`, NOW - 86400 - 301);           // unused for longer than window + skew: removed
  put(`n.${HEX("e")}`, NOW - 86400 - 299);           // just inside: kept
  put(`s.1.${HEX("f").toUpperCase()}`);              // not lowercase hex: ignored
  put(`s.x.${HEX("f")}`);                            // expires not digits: ignored
  put(`n.${"f".repeat(63)}`);                        // short hash: ignored
  put("notes.txt");                                  // anything else: ignored
  mkdirSync(join(dir, `s.1.${HEX("0")}`));           // a directory with a matching name: ignored
  const outside = mkdtempSync(join(tmpdir(), "wba-sweep-outside-"));
  const target = join(outside, "target");
  writeFileSync(target, "keep me");
  symlinkSync(target, join(dir, `n.${HEX("1")}`));   // a symlink with a matching name: ignored, target untouched
  return { dir, outside, target };
}

test("sweep: removes expired statements and long-unused nonces, nothing else", () => {
  const { dir, outside, target } = layout();
  try {
    assert.deepEqual(sweep(dir, NOW), { removed: 2, kept: 3, ignored: 6 });
    assert.equal(existsSync(join(dir, `s.${NOW - 1000}.${HEX("a")}`)), false);
    assert.equal(existsSync(join(dir, `n.${HEX("d")}`)), false);
    for (const kept of [`s.${NOW - 200}.${HEX("b")}`, `s.${NOW + 600}.${HEX("c")}`, `n.${HEX("e")}`, "notes.txt", `n.${HEX("1")}`]) {
      assert.equal(existsSync(join(dir, kept)), true, kept);
    }
    assert.equal(readFileSync(target, "utf8"), "keep me", "a symlink's target is never touched");
    assert.deepEqual(sweep(dir, NOW), { removed: 0, kept: 3, ignored: 6 }, "a second run removes nothing more");
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("sweep: --max-window and --skew set the margins", () => {
  const { dir, outside } = layout();
  try {
    // A 1-hour window: the nonce unused for a day goes too; skew 0 takes b.
    assert.deepEqual(sweep(dir, NOW, 3600, 0), { removed: 4, kept: 1, ignored: 6 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("sweep CLI: runs on a directory, refuses bad arguments with exit 1", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-sweep-cli-"));
  try {
    writeFileSync(join(dir, `s.1.${HEX("a")}`), "x"); // expired in 1970
    const cli = new URL("./sweep.ts", import.meta.url).pathname;
    const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
    const ok = run("--dir", dir);
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(ok.stdout, /removed 1, kept 0, ignored 0/);
    assert.equal(run().status, 1, "no --dir");
    assert.equal(run("--dir", dir, "--max-window", "1h").status, 1, "not a number of seconds");
    assert.equal(run("--dir", join(dir, "missing")).status, 1, "unreadable directory");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sweep: a nonce another sweeper removed after readdir is skipped, not fatal", () => {
  const dir = mkdtempSync(join(tmpdir(), "wba-sweep-race-"));
  try {
    writeFileSync(join(dir, `n.${HEX("a")}`), "x");
    const gone = () => { throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" }); };
    const r = sweep(dir, NOW, 86400, 300, { lstatSync: gone as never, unlinkSync: () => assert.fail("nothing to unlink") });
    assert.deepEqual(r, { removed: 0, kept: 0, ignored: 0 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sweep CLI: usage text for a usage error only, not for an unreadable directory", () => {
  const cli = new URL("./sweep.ts", import.meta.url).pathname;
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
  assert.match(run().stderr, /usage: wba-sweep/);
  const missing = run("--dir", join(tmpdir(), "wba-sweep-no-such-dir"));
  assert.equal(missing.status, 1);
  assert.doesNotMatch(missing.stderr, /usage:/);
});
