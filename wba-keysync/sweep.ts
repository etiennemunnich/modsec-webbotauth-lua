// wba-sweep: removes replay counters (lua/wba/replay.lua) that can no
// longer matter. Run on the same timer as wba-keysync, as a user that can
// write the replay directory:
//
//   bun wba-keysync/sweep.ts --dir /var/lib/wba/replay [--max-window 3600] [--skew 300]
//   node wba-keysync/sweep.ts ...
//
// s.<expires>.<hash>  a signed statement, named by the signature's own
//                     expires (never by the verifier's settings, so every
//                     server block counts it in one file): removed once
//                     expires + skew has passed (nothing verifies after
//                     expires plus tx.wba_expiry_grace, at most 60 s), or
//                     once unused (mtime) for longer than max-window + skew,
//                     whichever comes first. Every signature over the
//                     statement shares its created, so none verifies more
//                     than max-window (tx.wba_max_age) plus the verifier's
//                     60 s of clock skew after the statement's first use:
//                     the file is still there for every use that can count,
//                     and a bot that signs with a far-off expires cannot
//                     keep it longer.
// n.<hash>            a nonce: removed once unused (mtime) for longer than
//                     max-window + skew. Any signature carrying it that can
//                     still verify was made within max-window of its last
//                     use, so its count is still there; a new signature
//                     reusing a nonce unused for that long counts from 1.
//
// --max-window must cover the longest any server block sharing the directory
// lets a signature count: in each block, tx.wba_max_age (3600 by default), or
// tx.wba_max_window where that is smaller; with tx.wba_max_age off,
// tx.wba_max_window (a day unless set). The default, 86400, covers every
// setting of a day or less; give a longer one when a block allows more, or a
// counter is removed while a signature over it can still count. --skew
// (default 300) must cover the verifier's 60 s clock skew,
// tx.wba_expiry_grace (at most 60) and any clock difference between this
// host and the WAF.
//
// Only regular files directly in the directory whose names match exactly are
// touched; symlinks, directories and anything else are left alone and
// counted as ignored. Exit codes: 0 done; 1 usage error or unreadable
// directory.

import { lstatSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";

const STATEMENT = /^s\.(\d{1,15})\.[0-9a-f]{64}$/;
const NONCE = /^n\.[0-9a-f]{64}$/;

export interface SweepResult { removed: number; kept: number; ignored: number }

class UsageError extends Error {}

/** Removes what can no longer matter; `now` in Unix seconds. `io` is for tests. */
export function sweep(dir: string, now: number, maxWindow = 86400, skew = 300, io = { lstatSync, unlinkSync }): SweepResult {
  const result: SweepResult = { removed: 0, kept: 0, ignored: 0 };
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const name = entry.name;
    const statement = STATEMENT.exec(name);
    if (!entry.isFile() || (!statement && !NONCE.test(name))) { // Dirent types come from lstat: a symlink is not a file
      result.ignored++;
      continue;
    }
    const path = join(dir, name);
    let expired = statement !== null && Number(statement[1]) + skew < now;
    if (!expired) { // a statement not yet expired, or a nonce: gone once unused for longer than any signature counts
      let mtimeMs: number;
      try {
        mtimeMs = io.lstatSync(path).mtimeMs;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") continue; // another sweeper removed it after readdir
        throw e;
      }
      expired = Math.floor(mtimeMs / 1000) + maxWindow + skew < now;
    }
    if (!expired) { result.kept++; continue; }
    try {
      io.unlinkSync(path);
      result.removed++;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; // another sweeper got there first
    }
  }
  return result;
}

function main(argv: string[]): number {
  const opt = (name: string) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const seconds = (name: string, fallback: number) => {
    const v = opt(name);
    if (v === undefined) return fallback;
    if (!/^\d{1,9}$/.test(v)) throw new UsageError(`${name} must be a number of seconds`);
    return Number(v);
  };
  const dir = opt("--dir");
  try {
    if (!dir) throw new UsageError("--dir is required");
    const r = sweep(dir, Math.floor(Date.now() / 1000), seconds("--max-window", 86400), seconds("--skew", 300));
    console.log(`wba-sweep: ${dir}: removed ${r.removed}, kept ${r.kept}, ignored ${r.ignored}`);
    return 0;
  } catch (e) {
    const usage = "\nusage: wba-sweep --dir <replay directory> [--max-window SECONDS] [--skew SECONDS]";
    console.error(`wba-sweep: ${(e as Error).message}${e instanceof UsageError ? usage : ""}`);
    return 1;
  }
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
