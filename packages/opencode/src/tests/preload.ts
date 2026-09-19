import { afterAll } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (process.env.CLAUSTRUM_CUSTODY_LOG === undefined) {
  process.env.CLAUSTRUM_CUSTODY_LOG = "off";
}
// One state root per bun process, removed when that process exits.
//
// Without the exit hook this leaks a directory per test invocation -- 77 of them had
// accumulated by 2026-09-19, part of 291,480 entries fleet-wide in $TMPDIR. That
// directory had grown expensive enough that an unbounded readdir of it ran for minutes
// and starved another module's route-bind path until new clients could not connect, so
// a leak measured in directories-per-run stopped being free.
//
// A GLOBAL `afterAll` RATHER THAN `process.on("exit")`, and the difference is not
// stylistic: bun's test runner does NOT run exit handlers. Measured with a probe that
// printed from an exit listener registered in a preload -- the line never appeared,
// while the same probe using `afterAll` did. An exit hook here is a cleanup that reads
// correct, passes review, and never runs.
//
// `afterAll` from a preload registers once for the whole process, which is the right
// scope: the root is created once and every suite shares it, so no per-file hook owns
// it. `force` because an interrupted run leaves it already gone.
const stateRoot = mkdtempSync(join(tmpdir(), "claustrum-opencode-test-state-"));
process.env.XDG_STATE_HOME = stateRoot;
afterAll(() => rmSync(stateRoot, { recursive: true, force: true }));
