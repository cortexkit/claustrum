import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (process.env.CLAUSTRUM_CUSTODY_LOG === undefined) {
  process.env.CLAUSTRUM_CUSTODY_LOG = "off";
}
process.env.XDG_STATE_HOME = mkdtempSync(join(tmpdir(), "claustrum-opencode-test-state-"));
