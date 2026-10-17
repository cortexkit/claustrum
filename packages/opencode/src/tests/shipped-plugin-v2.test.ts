import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";

const DIST_PATH = join(import.meta.dir, "..", "..", "dist", "opencode-plugin-v2.js");

async function loadShipped() {
  if (!existsSync(DIST_PATH)) throw new Error(`shipped V2 plugin bundle missing at ${DIST_PATH}; run 'bun run build' before the hermetic suite.`);
  return import(DIST_PATH);
}

describe("shipped OpenCode 2 plugin bundle", () => {
  test("exposes only the default entry and cleanup setup", async () => {
    const module = await loadShipped();
    expect(Object.keys(module)).toEqual(["default"]);
    expect(module.default.id).toBe("opencode-claustrum");
    expect(typeof module.default.setup).toBe("function");
    expect(typeof await module.default.setup({ session: { hook: async () => ({ dispose: async () => {} }) } })).toBe("function");
  });
});
