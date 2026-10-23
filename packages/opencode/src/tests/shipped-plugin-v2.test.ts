import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const PACKAGE_ROOT = join(import.meta.dir, "..", "..");
const DIST_PATH = join(PACKAGE_ROOT, "dist", "opencode2", "server.js");

async function loadShipped() {
  if (!existsSync(DIST_PATH)) throw new Error(`shipped V2 plugin bundle missing at ${DIST_PATH}; run 'bun run build' before the hermetic suite.`);
  return import(DIST_PATH);
}

describe("shipped OpenCode 2 plugin bundle", () => {
  test("exports the plugin directory's server entry without replacing the serve library", async () => {
    const manifest: { exports: Record<string, { import: string; types: string }> } = JSON.parse(await readFile(join(PACKAGE_ROOT, "package.json"), "utf8"));
    expect(manifest.exports["./opencode-plugin-v2"]?.import).toBe("./dist/opencode2/server.js");
    expect(manifest.exports["./opencode-plugin-v2"]?.types).toBe("./dist/opencode-plugin-v2.d.ts");
    expect(existsSync(join(PACKAGE_ROOT, manifest.exports["./opencode-plugin-v2"]!.types))).toBe(true);
    expect(manifest.exports["./server"]?.import).toBe("./dist/serve.js");
  });
  test("exposes only the default entry and cleanup setup", async () => {
    const module = await loadShipped();
    expect(Object.keys(module)).toEqual(["default"]);
    expect(module.default.id).toBe("opencode-claustrum");
    expect(typeof module.default.setup).toBe("function");
    const cleanup = await module.default.setup({ session: { hook: async () => ({ dispose: async () => {} }) } });
    expect(typeof cleanup).toBe("function");
    await cleanup();
  });
});
