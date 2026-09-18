import { afterEach, expect, test } from "bun:test";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import type { ClaustrumClient } from "@cortexkit/claustrum-client";

import { createOpencodeClaustrumPlugin } from "../plugin";
import { sentinel, tombstoneFor } from "../tombstone";

const PROVIDER = "deepseek";
const HANDLE = `ckh_${"a".repeat(43)}`;
const liveLogPath = () => join(process.env.HOME ?? ".", ".local", "state", "cortexkit", "opencode-plugin", "custody.jsonl");
const savedEnv = new Map<string, string | undefined>();

function useEnv(key: string, value: string | undefined) {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

afterEach(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
});

test("a plugin serve without an injected logger does not write the live custody log", async () => {
  useEnv("CLAUSTRUM_CUSTODY_LOG", undefined);
  const path = liveLogPath();
  const beforeExists = existsSync(path);
  const beforeContent = beforeExists ? readFileSync(path, "utf8") : "";
  const beforeMtimeMs = beforeExists ? statSync(path).mtimeMs : undefined;

  const plugin = createOpencodeClaustrumPlugin({
    handleReader: async () => ({
      version: 1,
      providers: [{
        provider: PROVIDER,
        shape: "api",
        serve: "opencode-claustrum",
        accounts: [{ label: "main", handle: HANDLE, credential_id: `apikey:${PROVIDER}:main` }],
      }],
    }),
    authReader: async () => ({ [PROVIDER]: tombstoneFor("api", PROVIDER) }),
    detect: async () => ({ status: "available" as const, schema: 1, wireVersion: 1, endpoints: [] }),
    clientFactory: async () => ({
      getCredential: async () => ({ material: "served-material", recordVersion: 1, expiresAtMs: null }),
      reportAuthFailure: async () => {},
    } as unknown as ClaustrumClient),
    fetch: (async () => new Response("upstream", { status: 200 })) as unknown as typeof globalThis.fetch,
    handleVersionReader: async () => "stable",
  });
  const hooks = await plugin({} as never);
  const config: { provider: Record<string, { options?: Record<string, unknown> }> } = { provider: {} };

  if (!hooks.config) throw new Error("plugin did not provide config hook");
  await hooks.config(config);
  const serve = config.provider[PROVIDER]?.options?.fetch;
  expect(typeof serve).toBe("function");
  await (serve as (input: string, init?: RequestInit) => Promise<Response>)
    ("https://upstream.example/v1/chat", { headers: { Authorization: `Bearer ${sentinel(PROVIDER)}` } });

  const afterExists = existsSync(path);
  expect(afterExists).toBe(beforeExists);
  if (beforeExists) {
    expect(readFileSync(path, "utf8")).toBe(beforeContent);
    if (beforeMtimeMs !== undefined) expect(statSync(path).mtimeMs).toBe(beforeMtimeMs);
  }
});
