import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseHandleFile } from "../handles";
import { removeEnrollmentManifest, writeEnrollmentManifest } from "../enroll-manifest";
import { withManifestLock, writeHandleFileLocked } from "@cortexkit/claustrum-client";

const handle = `ckh_${"a".repeat(43)}`;
const otherHandle = `ckh_${"b".repeat(43)}`;
const input = { provider: "xai" as const, credentialId: "oauth:xai" as const, handle, minTtlMs: 5000 };
const roots: string[] = [];

async function fresh() {
  const root = await mkdtemp(join(tmpdir(), "enroll-manifest-"));
  roots.push(root);
  return join(root, "handles.json");
}
async function seed(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value), { mode: 0o600 });
  await chmod(path, 0o600);
}
async function read(path: string) { return parseHandleFile(JSON.parse(await readFile(path, "utf8"))); }
async function raw(path: string) { return readFile(path); }

afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

describe("xai enrollment manifest", () => {
  test("adds to an empty manifest and writes mode 0600", async () => {
    const path = await fresh();
    await writeEnrollmentManifest(path, input);
    expect(await read(path)).toEqual({ version: 1, providers: [{ provider: "xai", shape: "oauth", serve: "opencode-claustrum", accounts: [{ label: "main", handle, credential_id: "oauth:xai", minTtlMs: 5000 }] }] });
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  test("preserves foreign blocks, order, unknown keys, and owned api blocks", async () => {
    const path = await fresh();
    const foreign: unknown[] = [
      { provider: "apikey", shape: "api", serve: "opencode-claustrum", accounts: [{ label: "key", handle: otherHandle, credential_id: "apikey:apikey", extra: "keep" }] },
      { provider: "anthropic", shape: "oauth", serve: "anthropic-auth", accounts: [{ label: "main", handle: otherHandle, credential_id: "oauth:anthropic", minTtlMs: 7 }] },
      { provider: "openai", shape: "oauth", serve: "openai-auth", accounts: [{ label: "main", handle: otherHandle, credential_id: "oauth:openai", extra: { keep: true } }] },
    ];
    await seed(path, { version: 1, providers: foreign });
    await writeEnrollmentManifest(path, input);
    const result = await read(path);
    expect(result.providers.slice(0, 3) as unknown).toEqual(foreign);
    expect(result.providers[3]?.provider).toBe("xai");
  });

  test("duplicate enrollment converges and updates only the floor", async () => {
    const path = await fresh();
    await writeEnrollmentManifest(path, input);
    const first = await read(path);
    await writeEnrollmentManifest(path, input);
    expect(await read(path)).toEqual(first);
    await writeEnrollmentManifest(path, { ...input, minTtlMs: 9 });
    expect((await read(path)).providers[0]?.accounts[0]).toMatchObject({ minTtlMs: 9 });
  });

  test("preserves superseded and unknown account fields", async () => {
    const path = await fresh();
    await seed(path, { version: 1, providers: [{ provider: "xai", shape: "oauth", serve: "opencode-claustrum", accounts: [{ label: "main", handle, credential_id: "oauth:xai", minTtlMs: 1, superseded: [otherHandle], unknown: "keep" }] }] });
    await writeEnrollmentManifest(path, { ...input, minTtlMs: 42 });
    expect((await read(path)).providers[0]?.accounts[0] as Record<string, unknown>).toEqual({ label: "main", handle, credential_id: "oauth:xai", minTtlMs: 42, superseded: [otherHandle], unknown: "keep" });
  });

  test("refuses changed handle and foreign owner without changing the file", async () => {
    const path = await fresh();
    await writeEnrollmentManifest(path, input);
    const before = await raw(path);
    await expect(writeEnrollmentManifest(path, { ...input, handle: otherHandle })).rejects.toThrow("xai main handle differs; remove first, then enroll");
    expect(await raw(path)).toEqual(before);
    await seed(path, { version: 1, providers: [{ provider: "xai", shape: "oauth", serve: "someone-else", accounts: [{ label: "main", handle, credential_id: "oauth:xai" }] }] });
    const foreignBefore = await raw(path);
    await expect(writeEnrollmentManifest(path, input)).rejects.toThrow("xai manifest block is owned by another tenant");
    expect(await raw(path)).toEqual(foreignBefore);
  });

  test("refuses non-oauth, empty, multi-account, and different credential blocks", async () => {
    const path = await fresh();
    await seed(path, { version: 1, providers: [{ provider: "xai", shape: "api", serve: "opencode-claustrum", accounts: [{ label: "main", handle, credential_id: "oauth:xai" }] }] });
    await expect(writeEnrollmentManifest(path, input)).rejects.toThrow("xai manifest block has a non-oauth shape");
    await seed(path, { version: 1, providers: [{ provider: "xai", shape: "oauth", serve: "opencode-claustrum", accounts: [{ label: "main", handle, credential_id: "oauth:xai:other" }] }] });
    await expect(writeEnrollmentManifest(path, input)).rejects.toThrow("xai manifest block binds a different credential");
    await seed(path, { version: 1, providers: [{ provider: "xai", shape: "oauth", serve: "opencode-claustrum", accounts: [{ label: "main", handle, credential_id: "oauth:xai" }, { label: "fallback", handle: otherHandle, credential_id: "oauth:xai:fallback" }] }] });
    await expect(writeEnrollmentManifest(path, input)).rejects.toThrow("xai manifest block has unexpected accounts");
  });

  test("removal filters xai only and drops the last account", async () => {
    const path = await fresh();
    await seed(path, { version: 1, providers: [{ provider: "anthropic", shape: "oauth", serve: "anthropic-auth", accounts: [{ label: "main", handle: otherHandle, credential_id: "oauth:anthropic" }] }, { provider: "xai", shape: "oauth", serve: "opencode-claustrum", accounts: [{ label: "main", handle, credential_id: "oauth:xai" }, { label: "fallback", handle: otherHandle, credential_id: "oauth:xai:fallback" }] }] });
    const before = await raw(path);
    await removeEnrollmentManifest(path, { provider: "xai", credentialId: "oauth:xai" });
    expect((await read(path)).providers).toEqual([{ provider: "anthropic", shape: "oauth", serve: "anthropic-auth", accounts: [{ label: "main", handle: otherHandle, credential_id: "oauth:anthropic" }] }, { provider: "xai", shape: "oauth", serve: "opencode-claustrum", accounts: [{ label: "fallback", handle: otherHandle, credential_id: "oauth:xai:fallback" }] }]);
    await seed(path, { version: 1, providers: [{ provider: "anthropic", shape: "oauth", serve: "anthropic-auth", accounts: [{ label: "main", handle: otherHandle, credential_id: "oauth:anthropic" }] }, { provider: "xai", shape: "oauth", serve: "opencode-claustrum", accounts: [{ label: "main", handle, credential_id: "oauth:xai" }] }] });
    await removeEnrollmentManifest(path, { provider: "xai", credentialId: "oauth:xai" });
    expect((await read(path)).providers).toHaveLength(1);
    expect(before).not.toEqual(await raw(path));
  });

  test("absent removal is idempotent and foreign removal is refused", async () => {
    const path = await fresh();
    await removeEnrollmentManifest(path, { provider: "xai", credentialId: "oauth:xai" });
    await seed(path, { version: 1, providers: [{ provider: "xai", shape: "oauth", serve: "someone-else", accounts: [{ label: "main", handle, credential_id: "oauth:xai" }] }] });
    await expect(removeEnrollmentManifest(path, { provider: "xai", credentialId: "oauth:xai" })).rejects.toThrow("xai manifest block is owned by another tenant");
  });

  test("waits for the manifest lock and then sees a fresh snapshot", async () => {
    const path = await fresh();
    const release = Promise.withResolvers<void>();
    const held = withManifestLock(path, "other-tenant", () => release.promise);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const pending = writeEnrollmentManifest(path, input);
    const raced = await Promise.race([pending.then(() => "done"), new Promise((resolve) => setTimeout(() => resolve("waiting"), 300))]);
    try {
      expect(raced).toBe("waiting");
    } finally {
      release.resolve();
      await held;
    }
    await pending;
    expect((await read(path)).providers[0]?.provider).toBe("xai");
  });

  test("takes a fresh snapshot after a foreign writer commits", async () => {
    const path = await fresh();
    await writeHandleFileLocked(path, "other-tenant", (file) => {
      file.providers.push({ provider: "openai", shape: "oauth", serve: "other-tenant", accounts: [{ label: "main", handle: otherHandle, credential_id: "oauth:openai" }] });
    });
    await writeEnrollmentManifest(path, input);
    expect((await read(path)).providers.map((provider) => provider.provider)).toEqual(["openai", "xai"]);
  });

  test("rejects invalid input before acquiring a lock", async () => {
    const path = await fresh();
    await expect(writeEnrollmentManifest(path, { ...input, credentialId: "oauth:openai" as "oauth:xai" })).rejects.toThrow("invalid xai enrollment credential");
    await expect(writeEnrollmentManifest(path, { ...input, handle: "bad" })).rejects.toThrow("invalid xai enrollment handle");
    await expect(writeEnrollmentManifest(path, { ...input, minTtlMs: -1 })).rejects.toThrow("invalid xai enrollment minTtlMs");
    await expect(writeEnrollmentManifest(path, { ...input, minTtlMs: 1.5 })).rejects.toThrow("invalid xai enrollment minTtlMs");
    // "Before acquiring a lock" is observable only while someone else HOLDS it: a writer that
    // validated first rejects immediately; one that locked first would block on the held lock.
    // (A post-hoc "no lock dir" check cannot tell them apart -- release removes the dir either way.)
    const release = Promise.withResolvers<void>();
    const held = withManifestLock(path, "other-tenant", () => release.promise);
    await new Promise((resolve) => setTimeout(resolve, 20));
    try {
      const raced = await Promise.race([
        writeEnrollmentManifest(path, { ...input, minTtlMs: -1 }).then(() => "resolved", () => "rejected"),
        new Promise((resolve) => setTimeout(() => resolve("blocked"), 300)),
      ]);
      expect(raced).toBe("rejected");
    } finally {
      release.resolve();
      await held;
    }
  });
});
