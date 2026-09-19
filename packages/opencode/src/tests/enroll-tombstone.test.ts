import { afterEach, describe, expect, test } from "bun:test";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isProviderTombstone, tombstoneFor } from "../tombstone";
import { writeOAuthTombstone, type AuthTombstoneIo } from "../enroll-tombstone";
import { AuthFileValidationError } from "../errors";

const provider = "xai";
const canonical = Buffer.from(JSON.stringify({ [provider]: tombstoneFor("oauth", provider) }) + "\n");

function fake(initial: Buffer | null) {
  let disk = initial?.subarray() ?? null;
  const writes: Buffer[] = [];
  const io: AuthTombstoneIo = {
    async read() { return disk?.subarray() ?? null; },
    async write(_path, bytes) { writes.push(bytes.subarray()); disk = bytes.subarray(); },
  };
  return { io, writes, get disk() { return disk; }, set disk(value: Buffer | null) { disk = value; } };
}

describe("OAuth tombstone enrollment", () => {
  test("writes stable auth once", async () => {
    const f = fake(null);
    expect(await writeOAuthTombstone("auth.json", provider, f.io)).toEqual({ writes: 1 });
    expect(f.disk).toEqual(canonical);
  });

  test("reconciles one child restore", async () => {
    const before = Buffer.from('{"anthropic":{"type":"api","key":"secret"}}\n');
    const f = fake(before);
    let first = true;
    f.io.write = async (_path, bytes) => { f.writes.push(bytes.subarray()); f.disk = first ? before : bytes; first = false; };
    expect(await writeOAuthTombstone("auth.json", provider, f.io)).toEqual({ writes: 2 });
  });

  test("refuses repeated child restore", async () => {
    const before = Buffer.from('{}\n');
    const f = fake(before);
    f.io.write = async (_path, bytes) => { f.writes.push(bytes.subarray()); f.disk = before; };
    await expect(writeOAuthTombstone("auth.json", provider, f.io)).rejects.toThrow("auth repeatedly restored by workspace child; stop the child and retry");
    expect(f.writes).toHaveLength(2);
  });

  test("refuses newer bytes without another write", async () => {
    const f = fake(Buffer.from('{}\n'));
    f.io.write = async (_path, bytes) => { f.writes.push(bytes.subarray()); f.disk = Buffer.from('{"xai":{"type":"oauth","access":"new","refresh":"new","expires":9}}\n'); };
    await expect(writeOAuthTombstone("auth.json", provider, f.io)).rejects.toThrow("auth changed during enrolment; newer material left untouched");
    expect(f.writes).toHaveLength(1);
  });

  test("refuses another provider changing and leaves its newer bytes", async () => {
    const before = Buffer.from('{"xai":{"type":"oauth","access":"old","refresh":"old","expires":1},"anthropic":"A1"}\n');
    const after = Buffer.from('{"xai":{"type":"oauth","access":"old","refresh":"old","expires":1},"anthropic":"A2"}\n');
    const f = fake(before);
    f.io.write = async (_path, bytes) => { f.writes.push(bytes.subarray()); f.disk = after; };
    await expect(writeOAuthTombstone("auth.json", provider, f.io)).rejects.toThrow("auth changed during enrolment; newer material left untouched");
    expect(f.writes).toHaveLength(1);
    expect(f.disk).toEqual(after);
  });

  test("reformatted equal JSON is newer bytes", async () => {
    const f = fake(Buffer.from('{"anthropic":{}}\n'));
    f.io.write = async (_path, bytes) => { f.writes.push(bytes.subarray()); f.disk = Buffer.from('{ "anthropic": {} }\n'); };
    await expect(writeOAuthTombstone("auth.json", provider, f.io)).rejects.toThrow("auth changed during enrolment; newer material left untouched");
  });

  test("recognizes existing canonical tombstone", async () => {
    const f = fake(canonical);
    expect(await writeOAuthTombstone("auth.json", provider, f.io)).toEqual({ writes: 0 });
    expect(f.writes).toHaveLength(0);
  });

  test("rejects malformed and non-object auth", async () => {
    for (const [bytes, message] of [[Buffer.from("{oops"), "auth file contains invalid JSON"], [Buffer.from("[]"), "auth file must contain a JSON object"], [Buffer.from("null"), "auth file must contain a JSON object"]] as const) {
      const f = fake(bytes);
      await expect(writeOAuthTombstone("auth.json", provider, f.io)).rejects.toThrow(message);
      expect(f.writes).toHaveLength(0);
    }
  });

  test("preserves unrelated members", async () => {
    const f = fake(Buffer.from('{"anthropic":{"type":"api","key":"k"},"other":1}\n'));
    await writeOAuthTombstone("auth.json", provider, f.io);
    expect(JSON.parse(f.disk!.toString())).toMatchObject({ other: 1, anthropic: { key: "k" }, xai: canonical.toString() && tombstoneFor("oauth", provider) });
  });

  test("rejects invalid provider before read", async () => {
    let reads = 0;
    const io: AuthTombstoneIo = { async read() { reads++; return null; }, async write() {} };
    for (const invalid of ["x y", "constructor", "prototype"]) {
      await expect(writeOAuthTombstone("auth.json", invalid, io)).rejects.toThrow("invalid auth provider identifier");
    }
    expect(reads).toBe(0);
  });

  test("handles missing auth and disappearance without leaking raw material", async () => {
    const missing = fake(null);
    expect(await writeOAuthTombstone("auth.json", provider, missing.io)).toEqual({ writes: 1 });
    expect(missing.disk).toEqual(canonical);

    const restored = fake(null);
    let reads = 0;
    restored.io.write = async (_path, bytes) => { restored.writes.push(bytes.subarray()); restored.disk = reads++ === 0 ? null : bytes; };
    expect(await writeOAuthTombstone("auth.json", provider, restored.io)).toEqual({ writes: 2 });

    const disappeared = fake(Buffer.from('{}\n'));
    disappeared.io.write = async (_path, bytes) => { disappeared.writes.push(bytes.subarray()); disappeared.disk = null; };
    await expect(writeOAuthTombstone("auth.json", provider, disappeared.io)).rejects.toThrow("auth file disappeared during enrolment; nothing written back");
  });

  test("never includes raw auth material in thrown errors", async () => {
    const canary = "LEAK-CANARY-9f3a1c";
    const before = Buffer.from(JSON.stringify({ xai: { type: "oauth", access: "", refresh: canary, expires: 1 } }));
    expect(before.toString()).toContain(canary);
    const cases: AuthTombstoneIo[] = [];
    const repeated = fake(before); repeated.io.write = async (_path, bytes) => { repeated.writes.push(bytes.subarray()); repeated.disk = before; }; cases.push(repeated.io);
    const newer = fake(before); newer.io.write = async (_path, bytes) => { newer.writes.push(bytes.subarray()); newer.disk = Buffer.from(JSON.stringify({ xai: { type: "oauth", access: "new", refresh: canary, expires: 2 } })); }; cases.push(newer.io);
    const gone = fake(before); gone.io.write = async (_path, bytes) => { gone.writes.push(bytes.subarray()); gone.disk = null; }; cases.push(gone.io);
    cases.push(fake(Buffer.from(`{"xai":"${canary}`)).io);
    for (const io of cases) {
      let caught: Error | undefined;
      try { await writeOAuthTombstone("auth.json", provider, io); } catch (error) { caught = error as Error; }
      expect(caught).toBeDefined();
      expect(caught!.message).not.toContain(canary);
    }
  });
});

describe("OAuth tombstone real IO", () => {
  let dir = "";
  afterEach(async () => { if (dir) await rm(dir, { recursive: true, force: true }); dir = ""; });
  test("writes private file", async () => {
    dir = await mkdtemp(join(tmpdir(), "enroll-tombstone-"));
    const path = join(dir, "auth.json");
    expect(await writeOAuthTombstone(path, provider)).toEqual({ writes: 1 });
    expect(await readFile(path)).toEqual(canonical);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
  });
  test("refuses symlink", async () => {
    dir = await mkdtemp(join(tmpdir(), "enroll-tombstone-"));
    const target = join(dir, "target"); const path = join(dir, "auth.json");
    await writeFile(target, "{}\n"); await symlink(target, path);
    await expect(writeOAuthTombstone(path, provider)).rejects.toThrow("auth file must be a regular 0600 file");
    expect((await lstat(path)).isSymbolicLink()).toBe(true);
  });

  test("refuses oversized file", async () => {
    dir = await mkdtemp(join(tmpdir(), "enroll-tombstone-"));
    const path = join(dir, "auth.json");
    await writeFile(path, Buffer.alloc(1024 * 1024 + 1, 65), { mode: 0o600 });
    await expect(writeOAuthTombstone(path, provider)).rejects.toThrow("auth file exceeds 1 MiB");
    await expect(writeOAuthTombstone(path, provider)).rejects.toBeInstanceOf(AuthFileValidationError);
  });

  test("refuses insecure mode", async () => {
    dir = await mkdtemp(join(tmpdir(), "enroll-tombstone-"));
    const path = join(dir, "auth.json");
    await writeFile(path, "{}\n", { mode: 0o644 });
    await expect(writeOAuthTombstone(path, provider)).rejects.toThrow("auth file must be a regular 0600 file");
    await expect(writeOAuthTombstone(path, provider)).rejects.toBeInstanceOf(AuthFileValidationError);
  });

  test("refuses a directory at the auth path", async () => {
    dir = await mkdtemp(join(tmpdir(), "enroll-tombstone-"));
    const path = join(dir, "auth.json");
    await mkdir(path);
    await expect(writeOAuthTombstone(path, provider)).rejects.toThrow("auth file must be a regular 0600 file");
  });

  test("cleans temporary file when replacement fails", async () => {
    dir = await mkdtemp(join(tmpdir(), "enroll-tombstone-"));
    const path = join(dir, "auth.json");
    const original = Buffer.from("{}\n");
    await writeFile(path, original, { mode: 0o600 });
    try {
      await chmod(dir, 0o500);
      await expect(writeOAuthTombstone(path, provider)).rejects.toThrow("auth file replacement failed");
    } finally {
      await chmod(dir, 0o700);
    }
    expect(await readFile(path)).toEqual(original);
    expect((await readdir(dir)).filter((entry) => /^\.auth\.json\..*\.tmp$/.test(entry))).toHaveLength(0);
  });

  test("preserves destination validation when a directory replaces the path mid-write", async () => {
    // The refusal under test lives in writeAuth's catch: it fires only when the
    // destination becomes a directory between the pre-rename lstat and the rename.
    // No IO seam sits in that window, so the race is driven from outside and BOUNDED:
    // the watcher stops after 2 s whether or not it caught the temp file. If it did not,
    // the write completes and the test reports the miss by name instead of hanging or
    // passing vacuously. Two sites answer this race with the same refusal — the pre-rename
    // check and the catch's destination re-check — so only removing BOTH reddens this test;
    // a single-site mutation is answered by the other site and stays green by design.
    dir = await mkdtemp(join(tmpdir(), "enroll-tombstone-"));
    const path = join(dir, "auth.json");
    let planted = false;
    const deadline = Date.now() + 2000;
    const watcher = (async () => {
      while (Date.now() < deadline) {
        const entries = await readdir(dir).catch(() => [] as string[]);
        if (entries.some((entry) => entry.startsWith(".auth.json.") && entry.endsWith(".tmp"))) {
          await mkdir(path).catch(() => {});
          planted = true;
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    })();
    const outcome = await writeOAuthTombstone(path, provider).then(() => "wrote" as const, (error: unknown) => error);
    await watcher;
    if (!planted) throw new Error("race window missed: watcher never saw the temp file (inconclusive, not a pass)");
    expect(outcome).toBeInstanceOf(AuthFileValidationError);
    expect((outcome as Error).message).toBe("auth file must be a regular 0600 file");
  });
});
