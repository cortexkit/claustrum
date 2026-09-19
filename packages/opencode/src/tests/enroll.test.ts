import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ServedCredential } from "@cortexkit/claustrum-client";
import { parseEnrollArgs, readEnrollmentHandle, runEnrollment, type EnrollArgs, type EnrollDependencies } from "../enroll";

process.env.CLAUSTRUM_CUSTODY_LOG = "off";

const handle = `ckh_${"a".repeat(43)}`;
const token = "secret-token-must-never-appear";
const roots: string[] = [];

async function fresh(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "claustrum-enroll-"));
  roots.push(root);
  return root;
}

const args = (): EnrollArgs => ({ provider: "xai", credentialId: "oauth:xai", main: true, remove: false, handleFile: "/handle", minTtlMs: 0, tokenLifetimeMs: 1, manifestPath: "/manifest", authPath: "/auth" });
const served = (credentialId: string | undefined, material = token): ServedCredential => ({ credentialId, material, recordVersion: 1, expiresAtMs: Date.now() + 1 });

function dependencies(events: string[], overrides: Partial<EnrollDependencies> = {}): EnrollDependencies {
  return {
    readHandle: async () => handle,
    connect: async () => ({
      getCredential: async () => { events.push("get"); return served("oauth:xai"); },
      close: () => { events.push("close"); },
    }),
    writeManifest: async () => { events.push("manifest"); },
    removeManifest: async () => { events.push("remove"); },
    writeTombstone: async () => { events.push("tombstone"); return { writes: 1 }; },
    ...overrides,
  };
}

async function expectRefusal(argv: string[], message: string) {
  expect(() => parseEnrollArgs(argv)).toThrow(message);
}

afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

describe("enroll argument parsing", () => {
  test("refuses invalid, incomplete, duplicate, and incompatible action flags", async () => {
    await expectRefusal(["--provider", "xai", "--main"], "missing required --provider or --id");
    await expectRefusal(["--provider", "xai", "--id", "oauth:openai", "--main"], "invalid credential id for provider");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai:", "--main"], "invalid credential id for provider");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai:work", "--main"], "v1 supports only");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai"], "two-segment main id requires --main");
    await expectRefusal(["--provider", "openai", "--id", "oauth:openai", "--main"], "v1 supports only");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai", "--main", "--min-ttl-ms", "-1"], "minTtlMs");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai", "--main", "--min-ttl-ms", "1.5"], "minTtlMs");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai", "--main", "--token-lifetime-ms", "nope"], "minTtlMs");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai", "--main", "--min-ttl-ms", "2", "--token-lifetime-ms", "2"], "minTtlMs must be below measured token lifetime");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai", "--main", "--extra"], "invalid enrollment arguments");
    await expectRefusal(["--provider", "xai", "--provider", "xai", "--id", "oauth:xai", "--main"], "duplicate flag");
    await expectRefusal(["--provider", "xai", "--id", "oauth:xai", "--main", "--remove", "--handle-file", "/x"], "--remove");
    await expectRefusal(["--help"], "invalid enrollment arguments");
  });

  test("accepts zero floor and one Bun separator", () => {
    const parsed = parseEnrollArgs(["--", "--provider", "xai", "--id", "oauth:xai", "--main", "--min-ttl-ms", "0", "--token-lifetime-ms", "2"], { HOME: "/home/test" });
    expect(parsed.minTtlMs).toBe(0);
    expect(parsed.manifestPath).toBe(join("/home/test", ".config", "cortexkit", "opencode-handles.json"));
    expect(parsed.authPath).toBe(join("/home/test", ".local", "share", "opencode", "auth.json"));
    expect(() => parseEnrollArgs(["--", "--", "--provider", "xai", "--id", "oauth:xai", "--main"])).toThrow("invalid enrollment arguments");
  });
});

describe("enrollment runner", () => {
  test("orders successful enrollment and closes the client", async () => {
    const events: string[] = [];
    const deps = dependencies(events, { connect: async () => { events.push("connect"); return (await dependencies(events).connect()); } });
    await expect(runEnrollment(args(), deps)).resolves.toBe("Enrolled xai main in opencode-claustrum; reload OpenCode.");
    expect(events).toEqual(["connect", "get", "manifest", "tombstone", "close"]);
  });

  test("refuses a served identity mismatch", async () => {
    const events: string[] = [];
    const deps = dependencies(events, { connect: async () => ({ getCredential: async () => { events.push("get"); return served("oauth:other"); }, close: () => { events.push("close"); } }) });
    await expect(runEnrollment(args(), deps)).rejects.toThrow("credential identity mismatch");
    expect(events).toEqual(["get", "close"]);
  });

  test("refuses a served credential without identity metadata", async () => {
    const events: string[] = [];
    const deps = dependencies(events, { connect: async () => ({ getCredential: async () => { events.push("get"); return served(undefined); }, close: () => { events.push("close"); } }) });
    await expect(runEnrollment(args(), deps)).rejects.toThrow("credential identity mismatch");
    expect(events).toEqual(["get", "close"]);
  });

  test("refuses unusable material, vault failures, and write failures without later writes", async () => {
    const empty = dependencies([], { connect: async () => ({ getCredential: async () => served("oauth:xai", ""), close: () => {} }) });
    await expect(runEnrollment(args(), empty)).rejects.toThrow("credential did not serve usable material");
    const rpcEvents: string[] = [];
    const rpc = dependencies(rpcEvents, { connect: async () => ({ getCredential: async () => { rpcEvents.push("get"); throw new Error(token); }, close: () => { rpcEvents.push("close"); } }) });
    await expect(runEnrollment(args(), rpc)).rejects.toThrow("vault read failed");
    expect(rpcEvents).toEqual(["get", "close"]);
    const manifestEvents: string[] = [];
    await expect(runEnrollment(args(), dependencies(manifestEvents, { writeManifest: async () => { manifestEvents.push("manifest"); throw new Error(token); } }))).rejects.toThrow("manifest write failed");
    expect(manifestEvents).not.toContain("tombstone");
    const tombstoneEvents: string[] = [];
    await expect(runEnrollment(args(), dependencies(tombstoneEvents, { writeTombstone: async () => { tombstoneEvents.push("tombstone"); throw new Error(token); } }))).rejects.toThrow("tombstone write failed after manifest write; manifest entry remains — run --remove before /login");
  });

  test("removes only the manifest and reports remove failures without login instruction", async () => {
    const events: string[] = [];
    const removeArgs = { ...args(), remove: true, handleFile: undefined, minTtlMs: undefined, tokenLifetimeMs: undefined };
    const deps = dependencies(events, { readHandle: async () => { throw new Error("must not read"); }, connect: async () => { throw new Error("must not connect"); } });
    await expect(runEnrollment(removeArgs, deps)).resolves.toContain("/login");
    expect(events).toEqual(["remove"]);
    await expect(runEnrollment(removeArgs, dependencies([], { removeManifest: async () => { throw new Error(token); } }))).rejects.toThrow("manifest removal failed");
  });

  test("refuses handle failures before connection without touching seeded files", async () => {
    const root = await fresh();
    const authPath = join(root, "auth.json"); const manifestPath = join(root, "manifest.json");
    await writeFile(authPath, "auth-bytes"); await writeFile(manifestPath, "manifest-bytes");
    const before = await Promise.all([readFile(authPath), readFile(manifestPath)]);
    const events: string[] = [];
    await expect(runEnrollment({ ...args(), handleFile: join(root, "missing"), authPath, manifestPath }, dependencies(events, { readHandle: readEnrollmentHandle, connect: async () => { throw new Error("connected"); } }))).rejects.toThrow("handle file unreadable");
    expect(events).toEqual([]);
    expect(await Promise.all([readFile(authPath), readFile(manifestPath)])).toEqual(before);
  });
});

describe("capability handle reader", () => {
  test("trims one surrounding whitespace region and refuses unsafe files", async () => {
    const root = await fresh(); const path = join(root, "handle");
    await writeFile(path, `\n${handle}\n`, { mode: 0o600 }); await chmod(path, 0o600);
    await expect(readEnrollmentHandle(path)).resolves.toBe(handle);
    await chmod(path, 0o644); await expect(readEnrollmentHandle(path)).rejects.toThrow("unsafe handle file");
    await chmod(path, 0o600); await writeFile(path, "x".repeat(300)); await expect(readEnrollmentHandle(path)).rejects.toThrow("handle file exceeds limit");
    await writeFile(path, `${handle}\n${handle}`); await expect(readEnrollmentHandle(path)).rejects.toThrow("invalid handle file");
    await writeFile(path, "garbage"); await expect(readEnrollmentHandle(path)).rejects.toThrow("invalid handle file");
    await writeFile(path, handle, { mode: 0o600 }); await symlink(path, join(root, "link")); await expect(readEnrollmentHandle(join(root, "link"))).rejects.toThrow("ELOOP: too many symbolic links encountered, open");
    await expect(readEnrollmentHandle(root)).rejects.toThrow("unsafe handle file");
  });
});

describe("CLI and bundle boundaries", () => {
  test("help and refusals never reveal fixture secrets", async () => {
    const root = await fresh(); const handlePath = join(root, "handle");
    await writeFile(handlePath, handle, { mode: 0o600 }); await chmod(handlePath, 0o600);
    expect(await readFile(handlePath, "utf8")).toContain(handle);
    const cwd = join(import.meta.dir, "..", "..");
    const run = async (argv: string[]) => {
      const child = Bun.spawn(["bun", "run", "enroll", "--", ...argv], { cwd, env: { ...process.env, HOME: root, XDG_CONFIG_HOME: root, XDG_DATA_HOME: root, CLAUSTRUM_SUBC_CONNECTION: join(root, "missing.sock"), CLAUSTRUM_CUSTODY_LOG: "off" }, stdout: "pipe", stderr: "pipe" });
      return { code: await child.exited, stdout: await new Response(child.stdout).text(), stderr: await new Response(child.stderr).text() };
    };
    const help = await run(["--help"]);
    expect(help.code).toBe(0); expect(help.stdout).toContain("--id"); expect(help.stdout).toContain("--main"); expect(help.stdout).toContain("--min-ttl-ms"); expect(help.stdout).toContain("--token-lifetime-ms"); expect(help.stdout).toContain("--remove"); expect(help.stdout).toContain("manifest"); expect(help.stdout).toContain("v1 supports only");
    const refusal = await run(["--provider", "xai", "--id", "oauth:openai", "--main"]);
    expect(refusal.code).not.toBe(0); expect(refusal.stderr).toContain("invalid credential id for provider"); expect(refusal.stderr).not.toMatch(/\n\s+at /); expect(refusal.stderr).not.toContain("Error:");
    // run() prepends one separator and bun consumes one before argv reaches the script, so three
    // here reach main as two — which must fail at the argument stage, not reach validation.
    const doubled = await run(["--", "--", "--", "--provider", "xai", "--id", "oauth:openai", "--main"]);
    expect(doubled.code).not.toBe(0); expect(doubled.stderr).toContain("invalid enrollment arguments"); expect(doubled.stderr).not.toContain("invalid credential id");
    const connection = await run(["--provider", "xai", "--id", "oauth:xai", "--main", "--min-ttl-ms", "0", "--token-lifetime-ms", "1", "--handle-file", handlePath]);
    expect(connection.code).not.toBe(0); expect(connection.stderr).toContain("vault connection failed");
    for (const result of [help, refusal, connection]) { expect(result.stdout + result.stderr).not.toContain(handle); expect(result.stdout + result.stderr).not.toContain(token); }
  });

  test("keeps enroll out of the plugin bundle entry", async () => {
    const source = await readFile(join(import.meta.dir, "..", "opencode-plugin.ts"), "utf8");
    expect(source).not.toMatch(/enroll/);
  });
});
