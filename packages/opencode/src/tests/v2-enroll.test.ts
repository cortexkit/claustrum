import { beforeAll, describe, expect, test } from "bun:test";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { parseEnrollArgs, runEnrollment, type EnrollDependencies } from "../enroll";
import { OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "../handles";
import { createOc2Credentials, Oc2CredentialError, OC2_CREDENTIAL_CONSUMERS, type Oc2CredentialEntry, type Oc2Credentials } from "../v2/oc2-credentials";
import { v2KeyTombstone, v2OauthTombstone } from "../v2/tombstone";
import { sentinel } from "../tombstone";

const secret = "oc2-export-canary-secret";
const handle = `ckh_${"a".repeat(43)}`;
const base = "/tmp/opencode/oc2-d";
const freshArgs = () => parseEnrollArgs(["--oc2", "--provider", "xai", "--id", "oauth:xai", "--main", "--min-ttl-ms", "0", "--token-lifetime-ms", "2", "--oc2-method", "device"]);
const existingArgs = (provider = "deepseek") => parseEnrollArgs(["--oc2", "--provider", provider]);
const manifest = (provider = "deepseek", shape: "api" | "oauth" = "api", serve = OUR_PLUGIN_ID): OpenCodeHandleFileV1 => ({ version: 1, providers: [{ provider, shape, serve, accounts: [{ label: "main", handle, credential_id: `${shape === "api" ? "apikey" : "oauth"}:${provider}:main` }] }] });
const entry = (value: unknown, provider = "deepseek", active = true, id = "cred_old"): Oc2CredentialEntry => ({ id, integrationID: provider, label: "old label", active, value });

function fixture(previous: Oc2CredentialEntry[] = [], handles: OpenCodeHandleFileV1 = { version: 1, providers: [] }) {
  const events: string[] = [];
  let imported: Oc2CredentialEntry[] = [];
  let current = previous;
  let mismatch = false;
  const cli: Oc2Credentials = {
    exportCredentials: async () => { events.push("export"); return current; },
    importCredentials: async (entries) => { events.push("import"); imported = entries; },
    switchCredential: async (_provider, id) => { events.push("switch"); if (!mismatch) current = imported.map((item) => ({ ...item, active: item.id === id })); },
    logoutCredential: async (_provider, id) => { events.push(`logout:${id}`); },
  };
  const deps: EnrollDependencies = {
    readManifest: async () => handles,
    readHandle: async () => handle,
    connect: async () => { events.push("connect"); return {
      getCredential: async (givenHandle, ttl) => { events.push("get"); expect(givenHandle).toBe(handle); expect(ttl).toBe(0); return { credentialId: handles.providers[0]?.accounts[0]?.credential_id ?? "oauth:xai", material: secret, recordVersion: 1, expiresAtMs: null }; },
      close: () => { events.push("close"); },
    }; },
    writeManifest: async () => { events.push("manifest"); },
    removeManifest: async () => { throw new Error("unexpected remove"); },
    writeTombstone: async () => { throw new Error("unexpected V1 write"); },
    oc2: cli,
  };
  return { events, deps, cli, imported: () => imported, mismatch: () => { mismatch = true; } };
}

describe("OC2 enrol", () => {
  test("unsafe providers and voice key shapes refuse before vault or CLI calls", async () => {
    for (const provider of [...OC2_CREDENTIAL_CONSUMERS, "xai", "openai"]) {
      const f = fixture([], manifest(provider));
      await expect(runEnrollment(existingArgs(provider), f.deps)).rejects.toThrow(provider === "xai" || provider === "openai" ? "realtime" : `OpenCode 2's built-in ${provider} plugin reads the stored credential outside the request hooks`);
      expect(f.events).toEqual([]);
    }
  });
  test("fresh xai imports exactly one entry, activates and reads back before manifest", async () => {
    const f = fixture();
    const text = await runEnrollment(freshArgs(), f.deps);
    expect(f.events).toEqual(["connect", "get", "export", "import", "switch", "export", "manifest", "close"]);
    expect(f.imported()).toEqual([{ id: expect.stringMatching(/^cred_claustrum_[a-f0-9]{16}$/), integrationID: "xai", label: "claustrum custody", active: true, value: v2OauthTombstone("xai", "device") }]);
    expect(text).toContain("opencode service restart"); expect(text).not.toContain(secret);
  });
  test("existing provider proves every account and leaves real manifest byte-identical", async () => {
    await mkdir(base, { recursive: true });
    const path = `${base}/existing-handles.json`;
    const handles = manifest(); handles.providers[0]!.accounts.push({ ...handles.providers[0]!.accounts[0]!, label: "work", credential_id: "apikey:deepseek:work" });
    const bytes = JSON.stringify(handles, null, 4) + "\n";
    await writeFile(path, bytes, { mode: 0o600 }); await chmod(path, 0o600);
    const f = fixture([], handles);
    f.deps.readManifest = readHandleFile;
    let reads = 0;
    f.deps.connect = async () => ({ getCredential: async () => ({ credentialId: handles.providers[0]!.accounts[reads++]!.credential_id, material: secret, recordVersion: 1, expiresAtMs: null }), close() {} });
    await runEnrollment({ ...existingArgs(), manifestPath: path }, f.deps);
    expect(reads).toBe(2); expect(f.events).not.toContain("manifest"); expect(await readFile(path, "utf8")).toBe(bytes);
    expect(f.imported()[0]!.value).toEqual(v2KeyTombstone("deepseek"));
  });
  test("existing providers reject enrollment flags and foreign owners; absent non-xai refuses", async () => {
    for (const flag of [["--id", "apikey:deepseek:main"], ["--main"], ["--handle-file", "/handle"], ["--min-ttl-ms", "0"], ["--token-lifetime-ms", "2"]]) {
      const f = fixture([], manifest());
      await expect(runEnrollment(parseEnrollArgs(["--oc2", "--provider", "deepseek", ...flag]), f.deps)).rejects.toThrow("provider already enrolled in the handle manifest");
      expect(f.events).toEqual([]);
    }
    const foreign = fixture([], manifest("deepseek", "api", "other-plugin"));
    await expect(runEnrollment(existingArgs(), foreign.deps)).rejects.toThrow("other-plugin"); expect(foreign.events).toEqual([]);
    const absent = fixture(); await expect(runEnrollment(existingArgs(), absent.deps)).rejects.toThrow("add the provider to the handle manifest first (ck auth migrate-opencode --provider deepseek)"); expect(absent.events).toEqual([]);
  });
  test("idempotent active tombstone needs no import or switch and writes fresh manifest", async () => {
    const f = fixture([entry(v2OauthTombstone("xai", "device"), "xai")]);
    await runEnrollment(freshArgs(), f.deps);
    expect(f.events).toEqual(["connect", "get", "export", "export", "manifest", "close"]);
  });
  test("removes inactive tombstone leftovers without touching the active target or other integrations", async () => {
    const f = fixture([
      entry(v2OauthTombstone("xai", "device"), "xai", true, "cred_active"),
      entry(v2OauthTombstone("xai", "device"), "xai", false, "cred_leftover"),
      entry(v2KeyTombstone("deepseek"), "deepseek", false, "cred_other"),
      entry({ type: "oauth", methodID: "device", access: secret, refresh: secret, expires: 1 }, "xai", false, "cred_real"),
    ]);
    await runEnrollment(freshArgs(), f.deps);
    expect(f.events.filter((event) => event.startsWith("logout:"))).toEqual(["logout:cred_leftover"]);
    expect(f.events).not.toContain("import");
  });
  test("a switch failure after import names the imported id and safe finish or undo commands", async () => {
    const f = fixture();
    f.cli.switchCredential = async () => {
      const error = new Oc2CredentialError("switch", 17, "failed");
      error.message += secret;
      throw error;
    };
    let caught: unknown;
    try { await runEnrollment(freshArgs(), f.deps); } catch (error) { caught = error; }
    const id = f.imported()[0]?.id;
    expect(typeof id).toBe("string");
    expect(caught).toBeInstanceOf(Oc2CredentialError);
    const message = String(caught);
    expect(message.includes(`opencode auth switch xai ${id}`)).toBe(true);
    expect(message.includes(`opencode auth logout xai ${id}`)).toBe(true);
    expect(message.includes(secret)).toBe(false);
    expect(f.events).not.toContain("manifest");
  });
  test("replaces migrated OAuth and removes stale tombstones including inactive drift", async () => {
    const f = fixture([entry({ type: "oauth", methodID: "old-method", access: "", refresh: sentinel("xai"), expires: 0 }, "xai"), entry({ type: "key", key: sentinel("other") }, "xai", false, "cred_drift")]);
    await runEnrollment({ ...freshArgs(), oc2Method: undefined }, f.deps);
    expect(f.imported()[0]!.value).toEqual(v2OauthTombstone("xai", "old-method"));
    expect(f.events).toEqual(["connect", "get", "export", "import", "switch", "export", "logout:cred_old", "logout:cred_drift", "manifest", "close"]);
  });
  test("keeps real active key with notice, preserves configuration, removes only on request", async () => {
    for (const removePrevious of [false, true]) {
      const f = fixture([entry({ type: "key", key: secret, configuration: { region: "eu" } })], manifest());
      const text = await runEnrollment({ ...existingArgs(), removePrevious }, f.deps);
      expect(f.imported()[0]!.value).toEqual({ ...v2KeyTombstone("deepseek"), configuration: { region: "eu" } });
      expect(f.events.includes("logout:cred_old")).toBe(removePrevious);
      if (!removePrevious) { expect(text).toContain("cred_old"); expect(text).toContain("old label"); expect(text).toContain("opencode auth logout deepseek cred_old"); }
      expect(text).not.toContain(secret);
    }
  });
  test("OAuth requires a method and key shape rejects --oc2-method", async () => {
    const f = fixture(); await expect(runEnrollment({ ...freshArgs(), oc2Method: undefined }, f.deps)).rejects.toThrow("pass --oc2-method"); expect(f.events).not.toContain("manifest");
    const key = fixture([], manifest()); await expect(runEnrollment({ ...existingArgs(), oc2Method: "device" }, key.deps)).rejects.toThrow("oauth only"); expect(key.events).toEqual([]);
  });
  test("readback mismatch fails without manifest", async () => {
    const f = fixture(); f.mismatch();
    await expect(runEnrollment(freshArgs(), f.deps)).rejects.toThrow("OpenCode 2 readback did not show the tombstone active"); expect(f.events).not.toContain("manifest");
  });
  test("readback rejects a wrong id, inactive tombstone, or non-tombstone value", async () => {
    for (const mismatch of ["id", "active", "value"] as const) {
      const f = fixture(); const original = f.cli.exportCredentials; let calls = 0;
      f.cli.exportCredentials = async (provider) => {
        const entries = await original(provider);
        if (++calls === 1) return entries;
        return entries.map((item) => mismatch === "id" ? { ...item, id: "cred_other" } : mismatch === "active" ? { ...item, active: false } : { ...item, value: { type: "key", key: secret } });
      };
      await expect(runEnrollment(freshArgs(), f.deps)).rejects.toThrow("OpenCode 2 readback did not show the tombstone active");
      expect(f.events).not.toContain("manifest");
    }
  });
  test("existing manifest accounts must all prove matching usable vault material before export", async () => {
    for (const failure of ["identity", "empty", "read"] as const) {
      const f = fixture([], manifest());
      f.deps.connect = async () => ({ getCredential: async () => {
        if (failure === "read") throw new Error(secret);
        return { credentialId: failure === "identity" ? "apikey:other:main" : "apikey:deepseek:main", material: failure === "empty" ? "" : secret, recordVersion: 1, expiresAtMs: null };
      }, close() {} });
      await expect(runEnrollment(existingArgs(), f.deps)).rejects.toThrow(failure === "identity" ? "credential identity mismatch" : failure === "empty" ? "credential did not serve usable material" : "vault read failed");
      expect(f.events).toEqual([]);
    }
  });
  test("every CLI failure is typed and never includes exported secrets or writes manifest", async () => {
    for (const step of ["export", "import", "switch", "readback", "logout"] as const) {
      const f = fixture([entry({ type: "oauth", methodID: "device", access: secret, refresh: secret, expires: 1 }, "xai")]);
      let exports = 0;
      const fail = () => { throw new Oc2CredentialError(step === "readback" ? "export" : step, 17, "failed"); };
      const original = f.cli.exportCredentials;
      f.cli.exportCredentials = async (provider) => { exports++; if (step === "export" || (step === "readback" && exports === 2)) return fail(); return original(provider); };
      if (step === "import") f.cli.importCredentials = fail;
      if (step === "switch") f.cli.switchCredential = fail;
      if (step === "logout") f.cli.logoutCredential = fail;
      try { await runEnrollment({ ...freshArgs(), removePrevious: true }, f.deps); throw new Error("expected refusal"); } catch (error) {
        expect(error).toBeInstanceOf(Oc2CredentialError); expect(String(error)).toContain(step === "readback" ? "export" : step); expect(String(error)).not.toContain(secret);
      }
      expect(f.events).not.toContain("manifest");
    }
  });
});

const script = `${base}/fake-opencode.ts`;
beforeAll(async () => {
  await mkdir(base, { recursive: true });
  await writeFile(script, `#!${process.execPath}\nconst args = process.argv.slice(2);\nconst mode = args[args.indexOf("--server") + 1];\nif (mode === "timeout") { await Bun.sleep(10000); }\nelse if (mode === "cap") { process.stdout.write("x".repeat(4 * 1024 * 1024 + 1)); }\nelse if (mode === "stderr-cap") { process.stderr.write("x".repeat(64 * 1024 + 1)); }\nelse if (mode === "failure") { process.stdout.write("${secret}"); process.stderr.write("${secret}"); process.exit(17); }\nelse if (mode === "bad-json") { process.stdout.write("${secret}"); }\nelse if (args[1] === "import") { await Bun.write("${base}/stdin.json", await Bun.stdin.text()); await Bun.write("${base}/argv.json", JSON.stringify(args)); }\nelse if (args[1] === "export") { process.stdout.write(JSON.stringify([{id:"cred_old", integrationID:args[2],label:"fixture",active:true,value:{type:"key",key:"${secret}"}}])); }\nelse { await Bun.write("${base}/argv.json", JSON.stringify(args)); }\n`);
  await chmod(script, 0o700);
});

describe("bounded OC2 CLI runner", () => {
  test("uses argv arrays and import stdin, never credentials in argv", async () => {
    const cli = createOc2Credentials({ opencodeBin: script, oc2Standalone: true });
    const payload = [entry({ type: "key", key: secret })];
    await cli.importCredentials(payload);
    expect(await readFile(`${base}/stdin.json`, "utf8")).toBe(JSON.stringify(payload));
    expect(JSON.parse(await readFile(`${base}/argv.json`, "utf8"))).toEqual(["auth", "import", "--standalone"]);
    await cli.switchCredential("provider with spaces;", "cred_quoted'");
    expect(JSON.parse(await readFile(`${base}/argv.json`, "utf8"))).toEqual(["auth", "switch", "provider with spaces;", "cred_quoted'", "--standalone"]);
    await cli.logoutCredential("deepseek", "cred_old");
    expect(JSON.parse(await readFile(`${base}/argv.json`, "utf8"))).toEqual(["auth", "logout", "deepseek", "cred_old", "--standalone"]);
    expect((await cli.exportCredentials("deepseek"))[0]!.value).toEqual({ type: "key", key: secret });
  });
  test("nonzero exit and malformed export never disclose stdout or stderr", async () => {
    for (const oc2Server of ["failure", "bad-json"]) {
      try { await createOc2Credentials({ opencodeBin: script, oc2Server }).exportCredentials("deepseek"); throw new Error("expected failure"); } catch (error) {
        expect(error).toBeInstanceOf(Oc2CredentialError); expect(String(error)).toContain("export"); expect(String(error)).not.toContain(secret);
        if (error instanceof Oc2CredentialError) { expect(error.exitCode).toBe(oc2Server === "failure" ? 17 : 0); expect(JSON.stringify(error)).not.toContain(secret); }
      }
    }
  });
  test("enforces stdout and stderr byte caps and timeout", async () => {
    for (const oc2Server of ["cap", "stderr-cap", "timeout"]) await expect(createOc2Credentials({ opencodeBin: script, oc2Server, timeoutMs: oc2Server === "timeout" ? 100 : 30000 }).exportCredentials("deepseek")).rejects.toThrow(oc2Server === "timeout" ? "timeout" : "limit");
  });
});
