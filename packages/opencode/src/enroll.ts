import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { parseArgs } from "node:util";
import { defaultHandleFilePath, HANDLE_FILE_CONTRACT, credentialIdMatchesProvider, identifierIsValid, ClaustrumClient, type ServedCredential } from "@cortexkit/claustrum-client";
import { writeEnrollmentManifest, removeEnrollmentManifest, type XaiEnrollment } from "./enroll-manifest";
import { writeOAuthTombstone, type TombstoneResult } from "./enroll-tombstone";
import { readBounded } from "./bounded-read";
import { defaultAuthPath } from "./plugin";
import { OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "./handles";
import { createOc2Credentials, formatOc2AuthCommand, Oc2CredentialError, OC2_CREDENTIAL_CONSUMERS, type Oc2Credentials, type Oc2CredentialEntry } from "./v2/oc2-credentials";
import { classifyV2Credential, v2KeyTombstone, v2OauthTombstone } from "./v2/tombstone";

export type EnrollArgs = { provider: string; credentialId?: string; main: boolean; remove: boolean; handleFile?: string; minTtlMs?: number; tokenLifetimeMs?: number; manifestPath: string; authPath: string; oc2?: boolean; opencodeBin?: string; oc2Standalone?: boolean; oc2Server?: string; oc2Method?: string; removePrevious?: boolean; oc2EnrollmentFlags?: boolean; };
export type EnrollClient = { getCredential(handle: string, minTtlMs?: number): Promise<ServedCredential>; close(): void; };
export type EnrollDependencies = { connect(): Promise<EnrollClient>; readHandle(path: string): Promise<string>; writeManifest(path: string, input: XaiEnrollment): Promise<void>; removeManifest(path: string, input: { provider: "xai"; credentialId: "oauth:xai" }): Promise<void>; writeTombstone(path: string, provider: string): Promise<TombstoneResult>; readManifest?(path: string): Promise<OpenCodeHandleFileV1>; oc2?: Oc2Credentials; };

const help = `Usage: bun run enroll -- --provider xai --id oauth:xai --main --min-ttl-ms <ms> --token-lifetime-ms <ms>
       bun run enroll -- --oc2 --provider <provider>
       bun run enroll -- --oc2 --provider xai --id oauth:xai --main --min-ttl-ms <ms> --token-lifetime-ms <ms>

v1 supports only --provider xai --id oauth:xai. The manifest records local serving; --remove removes it before /login.

OpenCode 2: --oc2 uses an existing owned handle manifest entry. Only fresh xai accepts the V1 enrollment flags.
OC2 options: --opencode-bin <path> (default opencode), --oc2-standalone or --oc2-server <url>, --oc2-method <id> (oauth only), --remove-previous.
--oc2 rejects --remove; remove the manifest entry separately to hand ownership back to OpenCode.

Options: --handle-file <path>, --manifest-path <path>, --auth-path <path>, --remove, --help`;

function rejectDuplicateFlags(argv: string[]): void {
  const seen = new Set<string>();
  const valueFlags = new Set(["--provider", "--id", "--handle-file", "--min-ttl-ms", "--token-lifetime-ms", "--manifest-path", "--auth-path", "--opencode-bin", "--oc2-server", "--oc2-method"]);
  for (let index = 0; index < argv.length; index++) {
    const current = argv[index]!;
    const flag = current.split("=", 1)[0]!;
    if (!valueFlags.has(flag) && !["--main", "--remove", "--help", "--oc2", "--oc2-standalone", "--remove-previous"].includes(flag)) continue;
    if (seen.has(flag)) throw new Error("duplicate flag");
    seen.add(flag);
    if (valueFlags.has(flag) && !current.includes("=")) index++;
  }
}

function stringOption(value: unknown): string | undefined { return typeof value === "string" ? value : undefined; }

function numberOption(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  if (!/^(0|[1-9][0-9]*)$/.test(value)) return Number.NaN;
  return Number(value);
}

function normalizeNegativeValues(argv: string[]): string[] {
  const result: string[] = [];
  for (let index = 0; index < argv.length; index++) {
    const current = argv[index]!;
    const next = argv[index + 1];
    if (["--min-ttl-ms", "--token-lifetime-ms"].includes(current) && typeof next === "string" && /^-[0-9]/.test(next)) {
      result.push(`${current}=${next}`);
      index++;
    } else result.push(current);
  }
  return result;
}

export function parseEnrollArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): EnrollArgs {
  const effective = argv[0] === "--" ? argv.slice(1) : argv;
  rejectDuplicateFlags(effective);
  const normalized = normalizeNegativeValues(effective);
  let values: ReturnType<typeof parseArgs>["values"];
  try {
    values = parseArgs({ args: normalized, strict: true, allowPositionals: false, options: {
      provider: { type: "string" }, id: { type: "string" }, main: { type: "boolean", default: false }, remove: { type: "boolean", default: false },
      "handle-file": { type: "string" }, "min-ttl-ms": { type: "string" }, "token-lifetime-ms": { type: "string" }, "manifest-path": { type: "string" }, "auth-path": { type: "string" },
      oc2: { type: "boolean" }, "opencode-bin": { type: "string" }, "oc2-standalone": { type: "boolean" }, "oc2-server": { type: "string" }, "oc2-method": { type: "string" }, "remove-previous": { type: "boolean" },
    } }).values;
  } catch { throw new Error("invalid enrollment arguments"); }
  const provider = stringOption(values.provider);
  const id = stringOption(values.id);
  const main = values.main === true;
  const remove = values.remove === true;
  const oc2 = values.oc2 === true;
  if (!oc2 && ["opencode-bin", "oc2-standalone", "oc2-server", "oc2-method", "remove-previous"].some((key) => values[key] !== undefined)) throw new Error("OpenCode 2 flags require --oc2");
  if (oc2 && values["oc2-standalone"] && values["oc2-server"] !== undefined) throw new Error("--oc2-standalone and --oc2-server are mutually exclusive");
  if (oc2 && remove) throw new Error("--oc2 rejects --remove; remove the manifest separately");
  if (typeof provider !== "string" || (!oc2 && typeof id !== "string")) throw new Error("missing required --provider or --id");
  if (!identifierIsValid(provider) || (id !== undefined && !credentialIdMatchesProvider(id, provider))) throw new Error("invalid credential id for provider");
  if (!oc2 && (provider !== "xai" || id !== "oauth:xai")) throw new Error("v1 supports only --provider xai --id oauth:xai");
  if (!oc2 && !main) throw new Error("two-segment main id requires --main");
  const minTtlMs = numberOption(values["min-ttl-ms"]);
  const tokenLifetimeMs = numberOption(values["token-lifetime-ms"]);
  if (!oc2 && !remove && (minTtlMs === undefined || tokenLifetimeMs === undefined || !Number.isSafeInteger(minTtlMs) || minTtlMs < 0 || !Number.isSafeInteger(tokenLifetimeMs) || tokenLifetimeMs <= 0 || minTtlMs >= tokenLifetimeMs)) throw new Error("minTtlMs must be below measured token lifetime");
  if (remove && (values["handle-file"] !== undefined || values["min-ttl-ms"] !== undefined || values["token-lifetime-ms"] !== undefined)) throw new Error("--remove rejects handle and TTL flags");
  return {
    provider, credentialId: id, main, remove,
    ...(oc2 ? { oc2, opencodeBin: stringOption(values["opencode-bin"]) ?? "opencode", oc2Standalone: values["oc2-standalone"] === true, oc2Server: stringOption(values["oc2-server"]), oc2Method: stringOption(values["oc2-method"]), removePrevious: values["remove-previous"] === true, oc2EnrollmentFlags: ["id", "handle-file", "min-ttl-ms", "token-lifetime-ms"].some((key) => values[key] !== undefined) || main } : {}),
    handleFile: remove ? undefined : (stringOption(values["handle-file"]) ?? defaultHandleFilePath(env)),
    minTtlMs: remove ? undefined : minTtlMs,
    tokenLifetimeMs: remove ? undefined : tokenLifetimeMs,
    manifestPath: stringOption(values["manifest-path"]) ?? defaultHandleFilePath(env),
    authPath: stringOption(values["auth-path"]) ?? defaultAuthPath(env),
  };
}

export async function readEnrollmentHandle(path: string): Promise<string> {
  let descriptor: Awaited<ReturnType<typeof open>> | undefined;
  try {
    descriptor = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const metadata = await descriptor.stat();
    if (!metadata.isFile() || metadata.uid !== process.getuid?.() || (metadata.mode & 0o777) !== 0o600) throw new Error("unsafe handle file");
    // Parent and ancestor checks are omitted because caller-owned 0600 plus O_NOFOLLOW defeats the swap they guard against.
    // handles.ts retains those checks because its broader reader contract does not require caller ownership.
    const { buffer, bytes } = await readBounded(descriptor, 256);
    if (bytes === -1) throw new Error("handle file exceeds limit");
    const handle = buffer.subarray(0, bytes).toString("utf8").replace(/^\s+|\s+$/g, "");
    if (!HANDLE_FILE_CONTRACT.handleRe.test(handle)) throw new Error("invalid handle file");
    return handle;
  } finally { await descriptor?.close().catch(() => {}); }
}

function defaultDependencies(): EnrollDependencies {
  return { connect: () => ClaustrumClient.connect({ logger: () => {} }), readHandle: readEnrollmentHandle, writeManifest: writeEnrollmentManifest, removeManifest: removeEnrollmentManifest, writeTombstone: writeOAuthTombstone };
}

export async function runEnrollment(args: EnrollArgs, deps: EnrollDependencies = defaultDependencies()): Promise<string> {
  if (args.oc2) return runOc2Enrollment(args, deps);
  if (args.provider !== "xai" || args.credentialId !== "oauth:xai") throw new Error("v1 supports only --provider xai --id oauth:xai");
  if (args.remove) {
    try { await deps.removeManifest(args.manifestPath, { provider: "xai", credentialId: "oauth:xai" }); } catch { throw new Error("manifest removal failed"); }
    return "Manifest entry removed. Run /login for xai in OpenCode, then reload OpenCode; local serving is not restored until both complete.";
  }
  let handle: string;
  try { handle = await deps.readHandle(args.handleFile!); } catch { throw new Error("handle file unreadable"); }
  let client: EnrollClient;
  try { client = await deps.connect(); } catch { throw new Error("vault connection failed"); }
  try {
    let served: ServedCredential;
    try { served = await client.getCredential(handle, 0); } catch { throw new Error("vault read failed"); }
    if (served.credentialId !== args.credentialId) throw new Error("credential identity mismatch");
    if (!served.material) throw new Error("credential did not serve usable material");
    try { await deps.writeManifest(args.manifestPath, { provider: "xai", credentialId: "oauth:xai", handle, minTtlMs: args.minTtlMs! }); } catch { throw new Error("manifest write failed"); }
    try { await deps.writeTombstone(args.authPath, args.provider); } catch { throw new Error("tombstone write failed after manifest write; manifest entry remains — run --remove before /login"); }
    return "Enrolled xai main in opencode-claustrum; reload OpenCode.";
  } finally {
    // A throwing close() in finally would replace the wrapped error above.
    try { client.close(); } catch { /* ignore */ }
  }
}

async function runOc2Enrollment(args: EnrollArgs, deps: EnrollDependencies): Promise<string> {
  if ((OC2_CREDENTIAL_CONSUMERS as readonly string[]).includes(args.provider)) throw new Error(`OpenCode 2's built-in ${args.provider} plugin reads the stored credential outside the request hooks`);
  let manifest: OpenCodeHandleFileV1;
  try { manifest = await (deps.readManifest ?? readHandleFile)(args.manifestPath); } catch { throw new Error("handle manifest unreadable"); }
  const existing = manifest.providers.find((entry) => entry.provider === args.provider);
  if (existing && existing.serve !== OUR_PLUGIN_ID) throw new Error(`provider is owned by ${existing.serve}`);
  if (existing && args.oc2EnrollmentFlags) throw new Error("provider already enrolled in the handle manifest");
  if (!existing && (args.provider !== "xai" || args.credentialId !== "oauth:xai" || !args.main)) throw new Error(`add the provider to the handle manifest first (ck auth migrate-opencode --provider ${args.provider})`);
  const shape = existing?.shape ?? "oauth";
  // OC2 2.0.32 core/src/voice.ts:50-69 sends stored keys outside request hooks; OAuth is refused there.
  if (shape === "api" && ["openai", "xai"].includes(args.provider)) throw new Error(`OpenCode 2's ${args.provider} realtime voice reads the stored key outside the request hooks`);
  if (shape === "api" && args.oc2Method !== undefined) throw new Error("--oc2-method is oauth only");
  if (!existing && (args.minTtlMs === undefined || args.tokenLifetimeMs === undefined || !Number.isSafeInteger(args.minTtlMs) || args.minTtlMs < 0 || !Number.isSafeInteger(args.tokenLifetimeMs) || args.tokenLifetimeMs <= 0 || args.minTtlMs >= args.tokenLifetimeMs)) throw new Error("minTtlMs must be below measured token lifetime");
  let handle: string | undefined;
  if (!existing) { try { handle = await deps.readHandle(args.handleFile!); } catch { throw new Error("handle file unreadable"); } }
  const accounts = existing?.accounts ?? [{ handle: handle!, credential_id: "oauth:xai" }];
  let client: EnrollClient;
  try { client = await deps.connect(); } catch { throw new Error("vault connection failed"); }
  try {
    for (const account of accounts) {
      let served: ServedCredential;
      try { served = await client.getCredential(account.handle, 0); } catch { throw new Error("vault read failed"); }
      if (served.credentialId !== account.credential_id) throw new Error("credential identity mismatch");
      if (!served.material) throw new Error("credential did not serve usable material");
    }
    const cli = deps.oc2 ?? createOc2Credentials(args);
    const previous = await cli.exportCredentials(args.provider);
    const active = previous.find((entry) => entry.active && entry.integrationID === args.provider);
    let target: Oc2CredentialEntry;
    if (active && classifyV2Credential(active.value, args.provider) === "tombstone") target = active;
    else {
      const activeValue = active?.value as Record<string, unknown> | undefined;
      const oldOauth = previous.find((entry) => entry.integrationID === args.provider && (entry.value as Record<string, unknown> | null)?.type === "oauth")?.value as Record<string, unknown> | undefined;
      const methodID = args.oc2Method ?? (activeValue?.type === "oauth" ? activeValue.methodID : oldOauth?.methodID);
      if (shape === "oauth" && (typeof methodID !== "string" || !methodID)) throw new Error("pass --oc2-method for the OpenCode 2 OAuth integration");
      const value = shape === "api" ? { ...v2KeyTombstone(args.provider), ...(activeValue?.type === "key" && activeValue.configuration !== undefined ? { configuration: activeValue.configuration } : {}) } : v2OauthTombstone(args.provider, methodID as string);
      target = { id: `cred_claustrum_${randomBytes(8).toString("hex")}`, integrationID: args.provider, label: "claustrum custody", active: true, value };
      await cli.importCredentials([target]);
      try {
        await cli.switchCredential(args.provider, target.id);
      } catch (error) {
        const refusal = new Oc2CredentialError("switch", error instanceof Oc2CredentialError ? error.exitCode : null, "failed");
        refusal.message += `; imported credential ${target.id}; finish with: ${formatOc2AuthCommand(args, "switch", args.provider, target.id)}; undo with: ${formatOc2AuthCommand(args, "logout", args.provider, target.id)}`;
        throw refusal;
      }
    }
    const readback = (await cli.exportCredentials(args.provider)).filter((entry) => entry.integrationID === args.provider && entry.active);
    if (readback.length !== 1 || readback[0]!.id !== target.id || classifyV2Credential(readback[0]!.value, args.provider) !== "tombstone") throw new Error("OpenCode 2 readback did not show the tombstone active");
    const notices: string[] = [];
    for (const entry of previous) {
      if (entry.integrationID !== args.provider || entry.id === target.id) continue;
      const classification = classifyV2Credential(entry.value, args.provider);
      if (classification === "v1-migrated" || classification === "drift" || (!entry.active && classification === "tombstone") || (entry.active && classification === "real" && args.removePrevious)) await cli.logoutCredential(args.provider, entry.id);
      else if (entry.active && classification === "real") {
        notices.push(`Previous credential ${JSON.stringify(entry.id)} (${JSON.stringify(entry.label)}) retained. Remove it with: ${formatOc2AuthCommand(args, "logout", args.provider, entry.id)}`);
      }
    }
    // Unlike V1, fresh OC2 enrollment writes the manifest last so a failed CLI write cannot publish an unusable binding.
    if (!existing) { try { await deps.writeManifest(args.manifestPath, { provider: "xai", credentialId: "oauth:xai", handle: handle!, minTtlMs: args.minTtlMs! }); } catch { throw new Error("manifest write failed"); } }
    return [...notices, `Enrolled ${args.provider} in OpenCode 2; restart the OpenCode 2 service (opencode service restart).`].join("\n");
  } finally { try { client.close(); } catch { /* ignore */ } }
}

async function main(argv: string[]): Promise<string> {
  const effective = argv[0] === "--" ? argv.slice(1) : argv;
  if (effective.length === 1 && effective[0] === "--help") return help;
  // The parser performs the single Bun-separator strip; passing `effective` would strip twice.
  return runEnrollment(parseEnrollArgs(argv));
}

if (import.meta.main) {
  main(process.argv.slice(2)).then((message) => console.log(message)).catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "enrollment failed");
    process.exitCode = 1;
  });
}
