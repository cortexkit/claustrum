import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { parseArgs } from "node:util";
import { defaultHandleFilePath, HANDLE_FILE_CONTRACT, credentialIdMatchesProvider, ClaustrumClient, type ServedCredential } from "@cortexkit/claustrum-client";
import { writeEnrollmentManifest, removeEnrollmentManifest, type XaiEnrollment } from "./enroll-manifest";
import { writeOAuthTombstone, type TombstoneResult } from "./enroll-tombstone";
import { defaultAuthPath } from "./plugin";

export type EnrollArgs = { provider: "xai"; credentialId: "oauth:xai"; main: boolean; remove: boolean; handleFile?: string; minTtlMs?: number; tokenLifetimeMs?: number; manifestPath: string; authPath: string; };
export type EnrollClient = { getCredential(handle: string, minTtlMs?: number): Promise<ServedCredential>; close(): void; };
export type EnrollDependencies = { connect(): Promise<EnrollClient>; readHandle(path: string): Promise<string>; writeManifest(path: string, input: XaiEnrollment): Promise<void>; removeManifest(path: string, input: { provider: "xai"; credentialId: "oauth:xai" }): Promise<void>; writeTombstone(path: string, provider: string): Promise<TombstoneResult>; };

const help = `Usage: bun run enroll -- --provider xai --id oauth:xai --main --min-ttl-ms <ms> --token-lifetime-ms <ms>\n\nv1 supports only --provider xai --id oauth:xai. The manifest records local serving; --remove removes it before /login.\n\nOptions: --handle-file <path>, --manifest-path <path>, --auth-path <path>, --remove, --help`;

function rejectDuplicateFlags(argv: string[]): void {
  const seen = new Set<string>();
  const valueFlags = new Set(["--provider", "--id", "--handle-file", "--min-ttl-ms", "--token-lifetime-ms", "--manifest-path", "--auth-path"]);
  for (let index = 0; index < argv.length; index++) {
    const current = argv[index]!;
    const flag = current.split("=", 1)[0]!;
    if (!valueFlags.has(flag) && !["--main", "--remove", "--help"].includes(flag)) continue;
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
    } }).values;
  } catch { throw new Error("invalid enrollment arguments"); }
  const provider = stringOption(values.provider);
  const id = stringOption(values.id);
  const main = values.main === true;
  const remove = values.remove === true;
  if (typeof provider !== "string" || typeof id !== "string") throw new Error("missing required --provider or --id");
  if (!credentialIdMatchesProvider(id, provider)) throw new Error("invalid credential id for provider");
  if (provider !== "xai" || id !== "oauth:xai") throw new Error("v1 supports only --provider xai --id oauth:xai");
  if (!main) throw new Error("two-segment main id requires --main");
  const minTtlMs = numberOption(values["min-ttl-ms"]);
  const tokenLifetimeMs = numberOption(values["token-lifetime-ms"]);
  if (!remove && (minTtlMs === undefined || tokenLifetimeMs === undefined || !Number.isSafeInteger(minTtlMs) || minTtlMs < 0 || !Number.isSafeInteger(tokenLifetimeMs) || tokenLifetimeMs <= 0 || minTtlMs >= tokenLifetimeMs)) throw new Error("minTtlMs must be below measured token lifetime");
  if (remove && (values["handle-file"] !== undefined || values["min-ttl-ms"] !== undefined || values["token-lifetime-ms"] !== undefined)) throw new Error("--remove rejects handle and TTL flags");
  return {
    provider: "xai", credentialId: "oauth:xai", main, remove,
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
    const bytes = Buffer.alloc(257);
    const { bytesRead } = await descriptor.read(bytes, 0, bytes.length, 0);
    if (bytesRead > 256) throw new Error("handle file exceeds limit");
    const handle = bytes.subarray(0, bytesRead).toString("utf8").replace(/^\s+|\s+$/g, "");
    if (!HANDLE_FILE_CONTRACT.handleRe.test(handle)) throw new Error("invalid handle file");
    return handle;
  } finally { await descriptor?.close().catch(() => {}); }
}

function defaultDependencies(): EnrollDependencies {
  return { connect: () => ClaustrumClient.connect({ logger: () => {} }), readHandle: readEnrollmentHandle, writeManifest: writeEnrollmentManifest, removeManifest: removeEnrollmentManifest, writeTombstone: writeOAuthTombstone };
}

export async function runEnrollment(args: EnrollArgs, deps: EnrollDependencies = defaultDependencies()): Promise<string> {
  if (args.remove) {
    try { await deps.removeManifest(args.manifestPath, { provider: args.provider, credentialId: args.credentialId }); } catch { throw new Error("manifest removal failed"); }
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
    try { await deps.writeManifest(args.manifestPath, { provider: args.provider, credentialId: args.credentialId, handle, minTtlMs: args.minTtlMs! }); } catch { throw new Error("manifest write failed"); }
    try { await deps.writeTombstone(args.authPath, args.provider); } catch { throw new Error("tombstone write failed after manifest write; manifest entry remains — run --remove before /login"); }
    return "Enrolled xai main in opencode-claustrum; reload OpenCode.";
  } finally {
    // A throwing close() in finally would replace the wrapped error above.
    try { client.close(); } catch { /* ignore */ }
  }
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
