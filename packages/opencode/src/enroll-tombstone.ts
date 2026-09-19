import { constants as fsConstants, type Stats } from "node:fs";
import { lstat, mkdir, open, rename, stat, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { identifierIsValid } from "@cortexkit/claustrum-client";
import { readBounded } from "./bounded-read";
import { AuthFileValidationError } from "./errors";
import { parseSecretJson } from "./secret-json";
import { isProviderTombstone, tombstoneFor } from "./tombstone";

export type AuthTombstoneIo = {
  read(path: string): Promise<Buffer | null>;
  write(path: string, bytes: Buffer): Promise<void>;
  lstat(path: string): Promise<Stats>;
  rename(from: string, to: string): Promise<void>;
};

export type TombstoneResult = { writes: 0 | 1 | 2 };

export async function writeOAuthTombstone(path: string, provider: string, io?: AuthTombstoneIo): Promise<TombstoneResult> {
  if (!identifierIsValid(provider)) throw new Error("invalid auth provider identifier");
  const effective = io ?? defaultIo();
  const before = await effective.read(path);
  let auth: Record<string, unknown>;
  const parsed = parseSecretJson(before?.toString("utf8") ?? "{}", "auth file");
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new AuthFileValidationError("auth file must contain a JSON object");
  auth = parsed as Record<string, unknown>;
  if (isProviderTombstone(auth[provider], provider)) return { writes: 0 };
  const next = Buffer.from(JSON.stringify({ ...auth, [provider]: tombstoneFor("oauth", provider) }) + "\n");
  for (let attempt = 0; attempt < 2; attempt++) {
    await effective.write(path, next);
    const after = await effective.read(path);
    if (after !== null && after.equals(next)) return { writes: (attempt + 1) as 1 | 2 };
    const restoredOld = before === null ? after === null : after !== null && after.equals(before);
    if (after === null && before !== null) throw new Error("auth file disappeared during enrolment; nothing written back");
    if (!restoredOld) throw new Error("auth changed during enrolment; newer material left untouched");
    if (attempt === 1) throw new Error("auth repeatedly restored by workspace child; stop the child and retry");
  }
  throw new Error("unreachable reconciliation state");
}

export function defaultIo(): AuthTombstoneIo {
  return {
    lstat,
    rename,
    async read(this: AuthTombstoneIo, path) { return readAuth(path, this); },
    async write(this: AuthTombstoneIo, path, bytes) { return writeAuth(path, bytes, this); },
  };
}

async function readAuth(path: string, io: AuthTombstoneIo): Promise<Buffer | null> {
  let metadata;
  try { metadata = await io.lstat(path); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error("unable to inspect auth file");
  }
  // Parent and ancestor checks are omitted because caller-owned 0600 plus O_NOFOLLOW defeats the swap they guard against.
  // handles.ts retains those checks because its broader reader contract does not require caller ownership.
  if (!metadata.isFile() || metadata.uid !== process.getuid?.() || (metadata.mode & 0o777) !== 0o600) throw new AuthFileValidationError("auth file must be a regular 0600 file");
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const { buffer, bytes } = await readBounded(handle, 1024 * 1024);
    if (bytes === -1) throw new AuthFileValidationError("auth file exceeds 1 MiB");
    return buffer.subarray(0, bytes);
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function prepareParent(path: string): Promise<void> {
  const parent = dirname(path);
  try { await mkdir(parent, { recursive: true, mode: 0o700 }); } catch { throw new AuthFileValidationError("auth file parent cannot be created"); }
  let metadata;
  try { metadata = await stat(parent); } catch { throw new AuthFileValidationError("auth file parent is unavailable"); }
  if (!metadata.isDirectory() || ((metadata.mode & 0o002) !== 0 && (metadata.mode & 0o1000) === 0) || (metadata.mode & 0o022) !== 0) throw new AuthFileValidationError("auth file parent must be private");
}

async function writeAuth(path: string, bytes: Buffer, io: AuthTombstoneIo): Promise<void> {
  await prepareParent(path);
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
    await handle.chmod(0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    let destination;
    try { destination = await io.lstat(path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (destination && (!destination.isFile() || (destination.mode & 0o777) !== 0o600)) throw new AuthFileValidationError("auth file must be a regular 0600 file");
    await io.rename(temporary, path);
  } catch (error) {
    if (error instanceof AuthFileValidationError) throw error;
    try {
      const destination = await io.lstat(path);
      if (!destination.isFile() || (destination.mode & 0o777) !== 0o600) {
        throw new AuthFileValidationError("auth file must be a regular 0600 file");
      }
    } catch (destinationError) {
      if (destinationError instanceof AuthFileValidationError) throw destinationError;
    }
    throw new Error("auth file replacement failed");
  } finally {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
  }
}
