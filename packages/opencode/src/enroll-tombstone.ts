import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, rename, stat, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { identifierIsValid } from "@cortexkit/claustrum-client";
import { parseSecretJson } from "./secret-json";
import { isProviderTombstone, tombstoneFor } from "./tombstone";

export type AuthTombstoneIo = {
  read(path: string): Promise<Buffer | null>;
  write(path: string, bytes: Buffer): Promise<void>;
};

export type TombstoneResult = { writes: 0 | 1 | 2 };

export async function writeOAuthTombstone(path: string, provider: string, io?: AuthTombstoneIo): Promise<TombstoneResult> {
  if (!identifierIsValid(provider)) throw new Error("invalid auth provider identifier");
  const effective = io ?? defaultIo();
  const before = await effective.read(path);
  let auth: Record<string, unknown>;
  try {
    const parsed = parseSecretJson(before?.toString("utf8") ?? "{}", "auth file");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("auth file must contain a JSON object");
    auth = parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof Error && error.message === "auth file must contain a JSON object") throw error;
    throw error;
  }
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

function defaultIo(): AuthTombstoneIo {
  return { read: readAuth, write: writeAuth };
}

async function readAuth(path: string): Promise<Buffer | null> {
  let metadata;
  try { metadata = await lstat(path); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error("unable to inspect auth file");
  }
  if (!metadata.isFile() || metadata.uid !== process.getuid?.() || (metadata.mode & 0o777) !== 0o600) throw new Error("auth file must be a regular 0600 file");
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const bytes = Buffer.alloc(1024 * 1024 + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead > 1024 * 1024) throw new Error("auth file exceeds 1 MiB");
    return bytes.subarray(0, bytesRead);
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function prepareParent(path: string): Promise<void> {
  const parent = dirname(path);
  try { await mkdir(parent, { recursive: true, mode: 0o700 }); } catch { throw new Error("auth file parent cannot be created"); }
  let metadata;
  try { metadata = await stat(parent); } catch { throw new Error("auth file parent is unavailable"); }
  if (!metadata.isDirectory() || ((metadata.mode & 0o002) !== 0 && (metadata.mode & 0o1000) === 0) || (metadata.mode & 0o022) !== 0) throw new Error("auth file parent must be private");
}

async function writeAuth(path: string, bytes: Buffer): Promise<void> {
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
    try { destination = await lstat(path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (destination && (!destination.isFile() || (destination.mode & 0o777) !== 0o600)) throw new Error("auth file must be a regular 0600 file");
    await rename(temporary, path);
  } catch {
    throw new Error("auth file replacement failed");
  } finally {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
  }
}
