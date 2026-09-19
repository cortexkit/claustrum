import {
  credentialIdMatchesProvider,
  HANDLE_FILE_CONTRACT,
  identifierIsValid,
  writeHandleFileLocked,
  type ManifestHandleFile,
} from "@cortexkit/claustrum-client";
import { OUR_PLUGIN_ID } from "./handles";

export type XaiEnrollment = { provider: "xai"; credentialId: "oauth:xai"; handle: string; minTtlMs: number };

function validateCredential(provider: string, credentialId: string): void {
  if (!identifierIsValid(provider) || !credentialIdMatchesProvider(credentialId, provider) || credentialId !== "oauth:xai") throw new Error("invalid xai enrollment credential");
}

function validate(input: XaiEnrollment): void {
  validateCredential(input.provider, input.credentialId);
  if (!HANDLE_FILE_CONTRACT.handleRe.test(input.handle)) throw new Error("invalid xai enrollment handle");
  if (!Number.isSafeInteger(input.minTtlMs) || input.minTtlMs < 0) throw new Error("invalid xai enrollment minTtlMs");
}

function mutateAdd(file: ManifestHandleFile, input: XaiEnrollment): void {
  const index = file.providers.findIndex((p) => p.provider === input.provider);
  const existing = index === -1 ? undefined : file.providers[index]!;
  if (existing && existing.serve !== OUR_PLUGIN_ID) throw new Error("xai manifest block is owned by another tenant");
  if (existing && existing.shape !== "oauth") throw new Error("xai manifest block has a non-oauth shape");
  if (existing && existing.accounts.length !== 1) throw new Error("xai manifest block has unexpected accounts");
  if (existing && existing.accounts[0]!.credential_id !== input.credentialId) throw new Error("xai manifest block binds a different credential");
  if (existing && existing.accounts[0]!.handle !== input.handle) throw new Error("xai main handle differs; remove first, then enroll");
  if (!existing) {
    file.providers.push({ provider: input.provider, shape: "oauth", serve: OUR_PLUGIN_ID, accounts: [{ label: "main", handle: input.handle, credential_id: input.credentialId, minTtlMs: input.minTtlMs }] });
  } else {
    existing.accounts[0] = { ...existing.accounts[0], minTtlMs: input.minTtlMs };
  }
}

export async function writeEnrollmentManifest(path: string, input: XaiEnrollment): Promise<void> {
  validate(input);
  await writeHandleFileLocked(path, OUR_PLUGIN_ID, (file) => mutateAdd(file, input));
}

export async function removeEnrollmentManifest(path: string, input: { provider: "xai"; credentialId: "oauth:xai" }): Promise<void> {
  validateCredential(input.provider, input.credentialId);
  await writeHandleFileLocked(path, OUR_PLUGIN_ID, (file) => {
    const index = file.providers.findIndex((p) => p.provider === input.provider);
    if (index === -1) return;
    const existing = file.providers[index]!;
    if (existing.serve !== OUR_PLUGIN_ID) throw new Error("xai manifest block is owned by another tenant");
    const accounts = existing.accounts.filter((account) => account.credential_id !== input.credentialId);
    if (accounts.length === 0) file.providers.splice(index, 1);
    else file.providers[index] = { ...existing, accounts };
  });
}
