import { Oc2CredentialError } from "../errors";

export { Oc2CredentialError } from "../errors";

export const OC2_CREDENTIAL_CONSUMERS = [
  "azure", // OpenCode 2.0.32 packages/core/src/plugin/provider/azure.ts:280-336 — deployment discovery.
  "digitalocean", // OpenCode 2.0.32 packages/core/src/plugin/provider/digitalocean.ts:125-178 — router polling.
  "github-copilot", // OpenCode 2.0.32 packages/core/src/plugin/provider/github-copilot.ts:175-210,296-315,442 — model/title requests.
  "gitlab", // OpenCode 2.0.32 packages/core/src/plugin/provider/gitlab.ts:65-123 — workflow discovery.
  "modal", // OpenCode 2.0.32 packages/core/src/plugin/provider/modal.ts:25-73 — model discovery.
  "opencode", // OpenCode 2.0.32 packages/core/src/plugin/provider/opencode.ts:210-247,374-429,495 — config/websearch.
  "snowflake-cortex", // OpenCode 2.0.32 packages/core/src/plugin/provider/snowflake-cortex.ts:239-249 — refresh on retry.
  "exa", // OpenCode 2.0.32 packages/core/src/plugin/websearch/exa.ts:47-49 — stored-key search requests.
  "firecrawl", // OpenCode 2.0.32 packages/core/src/plugin/websearch/firecrawl.ts:58-67 — stored-key search requests.
  "parallel", // OpenCode 2.0.32 packages/core/src/plugin/websearch/parallel.ts:73-85 — stored-key search requests.
  "tavily", // OpenCode 2.0.32 packages/core/src/plugin/websearch/tavily.ts:49-56 — stored-key search requests.
  "tinyfish", // OpenCode 2.0.32 packages/core/src/plugin/websearch/tinyfish.ts:71-79 — stored-key search requests.
] as const;

export type Oc2CredentialEntry = { id: string; integrationID: string; label: string; active: boolean; value: unknown };
type Subcommand = Oc2CredentialError["subcommand"];
export type Oc2Credentials = {
  exportCredentials(integration: string): Promise<Oc2CredentialEntry[]>;
  importCredentials(entries: Oc2CredentialEntry[]): Promise<void>;
  switchCredential(integration: string, id: string): Promise<void>;
  logoutCredential(integration: string, id: string): Promise<void>;
};
export type Oc2CredentialOptions = { opencodeBin?: string; oc2Standalone?: boolean; oc2Server?: string; timeoutMs?: number };

export function formatOc2AuthCommand(options: Oc2CredentialOptions, subcommand: "switch" | "logout", integration: string, id: string): string {
  const quote = (text: string) => /^[A-Za-z0-9_./:-]+$/.test(text) ? text : `'${text.replaceAll("'", "'\\''")}'`;
  const target = options.oc2Standalone ? " --standalone" : options.oc2Server ? ` --server ${quote(options.oc2Server)}` : "";
  return `${quote(options.opencodeBin ?? "opencode")} auth ${subcommand} ${quote(integration)} ${quote(id)}${target}`;
}

export function createOc2Credentials(options: Oc2CredentialOptions = {}): Oc2Credentials {
  if (options.oc2Standalone && options.oc2Server !== undefined) throw new Error("--oc2-standalone and --oc2-server are mutually exclusive");
  const target = options.oc2Standalone ? ["--standalone"] : options.oc2Server !== undefined ? ["--server", options.oc2Server] : [];
  async function run(subcommand: Subcommand, args: string[], input?: string): Promise<string> {
    let child: ReturnType<typeof Bun.spawn<"pipe", "pipe", "pipe">>;
    try {
      child = Bun.spawn([options.opencodeBin ?? "opencode", "auth", subcommand, ...args, ...target], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    } catch { throw new Oc2CredentialError(subcommand, null, "failed"); }
    let reason: "timeout" | "output limit" | "failed" | undefined;
    const timer = setTimeout(() => { reason = "timeout"; child.kill("SIGKILL"); }, options.timeoutMs ?? 30_000);
    async function drain(stream: ReadableStream<Uint8Array>, limit: number, capture: boolean): Promise<string> {
      const reader = stream.getReader();
      let bytes = 0;
      const chunks: Uint8Array[] = [];
      try {
        while (true) {
          const result = await reader.read();
          if (result.done) break;
          bytes += result.value.byteLength;
          if (bytes > limit) { reason = "output limit"; child.kill("SIGKILL"); throw new Oc2CredentialError(subcommand, null, reason); }
          if (capture) chunks.push(result.value);
        }
        return capture ? Buffer.concat(chunks).toString("utf8") : "";
      } finally { reader.releaseLock(); }
    }
    try {
      // Both pipes drain concurrently so a noisy CLI cannot deadlock before its timeout.
      const output = drain(child.stdout, 4 * 1024 * 1024, true);
      const errors = drain(child.stderr, 64 * 1024, false);
      const write = async () => { if (input !== undefined) { child.stdin.write(input); await child.stdin.flush(); } await child.stdin.end(); };
      const [stdout, , exitCode] = await Promise.all([output, errors, child.exited, write()]);
      if (reason || exitCode !== 0) throw new Oc2CredentialError(subcommand, exitCode, reason ?? "failed");
      return stdout;
    } catch {
      child.kill("SIGKILL");
      const exitCode = await child.exited;
      // CLI output may contain live credentials, even on failure; never attach it or an underlying error.
      throw new Oc2CredentialError(subcommand, exitCode, reason ?? "failed");
    } finally { clearTimeout(timer); }
  }
  return {
    async exportCredentials(integration) {
      const text = await run("export", [integration]);
      try {
        const entries: unknown = JSON.parse(text);
        if (!Array.isArray(entries) || !entries.every((entry) => entry && typeof entry === "object" && typeof entry.id === "string" && entry.integrationID === integration && typeof entry.label === "string" && typeof entry.active === "boolean" && entry.value && typeof entry.value === "object" && !Array.isArray(entry.value))) throw new Error();
        return entries;
      } catch { throw new Oc2CredentialError("export", 0, "invalid export"); }
    },
    async importCredentials(entries) { await run("import", [], JSON.stringify(entries)); },
    async switchCredential(integration, id) { await run("switch", [integration, id]); },
    async logoutCredential(integration, id) { await run("logout", [integration, id]); },
  };
}
