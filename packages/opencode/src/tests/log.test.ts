import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createFileLogSink, createLogger, serializedLogSink } from "../log";

describe("custody logger", () => {
  const originalDebug = console.debug;
  const originalLog = console.log;
  const originalError = console.error;
  let debugLines: string[];
  let logLines: string[];
  let errorLines: string[];

  beforeEach(() => {
    debugLines = [];
    logLines = [];
    errorLines = [];
    console.debug = (...args: unknown[]) => {
      debugLines.push(args.map(String).join(" "));
    };
    console.log = (...args: unknown[]) => {
      logLines.push(args.map(String).join(" "));
    };
    console.error = (...args: unknown[]) => {
      errorLines.push(args.map(String).join(" "));
    };
  });

  afterEach(() => {
    console.debug = originalDebug;
    console.log = originalLog;
    console.error = originalError;
  });

  test("the default sink keeps debug on console.debug while routing info to stdout and warnings to stderr", () => {
    const logger = createLogger();
    logger.debug({ provider: "deepseek", state: "available" });
    logger.info({ provider: "deepseek", state: "available" });
    logger.warn({ provider: "deepseek", state: "transient", errorCode: "timeout" });
    logger.error({ provider: "deepseek", state: "gone", errorClass: "ClaustrumCredentialError" });

    expect(debugLines).toHaveLength(1);
    expect(logLines).toHaveLength(1);
    expect(errorLines).toHaveLength(2);
    expect(debugLines[0]).toContain('"level":"debug"');
    expect(logLines[0]).toContain('"level":"info"');
    expect(errorLines[0]).toContain('"level":"warn"');
    expect(errorLines[1]).toContain('"level":"error"');
  });

  test("serializedLogSink still writes every level to its caller-provided stream and never strips", () => {
    // Regression guard: the default-sink change must not silently move redacted records
    // off the stream a test asserted on. The serialized path keeps everything on the
    // write callback's channel so the existing contract survives.
    const captured: Array<{ level: string; provider?: string; errorCode?: string }> = [];
    const logger = createLogger(serializedLogSink((line) => {
      captured.push(JSON.parse(line));
    }));
    logger.debug({ provider: "deepseek" });
    logger.warn({ provider: "deepseek", errorCode: "timeout" });

    expect(captured).toEqual([
      { level: "debug", provider: "deepseek" },
      { level: "warn", provider: "deepseek", errorCode: "timeout" },
    ]);
  });

  test("file sink writes metadata and creates private parent and file", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "nested", "custody.jsonl");
    const logger = createLogger(createFileLogSink({ path }));

    logger.info({ provider: "openai", state: "serving" });

    const line = JSON.parse(readFileSync(path, "utf8"));
    expect(line).toMatchObject({ level: "info", provider: "openai", state: "serving" });
    expect(typeof line.ts).toBe("string");
    expect(line.pid).toBe(process.pid);
    expect(statSync(root).mode & 0o777).toBe(0o700);
    expect(statSync(join(root, "nested")).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  test("file sink honors override and off disable", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const override = join(root, "override.jsonl");

    createLogger(createFileLogSink({ env: { CLAUSTRUM_CUSTODY_LOG: override } })).info({ provider: "x" });
    createLogger(createFileLogSink({ env: { CLAUSTRUM_CUSTODY_LOG: "off" } })).info({ provider: "x" });

    expect(existsSync(override)).toBe(true);
    expect(existsSync(join(root, "disabled.jsonl"))).toBe(false);
  });

  test("file sink rotates at five MiB", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    mkdirSync(root, { recursive: true });
    writeFileSync(path, "x".repeat(5 * 1024 * 1024 + 1), { mode: 0o600 });
    createLogger(createFileLogSink({ path })).info({ provider: "rotated" });

    expect(statSync(`${path}.1`).size).toBe(5 * 1024 * 1024 + 1);
    expect(JSON.parse(readFileSync(path, "utf8")).provider).toBe("rotated");
  });

  test("file sink degrades with one console warning when path is unwritable", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    mkdirSync(root, { recursive: true });
    const blocked = join(root, "blocked");
    writeFileSync(blocked, "not a directory");
    const warnings: string[] = [];
    const sink = createFileLogSink({ path: join(blocked, "custody.jsonl"), warn: (message) => warnings.push(message) });

    sink({ level: "info", provider: "x" });
    sink({ level: "info", provider: "y" });

    expect(warnings).toHaveLength(1);
  });

  test("file sink excludes free-text error messages", () => {
    const path = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}.jsonl`);
    const handle = `ckh_${"A".repeat(43)}`;
    const key = "sk-fake-secret-key";
    createLogger(createFileLogSink({ path })).error({ provider: "openai", errorMessage: `${handle} ${key}` });

    const contents = readFileSync(path, "utf8");
    expect(contents).not.toContain(handle);
    expect(contents).not.toContain(key);
  });
});
