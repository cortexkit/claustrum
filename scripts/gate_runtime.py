"""Shared timing and fail-closed remote transport for the full and fast gates."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "CK_GATE_ARM "
RUNNER_ERRORS = {
    200: "runner unreachable or refused before start (nothing ran)",
    201: "runner outcome unknown or connection lost",
    202: "runner timeout",
    203: "runner cancelled",
    204: "runner bad arguments or unavailable hosted configuration",
}


def receipt(label, seconds, passed=None, floor=None, status="passed"):
    print(PREFIX + json.dumps(dict(label=label, seconds=seconds, passed=passed,
                                  floor=floor, status=status)), flush=True)


def remote_command(mode, plan=None):
    command = ["ck", "motor", "run", "--vcpus", "8", "--cwd", str(ROOT)]
    if mode == "full":
        sibling = os.environ.get("CRED_SUBCONSCIOUS_ROOT", "../subconscious")
        command += ["--sibling", sibling, "--env", "CRED_SUBCONSCIOUS_ROOT=" + sibling]
    if plan is not None:
        command += ["--env", "CK_FAST_PLAN=" + json.dumps(plan)]
    # Nested Cargo invocations must not rediscover a sandbox-incompatible cache wrapper.
    command += ["--env", "RUSTC_WRAPPER=", "--env", "CARGO_BUILD_RUSTC_WRAPPER=",
                "--", "python3", "scripts/gate-remote.py", mode]
    return command


def validate_remote(code, output):
    if code:
        if code in RUNNER_ERRORS:
            raise RuntimeError(f"runner exit {code}: {RUNNER_ERRORS[code]}")
        failures = re.findall(r"^GATE FAILED: (.+)$", output, re.MULTILINE)
        detail = ": " + failures[-1] if failures else ""
        raise RuntimeError(f"remote arm failed (exit {code}){detail}")
    rows = []
    for line in output.splitlines():
        if line.startswith(PREFIX):
            rows.append(json.loads(line[len(PREFIX):]))
    counted = [row for row in rows if row["floor"] is not None]
    if not counted:
        raise RuntimeError("remote job returned no counts; refusing a vacuous pass")
    for row in counted:
        if not isinstance(row["passed"], int):
            raise RuntimeError(f"{row['label']}: remote job returned no counts")
        if row["passed"] < row["floor"]:
            raise RuntimeError(f"{row['label']} ran {row['passed']} tests, expected at least {row['floor']}")
    if any(row["status"] == "failed" for row in rows):
        raise RuntimeError("remote arm reported failure")
    if "CK_GATE_DONE" not in output.splitlines():
        raise RuntimeError("remote job did not finish all arms (missing completion receipt)")
    return rows


class Gate:
    def __init__(self):
        self.start = time.monotonic()
        self.rows = []
        self.unchecked = []

    def job(self, label, command, remote=False):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
        except OSError as error:
            self.rows.append(dict(label=label, seconds=time.monotonic() - start,
                                  status="failed", where="Linux" if remote else "local"))
            raise RuntimeError(f"{label}: runner could not start: {error}" if remote else str(error)) from error
        # Print whole lanes together; interleaving libtest output would mix arm counts.
        print(result.stdout, end="", flush=True)
        self.unchecked.extend(re.findall(r"^CK_GATE_UNCHECKED (.+)$", result.stdout, re.MULTILINE))
        for line in result.stdout.splitlines():
            if line.startswith(PREFIX):
                row = json.loads(line[len(PREFIX):])
                row["where"] = "Linux" if remote else "local"
                self.rows.append(row)
        has_arms = any(line.startswith(PREFIX) for line in result.stdout.splitlines())
        self.rows.append(dict(label=label, seconds=time.monotonic() - start,
                              status="failed" if result.returncode else "passed",
                              where="Linux job" if remote else "local lane" if has_arms else "local"))
        if remote:
            try:
                validate_remote(result.returncode, result.stdout)
            except (RuntimeError, ValueError, KeyError, TypeError) as error:
                self.rows[-1]["status"] = "failed"
                raise RuntimeError(f"{label}: {error}") from error
        elif result.returncode:
            raise RuntimeError(f"{label} failed (exit {result.returncode})")

    def parallel(self, jobs):
        errors = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futures = [pool.submit(self.job, *job) for job in jobs]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except RuntimeError as error:
                    errors.append(str(error))
        if errors:
            raise RuntimeError("; ".join(errors))

    def summary(self):
        print("\nArm / lane                                          Where        Seconds  Result")
        for row in self.rows:
            print(f"{row['label']:52} {row['where']:12} {row['seconds']:7.2f}  {row['status']}")
        arms = [row for row in self.rows if row['where'] in ("Linux", "local")]
        print("Slowest arms: " + ", ".join(f"{r['label']} {r['seconds']:.2f}s" for r in
                                          sorted(arms, key=lambda r: r['seconds'], reverse=True)[:5]))
        print(f"Wall time: {time.monotonic() - self.start:.2f}s", flush=True)
