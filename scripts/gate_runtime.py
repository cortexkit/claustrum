"""Shared timing and fail-closed remote transport for the full and fast gates."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import threading
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
    if mode == "windows":
        command += ["--platform", "windows"]
    arguments = []
    # Runner jobs are offline unless asked. The v0.1.2 compatibility arm downloads
    # that release once from GitHub (then reuses its verified copy from the build
    # cache). Both gates can run it: the fast gate does whenever credentials-module
    # changed. So both jobs need outbound network.
    command.append("--net")
    if mode in ("full", "windows"):
        sibling = os.environ.get("CRED_SUBCONSCIOUS_ROOT", "../subconscious")
        command += ["--sibling", sibling]
        arguments += ["--sibling", sibling]
    if plan is not None:
        arguments += ["--plan", json.dumps(plan)]
    # The runner filters environment names; argv preserves both supervisor location
    # and dirty-tree scope without relying on its environment allowlist.
    command += ["--", "python3", "scripts/gate-remote.py", mode, *arguments]
    return command


def validate_remote(code, output, stderr=""):
    if code:
        if code in RUNNER_ERRORS:
            reasons = re.findall(r"^ck motor run:.*$", stderr, re.MULTILINE)
            reason = reasons[-1] if reasons else "no ck motor run: stderr line was printed"
            raise RuntimeError(f"runner exit {code}: {RUNNER_ERRORS[code]}; {reason}")
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


CAPTURED_LINE = "ck motor run: job_id="


def run_watching_capture(command, captured):
    """Run a runner job, signalling `captured` once its snapshot has been taken.

    ck motor prints the job id on stderr only after the snapshot is captured and
    handed off, so local writes after that line can't affect the job. The event is
    also set when the process ends, so a refusal never leaves local lanes waiting.
    """
    process = subprocess.Popen(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout_pipe, stderr_pipe = process.stdout, process.stderr
    assert stdout_pipe is not None and stderr_pipe is not None
    stderr_lines = []

    def read_stderr():
        for line in stderr_pipe:
            stderr_lines.append(line)
            if captured is not None and line.startswith(CAPTURED_LINE):
                captured.set()

    reader = threading.Thread(target=read_stderr, daemon=True)
    reader.start()
    stdout = stdout_pipe.read()
    process.wait()
    reader.join()
    stdout_pipe.close()
    stderr_pipe.close()
    return subprocess.CompletedProcess(command, process.returncode, stdout, "".join(stderr_lines))


class Gate:
    def __init__(self):
        self.start = time.monotonic()
        self.rows = []
        self.unchecked = []

    def job(self, label, command, remote=False, captured=None):
        start = time.monotonic()
        where = remote if isinstance(remote, str) else "Linux" if remote else "local"
        try:
            result = run_watching_capture(command, captured) if remote else subprocess.run(
                command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as error:
            self.rows.append(dict(label=label, seconds=time.monotonic() - start,
                                  status="failed", where=where))
            raise RuntimeError(f"{label}: runner could not start: {error}" if remote else str(error)) from error
        finally:
            if captured is not None:
                captured.set()
        # Print whole lanes together; interleaving libtest output would mix arm counts.
        stderr = result.stderr or ""
        output = result.stdout + stderr
        print(output, end="", flush=True)
        self.unchecked.extend(re.findall(r"^CK_GATE_UNCHECKED (.+)$", output, re.MULTILINE))
        for line in output.splitlines():
            if line.startswith(PREFIX):
                row = json.loads(line[len(PREFIX):])
                row["where"] = where
                self.rows.append(row)
        has_arms = any(line.startswith(PREFIX) for line in output.splitlines())
        self.rows.append(dict(label=label, seconds=time.monotonic() - start,
                              status="failed" if result.returncode else "passed",
                              where=where + " job" if remote else "local lane" if has_arms else "local"))
        if remote:
            try:
                validate_remote(result.returncode, output, stderr)
            except (RuntimeError, ValueError, KeyError, TypeError) as error:
                self.rows[-1]["status"] = "failed"
                raise RuntimeError(f"{label}: {error}") from error
        elif result.returncode:
            raise RuntimeError(f"{label} failed (exit {result.returncode})")

    def parallel(self, jobs):
        errors = []
        remote = [job for job in jobs if len(job) > 2 and job[2]]
        local = [job for job in jobs if not (len(job) > 2 and job[2])]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            # Start the runner jobs first and hold the local lanes until each runner has
            # captured its snapshot. Local lanes create build and package folders in the
            # checkout, and the runner refuses a checkout whose watched directories
            # change while it captures ("checkout changed during capture").
            events = [threading.Event() for _ in remote]
            futures = [pool.submit(self.job, job[0], job[1], job[2], event)
                       for job, event in zip(remote, events)]
            for event in events:
                event.wait()
            futures += [pool.submit(self.job, *job) for job in local]
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
        arms = [row for row in self.rows if row['where'] in ("Linux", "Windows", "local")]
        print("Slowest arms: " + ", ".join(f"{r['label']} {r['seconds']:.2f}s" for r in
                                          sorted(arms, key=lambda r: r['seconds'], reverse=True)[:5]))
        print(f"Wall time: {time.monotonic() - self.start:.2f}s", flush=True)
