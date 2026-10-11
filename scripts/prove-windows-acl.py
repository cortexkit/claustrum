#!/usr/bin/env python3
"""On Windows, break the master-key file checks twice and confirm the tests catch it.

One mutation skips the owner-only ACL check when a key file is loaded, the other
creates the key file without an owner-only ACL. Each must turn exactly its named
test in crates/credentials-core/tests/windows_acl.rs red while the others stay
green; the source is restored after each run."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


SOURCE = "crates/credentials-core/src/resolver.rs"
COMMAND = [
    "cargo", "test", "--locked", "-p", "credentials-core", "--test", "windows_acl",
    "--", "--nocapture", "--test-threads=1",
]
CONTROLS = [
    (
        "skip key-file handle verification",
        "subc_os::windows_acl::verify_owner_only(&file).map_err(|error| {",
        "Ok::<(), std::io::Error>(()).map_err(|error| { // NON-VACUITY BREAK",
        "windows_key_file_with_everyone_read_is_refused",
    ),
    (
        "create key file with an inherited DACL",
        "subc_os::windows_acl::create_private_file(path)",
        "std::fs::OpenOptions::new().write(true).create_new(true).open(path) /* NON-VACUITY BREAK */",
        "windows_created_key_file_has_protected_owner_only_dacl",
    ),
]


def run(argv):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
    print(result.stdout, end="", flush=True)
    return result


def git(*args):
    result = run(["git", *args])
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def main():
    if os.name != "nt":
        raise RuntimeError("Windows is required: a skipped wrapper is not a mutation proof")
    os.chdir(Path(__file__).resolve().parent.parent)
    run(["cargo", "--version"])
    baseline = run(COMMAND)
    if baseline.returncode or "test result: ok. 3 passed" not in baseline.stdout:
        raise RuntimeError("all three native Windows ACL tests must pass before mutation")
    source = Path(SOURCE)
    original = source.read_text(encoding="utf-8")
    records = []
    for control, old, new, expected in CONTROLS:
        if original.count(old) != 1:
            raise RuntimeError(f"{control}: mutation anchor is not unique")
        git("add", "--", SOURCE)
        if git("diff", "--stat"):
            raise RuntimeError("unstaged changes present before mutation")
        applied = restored = ""
        try:
            source.write_text(original.replace(old, new), encoding="utf-8")
            applied = git("diff", "--stat")
            if not applied:
                raise RuntimeError("mutation did not change the source")
            mutant = run(COMMAND)
            failed = re.findall(r"^test (\S+) \.\.\. FAILED$", mutant.stdout, re.MULTILINE)
            # libtest's nocapture output can interrupt the per-test status line.
            if not failed:
                failed = re.findall(r"^    (windows_\S+)$", mutant.stdout, re.MULTILINE)
            passed = re.findall(r"^test (\S+) \.\.\. ok$", mutant.stdout, re.MULTILINE)
            outcome = "reddened" if mutant.returncode == 101 and failed == [expected] else "undefended"
        finally:
            git("checkout", "--", SOURCE)
            os.utime(source, None)
            restored = git("diff", "--stat")
            if restored:
                raise RuntimeError("mutation restore left a diff")
        records.append({
            "control": control, "expected_red": expected, "outcome": outcome,
            "failed_tests": failed, "passed_tests": passed,
            "captured_output": mutant.stdout,
            "applied_evidence": f"{SOURCE}: during={applied!r}; after={restored!r}",
        })
        report = Path("gate-evidence/windows-acl-mutations.json")
        report.parent.mkdir(exist_ok=True)
        report.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        if outcome != "reddened" or len(passed) != 2:
            raise RuntimeError(f"{control}: expected only {expected} red and the other two green")
    print("Windows ACL mutation proofs: 2 controls reddened exactly one test each")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        sys.exit(str(error))
