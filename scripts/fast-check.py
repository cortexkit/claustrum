#!/usr/bin/env python3
"""Diff-scoped lint/tests plus wire, authorization, source-scan and migration checks."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

# Importing by path is also used by the script-contract suite.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate_runtime import Gate, receipt, remote_command

ROOT = Path(__file__).resolve().parents[1]
FEATURES = "credentials-core/test-support,credentials-core/migration-tools"
# Libtest treats these filters as alternatives; print each filter in the command
# transcript so the selected protection tests are visible without reading this file.
DAEMON_FILTERS = [
    "wire", "scoped", "grant", "handle", "admin", "enroll", "deposit_cookie",
    "route", "auth", "principal", "refus", "token",
    "key_set", "sign", "public_key", "error", "open",
    "every_daemon_output_site_is_enumerated",
    "no_shipped_source_reads_the_launch_nonce_directly",
]
# Pin critical names as well as broad groups, so a removed test cannot hide among
# other matches for a broad filter such as "wire" or "scoped".
REQUIRED_DAEMON_TESTS = [
    "the_get_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement",
    "the_status_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement",
    "credential_get_request_key_set_is_pinned",
    "credential_sign_request_key_set_is_pinned",
    "credential_public_key_request_key_set_is_pinned",
    "credential_get_many_request_key_set_is_pinned",
    "credential_status_request_key_set_is_pinned",
    "scoped_get_uncovered_and_unknown_ids_have_identical_wire_bodies",
    "scoped_status_unknown_and_no_grant_are_indistinguishable_on_the_wire",
    "a_list_only_principal_is_refused_by_every_other_scoped_surface",
    "every_scoped_surface_answers_an_enrolled_token_differently_than_no_token",
    "unknown_and_revoked_get_handles_refuse_without_disclosing_a_credential_id",
    "signing_is_fenced_to_signing_key_records",
    "public_key_matches_signatures_without_serializing_private_material",
    "every_daemon_output_site_is_enumerated",
    "no_shipped_source_reads_the_launch_nonce_directly",
    # Agent-secret wire contract (docs/wire-contract-v1.md section 15).
    "secret_phone_keys_register_request_and_result_key_sets_match_the_contract",
    "secret_deposit_keys_request_and_result_key_sets_match_the_contract",
    "secret_deposit_request_and_result_key_sets_match_the_contract",
    "secret_approve_request_and_result_key_sets_match_the_contract",
    "secret_list_request_and_result_key_sets_match_the_contract",
    "secret_delete_request_and_result_key_sets_match_the_contract",
    "secret_revoke_grant_request_and_result_key_sets_match_the_contract",
    "secret_use_request_and_result_key_sets_match_the_contract",
    "secret_statement_and_envelope_key_sets_match_the_contract_and_the_pinned_vectors",
    "secret_error_codes_are_golden_and_match_the_doc_table",
    "secret_caller_gate_and_op_matrix_matches_the_wire_contract",
    "every_secret_golden_example_in_the_wire_contract_is_checked",
]


def verify_registration(names):
    for required in REQUIRED_DAEMON_TESTS:
        name = "tests::" + required
        if name not in names or not any(pattern in name for pattern in DAEMON_FILTERS):
            raise RuntimeError(f"required protection {name!r} is missing or not selected")
    for pattern in DAEMON_FILTERS:
        if not any(pattern in name for name in names):
            raise RuntimeError(f"cross-seat filter {pattern!r} matches no registered tests")


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True)


def scope(base, metadata):
    # Comparing the working tree with base includes committed, staged and unstaged
    # edits. Disable rename folding to retain old paths; add untracked files separately.
    paths = set(output("git", "diff", "--name-only", "--no-renames", "-z", base, "--").split("\0"))
    paths.update(output("git", "ls-files", "--others", "--exclude-standard", "-z").split("\0"))
    paths.discard("")
    members = [p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]]
    shared = any(p in {"Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml"}
                 or p.startswith(".cargo/") for p in paths)
    crates = []
    for package in members:
        directory = Path(package["manifest_path"]).parent.relative_to(ROOT).as_posix() + "/"
        if shared or any(p.startswith(directory) for p in paths):
            crates.append(package["name"])
    return sorted(crates), paths, members


def run(label, command, tests=False):
    print(f"\n=== {label} ===\n$ {shlex.join(command)}", flush=True)
    start = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="", flush=True)
    seconds = time.monotonic() - start
    print(f"{label}: {seconds:.2f}s (exit {result.returncode})", flush=True)
    if result.returncode:
        receipt(label, seconds, status="failed")
        raise RuntimeError(f"{label} failed")
    passed = None
    if tests:
        counts = re.findall(r"^test result: ok\. (\d+) passed|^\s*(\d+) pass$|^Ran (\d+) tests?", result.stdout, re.MULTILINE)
        counts = [int(number) for match in counts for number in match if number]
        if not counts or sum(counts) == 0 or "SKIPPING" in result.stdout:
            receipt(label, seconds, status="failed")
            raise RuntimeError(f"{label}: no passing tests or a runtime skip; refusing a vacuous pass")
        passed = sum(counts)
    receipt(label, seconds, passed, 1 if tests else None)
    return result.stdout


def linux_checks(crates):
    if sys.platform != "linux":
        raise RuntimeError("Linux worker refuses to compile on this host")
    for tool in (["cargo", "--version"], ["rustfmt", "--version"], ["cargo", "clippy", "--version"]):
        print(output(*tool).strip(), flush=True)
    if crates:
        packages = [arg for crate in crates for arg in ("-p", crate)]
        features = ["--features", FEATURES] if {"credentials-core", "credentials-module"} & set(crates) else []
        run("changed-crate clippy", ["cargo", "clippy", "--locked", *packages, *features, "--all-targets", "--", "-D", "warnings"])
        run("changed-crate tests", ["cargo", "test", "--locked", *packages, *features], tests=True)
    cargo = ["cargo", "test", "--locked", "--workspace", "--features", FEATURES]
    listed = run("cross-seat test registration", cargo + ["--bin", "ck-claustrum", "--", "--list"])
    names = [line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test")]
    verify_registration(names)
    run("cross-seat wire, authorization, uniform refusal, anti-enumeration and source scans",
        cargo + ["--bin", "ck-claustrum", "--", *DAEMON_FILTERS, "--nocapture"], tests=True)
    run("migration safety (store::tests:: OR migration)", cargo + ["--lib", "--", "store::tests::", "migration", "--nocapture"], tests=True)
    run("migration tools", cargo + ["--test", "key_verify_takes_nothing", "--", "--nocapture"], tests=True)
    run("released v0.1.2 migration compatibility", cargo + ["--test", "v012_release_compat", "--", "--ignored", "--nocapture"], tests=True)
    run("Rust consumer wire contract", ["cargo", "test", "--locked", "-p", "cortexkit-claustrum-client", "--lib", "contract_tests::", "--", "--nocapture"], tests=True)


def typescript_checks(paths):
    bun = os.environ.get("BUN", "bun")
    print(output(bun, "--version").strip(), flush=True)
    run("Bun frozen install", [bun, "install", "--frozen-lockfile"])
    run("TypeScript typecheck", [bun, "run", "typecheck"])
    run("TypeScript build", [bun, "run", "build"])
    run("TypeScript consumer wire contract", [bun, "test", "packages/client/src/tests/handle-wire.test.ts",
        "packages/client/src/tests/scoped-wire.test.ts", "packages/client/src/tests/scoped.test.ts",
        "packages/client/src/tests/scoped-decode.test.ts"], tests=True)
    if any(p.startswith("packages/") or p in {"package.json", "bun.lock", "tsconfig.json"} for p in paths):
        run("changed TypeScript package tests (hermetic)", [bun, "run", "test:hermetic"], tests=True)
    else:
        print("SKIPPED unchanged TypeScript package suites (consumer wire tests ran)", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/master", help="diff base (default: origin/master); must resolve locally")
    parser.add_argument("--linux-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--typescript-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.linux_worker:
        linux_checks(json.loads(os.environ["CK_FAST_PLAN"])["crates"])
        return
    if args.typescript_worker:
        typescript_checks(json.loads(os.environ["CK_FAST_PLAN"])["paths"])
        return
    gate = Gate()
    error = None
    try:
        # Scope is resolved locally, before the runner copies the dirty working tree.
        base = output("git", "merge-base", "HEAD", args.base).strip()
        metadata = json.loads(output("cargo", "metadata", "--no-deps", "--format-version", "1"))
        crates, paths, members = scope(base, metadata)
        print(f"FAST CHECK (not the full gate): base {args.base} at {base}", flush=True)
        print("Changed crates: " + (", ".join(crates) or "none"), flush=True)
        print(output("cargo", "--version").strip(), flush=True)
        print(output("rustfmt", "--version").strip(), flush=True)
        fmt = ["cargo", "fmt"]
        for package in members:
            fmt += ["-p", package["name"]]
        if not members:
            raise RuntimeError("empty workspace; refusing an empty format scope")
        gate.job("workspace format", fmt + ["--", "--check"])
        if any(p.startswith(("scripts/", ".github/")) for p in paths):
            print(output("python3", "--version").strip(), flush=True)
            gate.job("script contracts", ["python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-v"])
        else:
            print("SKIPPED unchanged script contracts", flush=True)
        print("SKIPPED unchanged-crate clippy/tests: " + ", ".join(p["name"] for p in members if p["name"] not in crates), flush=True)
        plan = dict(crates=crates, paths=sorted(paths))
        gate.parallel([
            ("Linux Rust", remote_command("fast", plan), True),
            ("TypeScript", ["env", "CK_FAST_PLAN=" + json.dumps(plan), "python3", "scripts/fast-check.py", "--typescript-worker"], False),
        ])
    except (OSError, subprocess.CalledProcessError, RuntimeError) as caught:
        error = str(caught)
    finally:
        gate.summary()
    if error:
        raise RuntimeError(error)
    print("SKIPPED full gate: seam-feature lint/crash cuts, real-daemon e2e, native stores, Windows cross-check, "
          "repository scans and release-artifact probes. Run scripts/gate.sh and CI after live acceptance.", flush=True)
    print("Signing is NOT checked here: release-build.sh still requires pinned identifiers and hardened runtime.", flush=True)
    print("FAST CHECK PASSED (not the full gate)", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, RuntimeError) as error:
        print(f"FAST CHECK FAILED: {error}", file=sys.stderr)
        sys.exit(1)
