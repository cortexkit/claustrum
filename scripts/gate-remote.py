#!/usr/bin/env python3
"""Run gate workers in writable copies, never mutate the runner's snapshot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def copy_checkout(source, destination, target):
    # Copy the history with the working tree: the worker carries out its own git
    # operations (the floor ratchet compares against a merge target), and cloning
    # alone would silently test HEAD instead of staged/unstaged edits.
    # A local clone validates the source's .git directory, not its worktree root.
    # Snapshot ownership differs from the job user; trust only that exact path,
    # for this command, without widening or changing the user's Git configuration.
    subprocess.run(["git", "-c", "safe.directory=" + str(source / ".git"),
                    "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                    str(source), str(destination)], check=True)
    subprocess.run(["git", "-C", str(destination), "read-tree", "HEAD"], check=True)
    shutil.copytree(source, destination, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "target", "node_modules", ".cortexkit", "__pycache__"))
    # Build output goes to a writable cache outside the read-only snapshot, so it
    # survives between runs. A sibling snapshot's own target/ is read-only (and may not
    # exist), so each checkout names its cache directory explicitly.
    target.mkdir(parents=True, exist_ok=True)
    link_target(destination / "target", target)


def link_target(link, target):
    if os.name == "nt":
        # Junctions need no symlink privilege. Paths travel as environment data,
        # not shell source, so spaces and command metacharacters remain literal.
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                        "$ErrorActionPreference = 'Stop'; New-Item -ItemType Junction "
                        "-Path $env:CK_GATE_LINK -Target $env:CK_GATE_TARGET | Out-Null"],
                       env=dict(os.environ, CK_GATE_LINK=str(link), CK_GATE_TARGET=str(target)), check=True)
    else:
        link.symlink_to(target, target_is_directory=True)


def stable_scratch(source):
    """A per-checkout copy location that is the same on every run, emptied first.

    The build cache outlives each run, and copied sources keep their modification
    times, so cargo reuses test binaries built from an earlier copy. Those binaries
    bake in that copy's CARGO_MANIFEST_DIR; with a fresh random directory each run,
    the fixture paths they read pointed at a deleted copy. A path that never changes
    keeps every baked-in path valid. It is keyed on the snapshot path so two
    checkouts never share it, and the runner serialises jobs per checkout.
    """
    key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    scratch = Path(tempfile.gettempdir()) / f"claustrum-gate-{key}"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    return scratch


def forget_binaries_from_another_copy(checkout, target):
    """Clean the workspace's own build output when the cache was built from a copy elsewhere.

    A stable copy path keeps cached binaries valid from one run to the next, but a
    cache built while the copy lived somewhere else (an older gate, or a moved temp
    directory) still holds binaries pointing at that old location, and cargo won't
    rebuild them because the copied sources keep their old modification times. The
    cache records which copy path built it; on a mismatch, `cargo clean -p` drops
    only the workspace members, so dependencies stay cached.
    """
    marker = target / "gate-copy-path"
    if marker.exists() and marker.read_text() == str(checkout):
        return
    members = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=checkout, check=True, stdout=subprocess.PIPE, text=True).stdout
    names = [package["name"] for package in json.loads(members)["packages"]]
    if not names:
        raise RuntimeError("no workspace members found to clean")
    command = ["cargo", "clean"]
    for name in names:
        command += ["-p", name]
    subprocess.run(command, cwd=checkout, check=True)
    marker.write_text(str(checkout))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("full", "fast", "windows"))
    parser.add_argument("--sibling", type=Path)
    parser.add_argument("--plan")
    args = parser.parse_args(argv)
    mode = args.mode
    sibling = None
    if mode in ("full", "windows"):
        if args.sibling is None:
            parser.error(f"{mode} gate requires --sibling supervisor snapshot path")
        sibling = args.sibling.resolve()
        if not sibling.is_dir():
            print(f"GATE FAILED: supervisor snapshot not found inside runner: {sibling}", file=sys.stderr)
            return 1
    elif args.plan is None:
        parser.error("fast gate requires --plan with the locally resolved scope")
    source = Path.cwd()
    scratch = stable_scratch(source)
    checkout = scratch / "claustrum"
    copy_checkout(source, checkout, source / "target")
    forget_binaries_from_another_copy(checkout, source / "target")
    if mode == "full":
        supervisor = scratch / "subconscious"
        # Cached under claustrum's writable target so the supervisor isn't rebuilt
        # from scratch on every gate run.
        copy_checkout(sibling, supervisor, source / "target" / "gate-subconscious")
        os.environ["CRED_SUBCONSCIOUS_ROOT"] = str(supervisor)
    elif mode == "windows":
        assert sibling is not None
        supervisor = scratch / "subconscious"
        contract = Path("docs/push-sealed-payload.md")
        (supervisor / contract).parent.mkdir(parents=True)
        shutil.copy2(sibling / contract, supervisor / contract)
        # Bash consumes this path; use forward slashes even under native Python.
        os.environ["CRED_SUBCONSCIOUS_ROOT"] = supervisor.as_posix()
    else:
        os.environ["CK_FAST_PLAN"] = args.plan
    os.environ["RUSTC_WRAPPER"] = ""
    os.environ["CARGO_BUILD_RUSTC_WRAPPER"] = ""
    # The tests locate artifacts under each checkout's target directory. A
    # global target override would make the supervisor/picker probe a stale file.
    os.environ.pop("CARGO_TARGET_DIR", None)
    if mode in ("full", "windows"):
        command = ["bash", "scripts/gate.sh", "--lane", "windows-ci" if mode == "windows" else "linux"]
    else:
        command = ["python3", "scripts/fast-check.py", "--linux-worker"]
    result = subprocess.run(command, cwd=checkout)
    if result.returncode == 0:
        print("CK_GATE_DONE", flush=True)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
