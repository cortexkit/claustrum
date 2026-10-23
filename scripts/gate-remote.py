#!/usr/bin/env python3
"""Run gate workers in writable copies, never mutate the runner's snapshot."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def copy_checkout(source, destination, target):
    # Preserve history for mutation tooling, then overlay the actual working tree:
    # cloning alone would silently test HEAD instead of staged/unstaged edits.
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
    (destination / "target").symlink_to(target, target_is_directory=True)


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("full", "fast"))
    parser.add_argument("--sibling", type=Path)
    parser.add_argument("--plan")
    args = parser.parse_args(argv)
    mode = args.mode
    sibling = None
    if mode == "full":
        if args.sibling is None:
            parser.error("full gate requires --sibling supervisor snapshot path")
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
    if mode == "full":
        supervisor = scratch / "subconscious"
        # Cached under claustrum's writable target so the supervisor isn't rebuilt
        # from scratch on every gate run.
        copy_checkout(sibling, supervisor, source / "target" / "gate-subconscious")
        os.environ["CRED_SUBCONSCIOUS_ROOT"] = str(supervisor)
    else:
        os.environ["CK_FAST_PLAN"] = args.plan
    os.environ["RUSTC_WRAPPER"] = ""
    os.environ["CARGO_BUILD_RUSTC_WRAPPER"] = ""
    # The tests locate artifacts under each checkout's target directory. A
    # global target override would make the supervisor/picker probe a stale file.
    os.environ.pop("CARGO_TARGET_DIR", None)
    command = (["bash", "scripts/gate.sh", "--lane", "linux"] if mode == "full" else
               ["python3", "scripts/fast-check.py", "--linux-worker"])
    result = subprocess.run(command, cwd=checkout)
    if result.returncode == 0:
        print("CK_GATE_DONE", flush=True)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
