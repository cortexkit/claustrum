#!/usr/bin/env python3
"""Run gate workers in writable copies, never mutate the runner's snapshot."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def copy_checkout(source, destination):
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
    # Build output is the runner's writable cache, not part of its read-only tree.
    (destination / "target").symlink_to(source / "target", target_is_directory=True)


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
    with tempfile.TemporaryDirectory(prefix="claustrum-gate-") as scratch:
        checkout = Path(scratch) / "claustrum"
        copy_checkout(source, checkout)
        if mode == "full":
            supervisor = Path(scratch) / "subconscious"
            copy_checkout(sibling, supervisor)
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
