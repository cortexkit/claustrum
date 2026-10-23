#!/usr/bin/env python3
"""Run gate workers in writable copies, never mutate the runner's snapshot."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def copy_checkout(source, destination):
    # Preserve history for mutation tooling, then overlay the actual working tree:
    # cloning alone would silently test HEAD instead of staged/unstaged edits.
    subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                    str(source), str(destination)], check=True)
    subprocess.run(["git", "-C", str(destination), "read-tree", "HEAD"], check=True)
    shutil.copytree(source, destination, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "target", "node_modules", ".cortexkit", "__pycache__"))
    # Build output is the runner's writable cache, not part of its read-only tree.
    (destination / "target").symlink_to(source / "target", target_is_directory=True)


def main():
    mode = sys.argv[1]
    if mode not in ("full", "fast"):
        raise RuntimeError("unknown gate mode")
    source = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="claustrum-gate-") as scratch:
        checkout = Path(scratch) / "claustrum"
        copy_checkout(source, checkout)
        if mode == "full":
            sibling = Path(os.environ.get("CRED_SUBCONSCIOUS_ROOT", "../subconscious")).resolve()
            supervisor = Path(scratch) / "subconscious"
            copy_checkout(sibling, supervisor)
            os.environ["CRED_SUBCONSCIOUS_ROOT"] = str(supervisor)
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
