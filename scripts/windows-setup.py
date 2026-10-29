#!/usr/bin/env python3
"""Verify the Windows lane's existing tools without installing or downloading."""
import subprocess


def main():
    clippy = subprocess.check_output(["cargo", "clippy", "--version"], text=True).strip()
    rustfmt = subprocess.check_output(["cargo", "fmt", "--version"], text=True).strip()
    bun = subprocess.check_output(["bun", "--version"], text=True).strip()
    if bun.partition(".")[0] != "1":
        raise RuntimeError(f"expected Bun major version 1 on PATH, found {bun}")
    print(f"Windows setup: {clippy}; {rustfmt}; Bun {bun} from PATH", flush=True)


if __name__ == "__main__":
    main()
