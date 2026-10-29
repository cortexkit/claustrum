#!/usr/bin/env python3
"""Provision the Windows gate with CI's Rust components and pinned Bun release."""
from pathlib import Path
import subprocess
import urllib.request
import zipfile

BUN_VERSION = "1.3.14"


def main():
    subprocess.run(["rustup", "toolchain", "install", "stable", "--profile", "minimal",
                    "--component", "clippy,rustfmt"], check=True)
    directory = Path("target/windows-tools")
    binary = directory / "bun.exe"
    version = (subprocess.check_output([str(binary.resolve()), "--version"], text=True).strip()
               if binary.exists() else None)
    if version != BUN_VERSION:
        directory.mkdir(parents=True, exist_ok=True)
        archive = directory / "bun.zip"
        url = f"https://github.com/oven-sh/bun/releases/download/bun-v{BUN_VERSION}/bun-windows-x64.zip"
        urllib.request.urlretrieve(url, archive)
        # Extract only the executable, never arbitrary paths supplied by the archive.
        with zipfile.ZipFile(archive) as release:
            binary.write_bytes(release.read("bun-windows-x64/bun.exe"))
        archive.unlink()
    version = subprocess.check_output([str(binary.resolve()), "--version"], text=True).strip()
    if version != BUN_VERSION:
        raise RuntimeError(f"expected Bun {BUN_VERSION}, found {version}")
    print(f"Windows setup: stable Rust with clippy/rustfmt; Bun {version}", flush=True)


if __name__ == "__main__":
    main()
