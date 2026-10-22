#!/usr/bin/env python3
"""Read and validate the minimum subc-core version for release assets."""

from pathlib import Path
import re
import sys


VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def read_required_core(path: Path) -> str:
    """Return the minimum required subc-core version, refusing malformed values."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"cannot read workspace.metadata.release.requires_core from {path}") from error

    in_release_metadata = False
    values = []
    for line in lines:
        statement = line.split("#", 1)[0].strip()
        if statement.startswith("[") and statement.endswith("]"):
            in_release_metadata = statement == "[workspace.metadata.release]"
        elif in_release_metadata:
            key, separator, value = statement.partition("=")
            if separator and key.strip() == "requires_core":
                values.append(value.strip())

    if len(values) != 1:
        raise ValueError(f"expected one workspace.metadata.release.requires_core in {path}")
    match = re.fullmatch(r'"([^"]*)"|\'([^\']*)\'', values[0])
    if match is None:
        raise ValueError("workspace.metadata.release.requires_core must be a quoted X.Y.Z string")
    version = match.group(1) if match.group(1) is not None else match.group(2)

    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise ValueError("workspace.metadata.release.requires_core must be plain X.Y.Z digits")
    return version


def main() -> int:
    if len(sys.argv) > 2:
        print(f"usage: {sys.argv[0]} [Cargo.toml]", file=sys.stderr)
        return 2
    cargo_toml = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("Cargo.toml")
    try:
        print(read_required_core(cargo_toml))
    except ValueError as error:
        print(f"REFUSING: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
