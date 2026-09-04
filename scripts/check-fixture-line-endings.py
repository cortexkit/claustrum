#!/usr/bin/env python3
"""Assert every fixture directory is exempt from git's line-ending translation.

WHY THIS EXISTS. Git's `core.autocrlf` rewrites LF to CRLF when checking out on
Windows. For a source file that is invisible; for a file whose BYTES are the thing
under test it silently changes the artifact between the machine that wrote it and
the machine that reads it, and the failure surfaces as a mismatch on one platform
that reads like a broken test rather than a mangled file.

`.gitattributes` already carried that reasoning and the instruction "any future
vendored fixture whose CONTENT is asserted belongs in this list". It was written
after the same defect hit a signed manifest in August. IT DID NOT PREVENT THE NEXT
ONE: `packages/opencode/golden/` arrived in September, outside every listed path,
and its golden handle file checked out with CRLF on the Windows runner --
`the_golden_handle_file_matches_the_rust_contract_byte_for_byte` failed there with
`\\n` on the left and `\\r\\n` on the right.

A CONVENTION STATED IN A FILE IS ONLY FOLLOWED BY PEOPLE WHO OPEN THAT FILE. This
script is the same rule with a failure mode: it refuses rather than advises.

WHAT IT CHECKS, and the rule is deliberately mechanical so it needs no judgement:
every directory named `golden` or `fixtures` must be covered by a `-text` pattern
in `.gitattributes`. Not "every content-asserted file" -- distinguishing a
byte-exact comparison from a `contains()` check would need the script to understand
the assertion, and a checker that guesses is worse than one with a crude rule.

WHAT IT DOES NOT CHECK. A content-asserted file OUTSIDE such a directory is invisible
here (`docs/wire-contract-v1.md` is included and asserted, and is not covered). Those
are safe today because they are substring-checked rather than byte-compared, and that
safety is a property of the assertions rather than of this script. If you add a
byte-exact comparison against a file outside a fixture directory, put it in one.
"""

import re
import subprocess
import sys
from pathlib import Path

SKIP = {".git", "node_modules", "target", "dist", ".cortexkit"}
FIXTURE_DIR_NAMES = {"golden", "fixtures"}


def covered_patterns(root: Path) -> list[str]:
    attrs = root / ".gitattributes"
    if not attrs.is_file():
        return []
    out = []
    for line in attrs.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and "-text" in parts[1:]:
            out.append(parts[0])
    return out


def is_covered(rel: str, patterns: list[str]) -> bool:
    """Whether `rel` (a POSIX path) is matched by any -text pattern.

    Paths are compared in POSIX form on every platform: `str(Path)` renders
    backslashes on Windows, which silently fails every comparison against a
    manifest written with forward slashes. That defect has hit two other scripts in
    this directory, which is why `scripts/check-path-rendering.py` exists.
    """
    for pat in patterns:
        base = pat.rstrip("*").rstrip("/")
        if base and rel.startswith(base):
            return True
        # A bare glob like `*.pem` covers files, not directories.
        if pat.startswith("*.") and rel.endswith(pat[1:]):
            return True
    return False


def main() -> int:
    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    patterns = covered_patterns(root)
    if not patterns:
        print("REFUSING: .gitattributes declares no `-text` patterns at all.")
        print("Either the file is missing or its format changed; this check cannot run.")
        return 2

    found: list[str] = []
    for path in root.rglob("*"):
        if not path.is_dir() or path.name not in FIXTURE_DIR_NAMES:
            continue
        rel_parts = path.relative_to(root).parts
        if any(p in SKIP for p in rel_parts):
            continue
        found.append(path.relative_to(root).as_posix())

    if not found:
        # A zero population is a broken scan, not a clean result: this repository has
        # carried fixture directories since June. Refusing here is the difference
        # between "nothing to check" and "the walk found nothing", which look
        # identical in a passing exit code.
        print("REFUSING: found no fixture directories at all, which cannot be right.")
        print("The directory walk or the skip list is broken; this check proves nothing.")
        return 2

    gaps = [d for d in sorted(found) if not is_covered(d, patterns)]
    if gaps:
        print("Fixture directories not exempt from line-ending translation:")
        for d in gaps:
            print(f"  {d}")
        print()
        print("Git rewrites LF to CRLF in these on a Windows checkout, so a byte-exact")
        print("assertion against anything inside them fails there and only there.")
        print("Add to .gitattributes:")
        for d in gaps:
            print(f"  {d}/** -text")
        print()
        print("Then re-normalise what is already committed:")
        print("  git add --renormalize . && git status --short")
        return 1

    print(f"fixture line endings: {len(found)} directories, all -text")
    return 0


if __name__ == "__main__":
    sys.exit(main())
