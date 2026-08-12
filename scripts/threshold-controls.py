#!/usr/bin/env python3
"""Assert every threshold constant has a named boundary test.

A threshold is a constant a comparison decides on: a cap, a ceiling, a minimum
length, a staleness limit. Each needs a test that exercises the value where the
PREDICATE decides -- just below and at it -- because a control placed at zero or
empty tests the input instead. Measured: an empty-table control let a mutant
that warned unconditionally survive, since GROUP BY over zero rows returns
nothing whatever the HAVING clause says.

This checks the manifest is COMPLETE and its rows RESOLVE, which is deliberately
less than checking the tests are good. It cannot read a test and judge whether
the assertion sits at the boundary; a human does that once, at introduction,
which is when the evidence says the defect appears. What it can do is refuse to
let a new threshold arrive without that question being asked.

Usage:
  scripts/threshold-controls.py          # verify
  scripts/threshold-controls.py --list   # print what it found in the source
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "docs" / "threshold-controls.txt"

# Names that denote a value a comparison decides on. Deliberately a NAME rule:
# a semantic scan for `<` against a constant would drag in every array index and
# loop bound, and the false-positive rate is what gets a checker regenerated
# without being read.
# Tokens are matched between UNDERSCORE BOUNDARIES, not as substrings. A
# substring rule matched ADMIN_OP_SCHEMA_V1 and GEMINI_REDIRECT_URI, because
# both contain "MIN" -- and a checker with obvious false positives gets
# regenerated without being read, which is worse than not having it.
_TOKEN = r"(?:CAP|CEILING|LIMIT|MIN|MAX|CEILING)"
THRESHOLD_NAME = re.compile(
    rf"^pub const ((?:[A-Z0-9]+_)*{_TOKEN}(?:_[A-Z0-9]+)*)\s*:", re.M
)

# Fixed sizes wearing threshold-shaped names: nothing sits below them, so there
# is no boundary to control. Listed individually rather than pattern-matched --
# an exclusion rule wide enough to be convenient is wide enough to swallow a
# real threshold.
# Thresholds a NAME RULE CANNOT SEE. AUTH_EVENTS_PER_CREDENTIAL is a cap by
# meaning and carries none of the threshold words -- the scan misses it, and the
# manifest would have reported it as a stale row. Listing it here keeps the
# manifest honest about a limit the scan has rather than hiding it: a checker
# that silently under-scans is the same defect it was built to catch.
NAME_RULE_BLIND = {
    "AUTH_EVENTS_PER_CREDENTIAL": "crates/credentials-core/src/store.rs",
}

NOT_THRESHOLDS = {
    "ADMIN_NONCE_LEN",  # a fixed 32-byte nonce width
    "ADMIN_TAG_LEN",  # a fixed 32-byte MAC width
    "MASTER_KEY_LEN",  # a fixed 32-byte key width
    "KEY_ID_LEN",  # a fixed fingerprint width
}


def scan_source() -> dict[str, str]:
    """Every threshold constant in the crates, mapped to its file."""
    found: dict[str, str] = {}
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        if "/tests/" in str(path):
            continue
        for name in THRESHOLD_NAME.findall(path.read_text(encoding="utf-8")):
            if name not in NOT_THRESHOLDS:
                # as_posix(), NOT str(): on Windows str(Path) renders backslashes
                # and every manifest row fails to match. Same defect fixed in
                # endpoint-hosts.py on 2026-08-11 -- and pinning shell: bash does
                # NOT help, because the separator comes from Python's path
                # rendering rather than from the shell.
                found[name] = path.relative_to(ROOT).as_posix()
    found.update(NAME_RULE_BLIND)
    return found


def read_manifest() -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    for lineno, raw in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # REFUSE AN UNREADABLE ROW rather than skipping it. A parser that
        # silently drops rows it cannot read reports success while checking
        # nothing, which is the failure this whole file exists to prevent.
        if len(parts) != 3:
            sys.exit(
                f"{MANIFEST}:{lineno}: expected '<constant> <file> <test>', got: {raw}"
            )
        rows[parts[0]] = (parts[1], parts[2])
    return rows


def main() -> int:
    source = scan_source()

    if "--list" in sys.argv:
        for name, path in sorted(source.items()):
            print(f"{name} {path}")
        return 0

    manifest = read_manifest()
    problems: list[str] = []

    # An empty scan is indistinguishable from a broken pattern, so require the
    # population to be non-trivial before believing any of its answers.
    if len(source) < 4:
        return fail(
            f"found only {len(source)} threshold constants, which suggests the scan "
            f"pattern is broken rather than that the codebase has that few"
        )

    for name, path in sorted(source.items()):
        if name not in manifest:
            problems.append(
                f"  {name} ({path})\n"
                f"      No boundary test recorded. Where does its negative control sit?\n"
                f"      It must exercise the value JUST BELOW the threshold and AT it --\n"
                f"      a control at zero or empty tests the input, not the predicate.\n"
                f"      Add a row to {MANIFEST.relative_to(ROOT)} naming the test."
            )
        elif manifest[name][0] != path:
            problems.append(
                f"  {name} moved: manifest says {manifest[name][0]}, found in {path}"
            )

    for name in sorted(manifest):
        if name not in source:
            problems.append(
                f"  {name} is in the manifest but no longer in the source.\n"
                f"      Delete the row if the threshold is gone."
            )

    # The named test must EXIST. Without this the manifest degrades into prose:
    # a renamed or deleted test leaves a row that reads as coverage.
    for name, (path, test) in sorted(manifest.items()):
        if name not in source:
            continue
        hits = [
            p
            for p in (ROOT / "crates").rglob("*.rs")
            if f"fn {test}(" in p.read_text(encoding="utf-8")
        ]
        if not hits:
            problems.append(
                f"  {name}: named boundary test '{test}' does not exist.\n"
                f"      A row naming a missing test reads as coverage and is not."
            )

    if problems:
        return fail("thresholds without a recorded boundary test:\n" + "\n".join(problems))

    print(f"threshold controls: {len(source)} threshold(s), each with a boundary test")
    return 0


def fail(message: str) -> int:
    print(f"REFUSING: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
