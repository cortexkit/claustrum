#!/usr/bin/env python3
"""Refuse `str()` on a path in the repo scripts.

WHY THIS EXISTS RATHER THAN A COMMENT. `str(Path)` renders backslashes on
Windows, so any comparison against a posix literal -- a manifest row, a
`"/tests/"` fragment -- fails there and passes everywhere else. It has now
appeared three times:

  2026-08-11  endpoint-hosts.py    all 29 manifest rows failed on the Windows leg
  2026-08-12  threshold-controls.py  every manifest row reported "moved"
  2026-08-12  threshold-controls.py  a "/tests/" exclusion, LATENT, one line below
                                     the comment warning about the previous one

The third is the argument. I had just fixed the second, written a comment about
it, and left an instance of the same defect immediately above that comment --
and CI passed, because no threshold is currently defined in a test file. Knowing
about a defect does not prevent it; a check does.

It also does not depend on remembering to run it against a new script: the sweep
is over `scripts/*.py`, so a file added tomorrow is covered by existing code.

The permitted form is `Path.as_posix()`. Where a genuine platform-native string
is wanted -- passing a path to a subprocess -- use `os.fspath()`, which says so
at the call site and is not what a comparison against a literal ever wants.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

# `str(` applied to something path-shaped. Deliberately narrow: a broad "no str()"
# rule would fire on every f-string and be switched off within a week.
BAD = re.compile(r"\bstr\(\s*(?:[A-Za-z_][A-Za-z0-9_]*)?(?:path|Path|_dir|file)\w*\s*[).]")

# `Path.relative_to()` returns a Path, and interpolating it into an f-string calls
# str() implicitly -- the same rendering, with no `str(` to match. Only worth
# flagging when the result is COMPARED; in a print it is cosmetic.
IMPLICIT = re.compile(r"relative_to\([^)]*\)\s*(?:==|!=|\bin\b)")


def main() -> int:
    files = sorted(SCRIPTS.glob("*.py"))
    if not files:
        print("REFUSING: no scripts found to check -- the sweep is broken", file=sys.stderr)
        return 1

    problems: list[str] = []
    for path in files:
        if path.name == Path(__file__).name:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            # A line describing the defect is not the defect. Comments are where the
            # rule gets explained, and flagging them makes the checker unusable in
            # exactly the files that document it.
            if stripped.startswith("#"):
                continue
            rel = path.relative_to(ROOT).as_posix()
            if BAD.search(line):
                problems.append(
                    f"  {rel}:{lineno}: str() on a path renders backslashes on Windows\n"
                    f"      {stripped}\n"
                    f"      Use .as_posix() for comparison, or os.fspath() when a\n"
                    f"      platform-native string is genuinely wanted."
                )
            elif IMPLICIT.search(line):
                problems.append(
                    f"  {rel}:{lineno}: relative_to() result compared without .as_posix()\n"
                    f"      {stripped}\n"
                    f"      The f-string/comparison renders it platform-natively."
                )

    if problems:
        print(
            "REFUSING: platform-dependent path rendering:\n" + "\n".join(problems),
            file=sys.stderr,
        )
        return 1

    print(f"path rendering: {len(files)} script(s) clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
