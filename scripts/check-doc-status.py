#!/usr/bin/env python3
"""Refuse a design doc whose NOT-BUILT status claim is contradicted by the code.

WHY THIS EXISTS. This repo adds a "DESIGNED, NOT BUILT" header to design docs
deliberately: a document detailed enough to follow reads as one that has been
followed, and two seats have built against a spec believing it shipped. The header
is the guard against that.

Then the feature ships, the header does not move, and the guard inverts: an external
operator read `report-marks-stale-design.md` on 2026-08-24 and concluded the feature
was unbuilt A DAY AFTER IT WAS DEPLOYED AND MEASURED IN PRODUCTION. The safeguard
became the defect, pointing the other way.

A STATUS LINE IS AN ASSERTION THAT AGES, AND WRITING THE CONVENTION DOWN IS NOT A
MECHANISM. So a doc claiming NOT BUILT must name the symbol whose EXISTENCE would
falsify the claim, and this script fails the gate when that symbol appears.

Usage in a doc that is genuinely unbuilt:

    <!-- built-when: crates/credentials-core/src/store.rs::mark_stale_if_version -->
    **Status: DESIGNED, NOT BUILT (date).** ...

When the feature ships, the symbol appears, this check goes red, and updating the
header is how you make it green. The doc cannot silently outlive its own claim.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DOCS = Path("docs")
# Scoped to a STATUS LINE, not to the phrase anywhere in the file. The first version
# matched prose, and its first victim was this repo's own doc explaining why the
# header had gone stale: a sentence ABOUT a status claim is not a status claim. A
# checker that cannot tell those apart teaches people to reword their prose.
# Matched in the two STRUCTURAL positions a status claim occupies -- a Status line and
# a heading -- rather than anywhere in the file.
#
# The first version matched prose, and its first victim was this repo's own doc
# explaining why a header had gone stale: a sentence ABOUT a status claim is not one.
# A checker that cannot tell those apart teaches people to reword their prose.
#
# But scoping to Status lines ALONE reported "0 claims checked, all honest" while a
# real unbuilt claim sat in a heading two files over -- the vacuous pass this script's
# own empty-enumeration guard exists to prevent, reintroduced one narrowing later.
# Both positions, and the refusal below fires when NEITHER is present in a repo that
# should have some.
NOT_BUILT = re.compile(
    r"^\s*(?:#{1,6}\s.*|(?:\*\*)?Status:.*)(?:NOT BUILT|NOT built|NONE OF THIS IS BUILT)",
    re.MULTILINE,
)
MARKER = re.compile(r"<!--\s*built-when:\s*(?P<path>[^:]+)::(?P<symbol>[^\s]+)\s*-->")

# THE CROSS-REPO CASE, met the first time a design doc arrived through a PR rather
# than from this seat: the contributor's serve-contract design is the VAULT-SIDE HALF
# of a two-part design whose implementing half lives in another repository. No symbol
# in this tree can falsify it, so demanding one would have forced a marker pointing at
# a plausible-looking local symbol that does not govern the claim -- a guard that fires
# on the wrong event is worse than an absent one, because it reads as coverage.
#
# The escape is deliberately NOT silent. A doc may declare that its falsifier is
# external, but it must say WHERE, and this script COUNTS AND PRINTS those separately
# on every run. The guard's purpose is that a doc cannot silently outlive its claim;
# for a cross-repo claim no local mechanism can enforce that, so the honest substitute
# is to keep the unguarded ones VISIBLE rather than to pretend they are covered.
#
#     <!-- built-when: EXTERNAL anthropic-auth plugin -- the implementing half is not
#          in this repository, so no local symbol can disprove this -->
# `.*?` with DOTALL rather than `[^\n]*?`: the first version could not cross a newline,
# so it silently failed to match the very marker it was written for -- a multi-line one,
# which is the shape any honest destination-plus-reason takes -- and the doc came back
# as "names no falsifier". A regex that only matches the one-line case would have let
# the terse, least informative markers through and refused the useful ones.
EXTERNAL = re.compile(r"<!--\s*built-when:\s*EXTERNAL\s+(?P<where>.*?)\s*-->", re.DOTALL)


def main() -> int:
    if not DOCS.is_dir():
        print(f"REFUSING: no {DOCS}/ directory — run from the repo root", file=sys.stderr)
        return 2

    docs = sorted(DOCS.rglob("*.md"))
    if not docs:
        # An empty enumeration passes every check trivially, which is the shape of a
        # dead gate. Refuse instead.
        print("REFUSING: found no markdown under docs/", file=sys.stderr)
        return 2

    failures: list[str] = []
    externals: list[str] = []
    checked = 0

    for doc in docs:
        text = doc.read_text(encoding="utf-8", errors="replace")
        if not NOT_BUILT.search(text):
            continue

        external = EXTERNAL.search(text)
        if external:
            where = " ".join(external.group("where").split())
            # A bare EXTERNAL with no destination is the hole this escape must not be:
            # it would let any doc opt out of the guard by typing one word.
            if len(where) < 12:
                failures.append(
                    f"{doc.as_posix()} declares its falsifier EXTERNAL but does not say\n"
                    f"    where. Name the repository or component that would disprove the\n"
                    f"    claim, so a reader can go and check it."
                )
            else:
                externals.append(f"{doc.as_posix()} -> {where}")
            continue

        marker = MARKER.search(text)
        if not marker:
            failures.append(
                f"{doc.as_posix()} claims NOT BUILT but names no falsifier.\n"
                f"    Add a marker naming the symbol whose existence would disprove it:\n"
                f"    <!-- built-when: path/to/file.rs::symbol_name -->\n"
                f"    An unfalsifiable status claim is how this header went stale before."
            )
            continue

        checked += 1
        target = Path(marker.group("path"))
        symbol = marker.group("symbol")
        if not target.is_file():
            failures.append(
                f"{doc.as_posix()} names {target.as_posix()} which does not exist.\n"
                f"    A marker pointing at a missing file can never fire, so the claim\n"
                f"    is unguarded. Fix the path."
            )
            continue

        if symbol in target.read_text(encoding="utf-8", errors="replace"):
            failures.append(
                f"{doc.as_posix()} says NOT BUILT, but `{symbol}` EXISTS in\n"
                f"    {target.as_posix()}. The feature shipped and the header did not\n"
                f"    move. Update the status line — that is what this check is for."
            )

    if failures:
        print("REFUSING: design doc status claims contradicted by the code:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}\n", file=sys.stderr)
        return 1

    print(f"doc status: {checked} NOT-BUILT claim(s) checked against their falsifier, all honest")
    if externals:
        # Printed unconditionally, not hidden behind a verbose flag: these are the
        # claims this gate CANNOT check, and a reader of the output should see the
        # boundary of what was actually verified.
        print(f"doc status: {len(externals)} claim(s) declared EXTERNAL and NOT guarded here:")
        for e in externals:
            print(f"  {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
