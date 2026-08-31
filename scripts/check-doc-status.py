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
# Hence both positions.
#
# THIS COMMENT USED TO END BY CLAIMING A REFUSAL FIRES "WHEN NEITHER IS PRESENT IN A
# REPO THAT SHOULD HAVE SOME". No such refusal was ever written. The sentence read as
# a mechanism for a week; EXTRACTOR_CONTROL below is the mechanism, added once the
# claim was tested rather than re-read.
NOT_BUILT = re.compile(
    r"^\s*(?:#{1,6}\s.*|(?:\*\*)?Status:.*)(?:NOT BUILT|NOT built|NONE OF THIS IS BUILT)",
    re.MULTILINE,
)
MARKER = re.compile(r"<!--\s*built-when:\s*(?P<path>[^:]+)::(?P<symbol>[^\s]+)\s*-->")

# POSITIVE CONTROL FOR THE EXTRACTOR ITSELF, and the reason it is here rather than
# assumed: a scan of a corpus reports ZERO for two different causes that print the same
# number -- the corpus genuinely holds no unbuilt claim, or the pattern stopped matching
# the shape it was written for. Only the first is a pass. Proved on 2026-08-31 by
# breaking NOT_BUILT so it could match nothing at all; this script printed
#
#     doc status: 0 NOT-BUILT claim(s) checked against their falsifier, all honest
#
# and exited 0 -- a confident verification claim derived from zero measurements, which
# is the same defect an external contributor filed against this repo's test-count check.
# Worse, the comment above ALREADY CLAIMED this refusal existed ("the refusal below
# fires when NEITHER is present"); it did not. A described guard reads as a present one.
#
# A population floor would be wrong here, unlike the threshold scan: a repo where every
# design doc has shipped legitimately has zero claims. So the control runs against fixed
# samples instead, which separates "the extractor works" from "the corpus has none".
#
# The negative arm is not decoration. This pattern has been narrowed twice for
# over-matching prose, and a control that only proves it still FINDS things would pass a
# version that matches every sentence containing the words.
EXTRACTOR_CONTROL: tuple[tuple[str, str, bool], ...] = (
    ("Status line", "**Status: DESIGNED, NOT BUILT (2026-01-01).** Nothing here exists.", True),
    ("heading", "## Status: NOT BUILT", True),
    ("shout form", "# NONE OF THIS IS BUILT", True),
    ("prose", "This section explains why a NOT BUILT header went stale last month.", False),
)

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


def check_extractor() -> list[str]:
    """Prove the pattern still sees each shape it claims to, and still ignores prose."""
    broken: list[str] = []
    for label, sample, should_match in EXTRACTOR_CONTROL:
        if bool(NOT_BUILT.search(sample)) is not should_match:
            verb = "no longer matches" if should_match else "now matches"
            broken.append(f"{label}: the pattern {verb} {sample!r}")
    return broken


def main() -> int:
    # Before believing any count this scan produces, including zero.
    broken = check_extractor()
    if broken:
        print(
            "REFUSING: the NOT-BUILT pattern no longer behaves as documented, so every\n"
            "    count below would be about the pattern rather than about the docs:",
            file=sys.stderr,
        )
        for b in broken:
            print(f"  - {b}", file=sys.stderr)
        return 2

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

    # Worded so a zero reads as a zero. "all honest" over an empty set is a verdict
    # about nothing, and it is the phrasing that made the vacuous pass unreadable.
    if checked:
        print(
            f"doc status: {checked} NOT-BUILT claim(s) checked against their falsifier, "
            f"all honest (extractor control: {len(EXTRACTOR_CONTROL)} shapes verified)"
        )
    else:
        print(
            f"doc status: no NOT-BUILT claim in {len(docs)} doc(s) — nothing to falsify "
            f"(extractor control: {len(EXTRACTOR_CONTROL)} shapes verified, so this is an "
            f"empty corpus rather than a blind scan)"
        )
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
