#!/usr/bin/env python3
"""Pin the HOST every provider endpoint constant reaches.

WHY A MANIFEST RATHER THAN MORE UNIT TESTS. Seven of these are pinned by a literal
assertion in `refresh_adapters/mod.rs`; the rest were not, and as separate
assertions the POPULATION is invisible: nothing states how many exist, and nothing
fails when a new provider adds one. "Is this URL asserted somewhere" is also
satisfied by a test comparing the constant to itself, which is the shape that let a
repointed Anthropic endpoint pass 238 tests and 8 e2e arms.

WHAT A WRONG HOST COSTS. A refresh posts a LIVE REFRESH TOKEN in the request body,
so a wrong host does not merely fail -- it receives a working credential. The
symptom is then indistinguishable from a dead login: the exchange fails, the
account reads as needing re-auth, and logging in again neither fixes it nor reveals
the cause.

ONLY THE HOST IS PINNED, NEVER THE PATH. Paths change with an upstream API and say
nothing about where a credential travels. A check that fires on every path revision
gets relaxed away, and a relaxed check is worse than none because it still reads as
coverage.

THE MANIFEST IS DERIVED, NOT TRANSCRIBED. `--update` rewrites it from source; the
review step is reading the diff. Hand-writing it inherits the errors of
recollection while looking more authoritative than the source it came from -- I
nearly pinned `api.x.ai` for what is actually `auth.x.ai`, and QTA recorded
`mimo.xiaomi.com` for `platform.xiaomimimo.com`, both from memory within an hour of
each other. A host that moves in the diff without a reason is the finding.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = [
    ROOT / "crates" / "credentials-core" / "src",
    ROOT / "crates" / "credentials-module" / "src",
]
MANIFEST = ROOT / "docs" / "endpoint-hosts.txt"

# `pub const NAME: &str = "https://host/path";` and its private form.
CONST_RE = re.compile(
    r'\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"(https://[^"]+)"'
)


def discover() -> list[tuple[str, str, str]]:
    """Every PRODUCTION https endpoint constant in source, as (file, const, host).

    Test fixtures are excluded, and that exclusion is load-bearing rather than
    tidiness: the first run of this script pinned five constants from a
    `#[cfg(test)]` module, so the manifest claimed to protect hosts no credential
    ever reaches while reading exactly like the real rows. A manifest whose
    population is wrong is worse than none -- it reports a count that sounds like
    coverage and cannot be checked by looking at it.

    THE CUT IS THE TEST MODULE, NOT THE FIRST `#[cfg(test)]`, and the difference is
    a real bug rather than pedantry. That attribute also marks PRODUCTION test
    seams -- `store.rs` has `with_raw_conn`, `read_surface.rs` has
    `force_stale_refresher_for_test`, and `refresh_adapters/mod.rs` declares
    `pub(crate) mod fixture` that way. Cutting at the first occurrence would drop
    everything below those, and the run would still report clean: an
    UNDER-inclusion that is invisible in the count, exactly as the over-inclusion
    was. No endpoint sits below one today, so the naive cut would have been correct
    by coincidence -- one edit away from silently pinning less than it claims.

    Both directions of this boundary fail quietly, which is why the guard is tested
    both ways: a constant planted after a production `#[cfg(test)]` must be FOUND,
    and one planted inside the test module must be IGNORED.
    """
    # `#[cfg(test)]` immediately followed by a module declaration -- the conventional
    # trailing test module, and the only form that should truncate the scan.
    TEST_MOD_RE = re.compile(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{")
    found: list[tuple[str, str, str]] = []
    for src in SOURCE_DIRS:
        for path in sorted(src.rglob("*.rs")):
            text = path.read_text(encoding="utf-8")
            test_mods = [m.start() for m in TEST_MOD_RE.finditer(text)]
            cutoff = min(test_mods) if test_mods else len(text)
            for m in CONST_RE.finditer(text):
                if m.start() > cutoff:
                    continue
                # A templated host ({account}.snowflakecomputing.com) still has a
                # pinnable suffix: the tenant varies, the provider domain must not.
                host = urlsplit(m.group(2)).netloc
                found.append((str(path.relative_to(ROOT)), m.group(1), host))
    return sorted(found)


def render(rows: list[tuple[str, str, str]]) -> str:
    head = (
        "# DERIVED FILE -- regenerate with scripts/endpoint-hosts.py --update and\n"
        "# review the DIFF. Do not hand-edit: a transcribed host inherits the errors\n"
        "# of recollection while looking more authoritative than the source.\n"
        "#\n"
        "# One line per endpoint constant: <file> <CONST> <host>. Only the host is\n"
        "# pinned; paths change with upstream APIs and say nothing about where a\n"
        "# credential travels.\n"
        "#\n"
        "# A host that changed without a reason is a finding: a refresh posts a live\n"
        "# refresh token in the body, so a wrong host RECEIVES a working credential\n"
        "# and the failure looks like an ordinary dead login.\n"
    )
    body = "".join(f"{f} {n} {h}\n" for f, n, h in rows)
    return head + body


def parse(text: str) -> list[tuple[str, str, str]]:
    rows = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        # REFUSE an unparseable row rather than skipping it. A parser that silently
        # drops rows it cannot read reports success while checking less than the
        # file claims -- the exact failure this manifest exists to prevent.
        if len(parts) != 3:
            raise SystemExit(
                f"{MANIFEST}:{lineno}: expected '<file> <CONST> <host>', got: {stripped}"
            )
        rows.append((parts[0], parts[1], parts[2]))
    return rows


def main() -> int:
    rows = discover()
    if not rows:
        # An empty discovery is a broken scan, not a clean repo: these constants
        # are load-bearing and cannot all vanish.
        print("REFUSING: found no endpoint constants at all -- the scan is broken")
        return 1

    if "--update" in sys.argv:
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(render(rows), encoding="utf-8")
        print(f"wrote {MANIFEST.relative_to(ROOT)} ({len(rows)} endpoints)")
        return 0

    if not MANIFEST.exists():
        print(f"missing {MANIFEST.relative_to(ROOT)}; run with --update")
        return 1

    recorded = parse(MANIFEST.read_text(encoding="utf-8"))
    if recorded == rows:
        print(f"endpoint hosts: {len(rows)} pinned, all match")
        return 0

    rec = {(f, n): h for f, n, h in recorded}
    cur = {(f, n): h for f, n, h in rows}
    print("ENDPOINT HOST MISMATCH")
    for key in sorted(set(rec) | set(cur)):
        f, n = key
        if key not in rec:
            print(f"  NEW      {f} {n} -> {cur[key]} (record it deliberately)")
        elif key not in cur:
            print(f"  REMOVED  {f} {n} (was {rec[key]})")
        elif rec[key] != cur[key]:
            print(f"  CHANGED  {f} {n}: {rec[key]} -> {cur[key]}")
    print("\nIf a change is intended: scripts/endpoint-hosts.py --update, then review")
    print("the diff. A host that moved without a reason is the finding.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
