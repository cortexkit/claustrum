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

# Byte-string domain separators: `b"cortexkit-credentials/…"`, wherever they appear
# — as a const, or inline in a `hasher.update(…)` call, which is how three of them
# are written.
#
# THESE ARE ON-DISK FORMAT PARAMETERS WEARING THE CLOTHES OF NAMES, and they are a
# worse hazard than the endpoints: a changed endpoint misroutes a credential, a
# changed separator makes every existing vault unreadable. The `cortexkit-credentials`
# prefix is the PRE-RENAME module id, so the tempting edit — updating it to
# `claustrum` for consistency — is exactly the destructive one.
#
# Measured on the envelope AAD: seal a vault under v1, reopen under v2, and
# `EncryptedStore::open` fails with "cipher envelope failed authenticated
# decryption". Nothing in 240 unit tests, 8 e2e arms or 4 rotation crash cuts
# noticed the change.
DOMAIN_RE = re.compile(r'b"(cortexkit-[a-z-]+/[a-z0-9-]+/v\d[^"]*)"')
DOMAIN_MANIFEST = ROOT / "docs" / "domain-separators.txt"

# `#[cfg(test)]` immediately followed by a module declaration -- the conventional
# trailing test module, and the only form that should truncate a scan. The bare
# attribute also marks PRODUCTION test seams (store.rs `with_raw_conn`,
# read_surface.rs `force_stale_refresher_for_test`), so cutting at the first
# occurrence would silently drop everything below them.
TEST_MOD_RE = re.compile(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{")


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
                # POSIX separators always. `str(Path)` yields backslashes on Windows,
                # so the manifest would read as 29 REMOVED plus 29 NEW there --
                # every row "changed" while nothing in source did. The manifest is a
                # committed artifact shared across platforms, so its keys cannot
                # carry the local path flavour.
                rel = path.relative_to(ROOT).as_posix()
                found.append((rel, m.group(1), host))
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


def parse(text: str, manifest: Path) -> list[tuple[str, str, str]]:
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
                f"{manifest}:{lineno}: expected three fields, got: {stripped}"
            )
        rows.append((parts[0], parts[1], parts[2]))
    return rows


def discover_domains() -> list[tuple[str, str, str]]:
    """Every domain separator in production source, as (file, lineno, value).

    Rows are `(file, value, value)` -- the value twice, so the shared checker's
    key is `(file, value)`.

    NOT KEYED BY LINE NUMBER, which was the first attempt: three of the seven are
    written inline in a `hasher.update(b"…")` call and have no constant name, so
    line seemed like the only stable handle. It is not stable at all -- any edit
    above one shifts it, producing a REMOVED/NEW pair for a separator nobody
    touched. A checker that cries wolf on unrelated edits is one that gets
    regenerated without reading, which is precisely how a real change would pass.

    Keying on the value itself is immune to movement, and a changed separator
    still fires: it appears as the old value REMOVED and the new one NEW, which is
    the finding stated in two lines instead of one.
    """
    found: list[tuple[str, str, str]] = []
    for src in SOURCE_DIRS:
        for path in sorted(src.rglob("*.rs")):
            text = path.read_text(encoding="utf-8")
            test_mods = [m.start() for m in TEST_MOD_RE.finditer(text)]
            cutoff = min(test_mods) if test_mods else len(text)
            for m in DOMAIN_RE.finditer(text):
                if m.start() > cutoff:
                    continue
                rel = path.relative_to(ROOT).as_posix()
                found.append((rel, m.group(1), m.group(1)))
    return sorted(set(found))


def render_domains(rows: list[tuple[str, str, str]]) -> str:
    head = (
        "# DERIVED FILE -- regenerate with scripts/endpoint-hosts.py --update and\n"
        "# review the DIFF. Do not hand-edit.\n"
        "#\n"
        "# One line per cryptographic domain separator: <file> <value> <value>.\n"
        "# The value appears twice so the row is keyed by it: line numbers move when\n"
        "# unrelated code shifts, and a checker that cries wolf gets regenerated\n"
        "# without being read.\n"
        "#\n"
        "# THESE ARE ON-DISK FORMAT PARAMETERS, NOT NAMES. Each is authenticated or\n"
        "# hashed into stored data and re-derived on read, so changing one makes every\n"
        "# existing vault unreadable -- measured on the envelope AAD: seal under v1,\n"
        "# reopen under v2, EncryptedStore::open fails authenticated decryption, and\n"
        "# nothing in the test suite noticed.\n"
        "#\n"
        "# The `cortexkit-credentials` prefix is the PRE-RENAME module id. Updating it\n"
        "# to `claustrum` for consistency is the destructive edit this file exists to\n"
        "# catch. A separator only ever changes as a deliberate, migrated format bump.\n"
    )
    return head + "".join(f"{f} {n} {v}\n" for f, n, v in rows)


def check(
    rows: list[tuple[str, str, str]],
    manifest: Path,
    label: str,
    noun: str,
) -> int:
    """Compare discovered rows against a manifest; print a keyed diff on mismatch."""
    if not manifest.exists():
        print(f"missing {manifest.relative_to(ROOT)}; run with --update")
        return 1
    recorded = parse(manifest.read_text(encoding="utf-8"), manifest)
    if recorded == rows:
        print(f"{label}: {len(rows)} pinned, all match")
        return 0
    rec = {(f, n): v for f, n, v in recorded}
    cur = {(f, n): v for f, n, v in rows}
    print(f"{label.upper()} MISMATCH")
    for key in sorted(set(rec) | set(cur)):
        f, n = key
        if key not in rec:
            print(f"  NEW      {f} {n} -> {cur[key]} (record it deliberately)")
        elif key not in cur:
            print(f"  REMOVED  {f} {n} (was {rec[key]})")
        elif rec[key] != cur[key]:
            print(f"  CHANGED  {f} {n}: {rec[key]} -> {cur[key]}")
    print(f"\nIf intended: scripts/endpoint-hosts.py --update, then review the diff.")
    print(f"A {noun} that moved without a reason is the finding.")
    return 1


def main() -> int:
    rows = discover()
    domains = discover_domains()
    # An empty discovery is a broken scan, not a clean repo: both populations are
    # load-bearing and cannot all vanish.
    if not rows:
        print("REFUSING: found no endpoint constants at all -- the scan is broken")
        return 1
    if not domains:
        print("REFUSING: found no domain separators at all -- the scan is broken")
        return 1

    if "--update" in sys.argv:
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(render(rows), encoding="utf-8")
        DOMAIN_MANIFEST.write_text(render_domains(domains), encoding="utf-8")
        print(f"wrote {MANIFEST.relative_to(ROOT)} ({len(rows)} endpoints)")
        print(f"wrote {DOMAIN_MANIFEST.relative_to(ROOT)} ({len(domains)} separators)")
        return 0

    rc = check(rows, MANIFEST, "endpoint hosts", "host")
    rc |= check(domains, DOMAIN_MANIFEST, "domain separators", "separator")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
