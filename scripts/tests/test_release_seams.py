#!/usr/bin/env python3
"""Keep release-build.sh's pinned count of debug-only seams equal to the source.

The release builder refuses when the count differs, but it runs only after a change
has landed. This check runs in the gate, so a new seam is noticed before landing,
together with the decision the pin asks for (what its test arm does against a
staged release binary).
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
# The builder's own scan: grep -rcE 'cfg\(.*debug_assertions' over crates/*/src, which
# counts matching lines in every .rs file.
SEAM = re.compile(r'cfg\(.*debug_assertions')


def source_seams() -> int:
    count = 0
    for path in ROOT.glob('crates/*/src/**/*.rs'):
        count += sum(1 for line in path.read_text(errors='replace').splitlines()
                     if SEAM.search(line))
    return count


class ReleaseSeamPin(unittest.TestCase):
    def test_pinned_count_matches_the_source(self):
        script = (ROOT / 'scripts/release-build.sh').read_text()
        pinned = re.search(r'^KNOWN_DEBUG_SEAMS=(\d+)$', script, re.M)
        self.assertIsNotNone(pinned, 'release-build.sh no longer pins KNOWN_DEBUG_SEAMS')
        found = source_seams()
        # The anchor: the import picker alone holds 13, so a scan finding fewer than
        # that has stopped reading the source rather than found it clean.
        self.assertGreaterEqual(found, 13)
        self.assertEqual(
            found, int(pinned.group(1)),
            'debug-only seams changed: decide what the matching test arm does under '
            'CRED_CLI_BIN / CRED_DAEMON_BIN, then update KNOWN_DEBUG_SEAMS and its table '
            'in scripts/release-build.sh')


if __name__ == '__main__':
    unittest.main()
