"""Run a planted violation through a scan's real decision path before trusting it.

The controls use temporary fixtures, not edits to the checkout. Importing a scan
in the unittest bypasses its executable entry point, so this does not recurse.
"""
from pathlib import Path
import subprocess
import sys


def check(test):
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "-v",
         "scripts.tests.test_script_contracts.ScriptContracts." + test],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode or "Ran 1 test" not in result.stderr or "skipped" in result.stderr:
        print("REFUSING: planted scan control did not pass:\n" +
              result.stdout + result.stderr, file=sys.stderr)
        return 2
    print(f"scan self-test: {test} (1 planted-violation control passed)")
    return 0
