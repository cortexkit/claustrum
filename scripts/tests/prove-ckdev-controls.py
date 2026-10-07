#!/usr/bin/env python3
"""Expose the applied diff while a named source-fence control is running.

ckdev-mutate handles the edit and restoration. The caller stages the live files
first so this stat describes the mutant, not an unrelated implementation diff.
"""
import subprocess
import sys

subprocess.run(['git', 'diff', '--stat'], check=True)
sys.exit(subprocess.call([sys.executable, '-m', 'unittest', '-v', sys.argv[1]]))
