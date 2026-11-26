#!/usr/bin/env python3
"""check-cortexkit-layout.sh passes the allowlist, fails a stray tracked file, and fails
closed when git cannot list files."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-cortexkit-layout.sh"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


class CortexkitLayout(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo)
        (self.repo / "scripts").mkdir()
        shutil.copy(SCRIPT, self.repo / "scripts" / SCRIPT.name)

    def make_repo(self, tracked, gitignore=".cortexkit/*\n!.cortexkit/WORKER.md\n"):
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "user.name", "test")
        (self.repo / ".gitignore").write_text(gitignore)
        for path in tracked:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("x\n")
            git(self.repo, "add", "-f", path)
        git(self.repo, "add", ".gitignore", "scripts")
        git(self.repo, "commit", "-q", "-m", "fixture")

    def run_check(self):
        return subprocess.run(["bash", str(self.repo / "scripts" / SCRIPT.name)],
                              capture_output=True, text=True)

    def test_allowlisted_paths_pass(self):
        self.make_repo([".cortexkit/WORKER.md", ".cortexkit/release-notes/v1.md",
                        ".cortexkit/skills/x/SKILL.md", ".cortexkit/rules/r.md",
                        ".cortexkit/claustrum.jsonc"])
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("5 tracked path(s)", result.stdout)

    def test_a_private_file_unignored_by_a_bang_rule_fails(self):
        # The case `git ls-files -ci` misses: tracked, and no longer ignored.
        self.make_repo([".cortexkit/WORKER.md", ".cortexkit/notes.md"],
                       gitignore=".cortexkit/*\n!.cortexkit/WORKER.md\n!.cortexkit/notes.md\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(".cortexkit/notes.md", result.stderr)

    def test_a_nested_internal_doc_fails(self):
        self.make_repo([".cortexkit/internal-docs/designs/d.md"])
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("internal-docs/designs/d.md", result.stderr)

    def test_git_failure_fails_closed(self):
        # No repository at all: git ls-files fails, and an empty list must not pass.
        result = self.run_check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("BLIND", result.stderr)


if __name__ == "__main__":
    unittest.main()
