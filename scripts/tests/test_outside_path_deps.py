"""Controls for metadata failures, path boundaries, and Cargo stdout isolation."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'check-outside-path-deps.py'
spec = importlib.util.spec_from_file_location('outside_path_deps', SCRIPT)
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class OutsidePathDeps(unittest.TestCase):
    def run_metadata(self, root, packages=None, stdout=None, returncode=0):
        result = subprocess.CompletedProcess([], returncode,
            json.dumps({'packages': packages}) if stdout is None else stdout,
            'Blocking waiting for file lock on package cache')
        with patch.object(checker.subprocess, 'run', return_value=result) as run:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = checker.check(root)
        self.assertEqual(run.call_args.args[0], ['cargo', 'metadata', '--locked', '--format-version', '1'])
        self.assertTrue(run.call_args.kwargs['capture_output'])
        return status

    def test_stdout_only_and_registry_packages(self):
        root = Path(tempfile.gettempdir()) / 'inside'
        packages = [dict(name='member', source=None, manifest_path=str(root / 'Cargo.toml')),
                    dict(name='registry', source='registry+https://example.org', manifest_path='/elsewhere/Cargo.toml')]
        self.assertEqual(self.run_metadata(root, packages), 0)

    def test_outside_path_and_patch_are_refused(self):
        root = Path(tempfile.gettempdir()) / 'inside'
        packages = [dict(name='patched', source=None, manifest_path=str(root.parent / 'inside-other/Cargo.toml'))]
        self.assertEqual(self.run_metadata(root, packages), checker.VIOLATION)

    def test_zero_path_packages_is_check_error(self):
        self.assertEqual(self.run_metadata(Path.cwd(), []), checker.CHECK_ERROR)

    def test_broken_metadata_is_distinct_from_violation(self):
        for stdout, returncode in [('not JSON', 0), ('{}', 0), ('', 101)]:
            with self.subTest(stdout=stdout, returncode=returncode):
                self.assertEqual(self.run_metadata(Path.cwd(), stdout=stdout, returncode=returncode), checker.CHECK_ERROR)
        self.assertNotEqual(checker.CHECK_ERROR, checker.VIOLATION)

    def test_self_test_rejects_a_silent_checker(self):
        result = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(checker.subprocess, 'run', return_value=result):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(checker.self_test(), checker.CHECK_ERROR)
