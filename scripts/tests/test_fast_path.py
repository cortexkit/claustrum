#!/usr/bin/env python3
"""Exercise diff scope and release refusals without building or placing a vault."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fast_check', ROOT / 'scripts/fast-check.py')
assert spec is not None and spec.loader is not None
fast = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fast)


class FastScope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        self.packages = []
        for name in ('core', 'module', 'client'):
            path = self.root / 'crates' / name / 'Cargo.toml'
            path.parent.mkdir(parents=True)
            path.write_text('initial\n')
            self.packages.append({'id': name, 'name': name, 'manifest_path': os.fspath(path)})
        self.git('add', '.')
        self.git('commit', '-qm', 'initial')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.metadata = {'packages': self.packages, 'workspace_members': ['core', 'module', 'client']}

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True)

    def scope(self):
        with patch.object(fast, 'ROOT', self.root):
            return fast.scope(self.base, self.metadata)[0]

    def test_committed_staged_unstaged_and_untracked_files_select_crates(self):
        (self.root / 'crates/core/Cargo.toml').write_text('committed\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'core change')
        (self.root / 'crates/module/Cargo.toml').write_text('staged\n')
        self.git('add', '.')
        (self.root / 'crates/client/new.rs').write_text('untracked\n')
        self.assertEqual(self.scope(), ['client', 'core', 'module'])
        (self.root / 'crates/module/Cargo.toml').write_text('unstaged\n')
        self.assertEqual(self.scope(), ['client', 'core', 'module'])

    def test_rename_and_deletion_include_old_crate(self):
        self.git('mv', 'crates/core/Cargo.toml', 'crates/client/renamed')
        (self.root / 'crates/module/Cargo.toml').unlink()
        self.assertEqual(self.scope(), ['client', 'core', 'module'])

    def test_shared_lock_selects_all_but_docs_do_not(self):
        (self.root / 'README.md').write_text('docs only')
        self.assertEqual(self.scope(), [])
        (self.root / 'Cargo.lock').write_text('shared')
        self.assertEqual(self.scope(), ['client', 'core', 'module'])

    def test_zero_test_and_runtime_skip_are_refused(self):
        with contextlib.redirect_stdout(io.StringIO()):
            for message in ('test result: ok. 0 passed', 'SKIPPING arm\ntest result: ok. 1 passed', ''):
                with self.subTest(message=message), self.assertRaises(RuntimeError):
                    fast.run('probe', ['printf', '%s', message], tests=True)
            fast.run('probe', ['printf', 'test result: ok. 1 passed\n'], tests=True)

    def test_missing_or_unselected_critical_protection_is_refused(self):
        with patch.object(fast, 'REQUIRED_DAEMON_TESTS', ['credential_get_request_key_set_is_pinned']), \
                patch.object(fast, 'DAEMON_FILTERS', ['wire']):
            with self.assertRaisesRegex(RuntimeError, 'missing or not selected'):
                fast.verify_registration(['tests::unrelated_wire_test'])
            with self.assertRaisesRegex(RuntimeError, 'missing or not selected'):
                fast.verify_registration(['tests::credential_get_request_key_set_is_pinned'])
            with patch.object(fast, 'DAEMON_FILTERS', ['key_set']):
                fast.verify_registration(['tests::credential_get_request_key_set_is_pinned'])


class ReleaseFastPath(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts/lib').mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/release-build.sh', self.root / 'scripts/release-build.sh')
        shutil.copy2(ROOT / 'scripts/lib/ckdev-binary.sh', self.root / 'scripts/lib/ckdev-binary.sh')
        (self.root / 'scripts/fast-check.sh').write_text('echo fast-check >> "$HOME/calls"\nexit "${CHECK_RC:-0}"\n')
        # The builder counts debug-only source seams. Five inert lines let the real
        # count check run in this fixture instead of stubbing that refusal away.
        source = self.root / 'crates/example/src/seams.rs'
        source.parent.mkdir(parents=True)
        source.write_text('cfg(debug_assertions)\n')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, HOME=os.fspath(self.root), PROBE='none: hermetic policy test',
                        PATH=os.fspath(self.bin) + ':' + os.environ['PATH'])
        self.executable('git', '''case "$*" in
          'status --porcelain') [ "${DIRTY:-0}" = 0 ] || echo ' M dirty';;
          'status --short') echo ' M dirty';;
          'symbolic-ref -q --short HEAD') echo feature;;
          'fetch --quiet origin master') exit 0;;
          'merge-base --is-ancestor '*) exit "${ANCESTOR_RC:-1}";;
          'rev-parse --verify origin/master') printf '%040d\n' 2;;
          'rev-parse HEAD') printf '%040d\n' 1;;
          'rev-parse --short '*) echo 1234567;;
          *) echo "unexpected git: $*" >&2; exit 90;; esac''')
        self.executable('cargo', '''echo "cargo $*" >> "$HOME/calls"
          if [ "$1" = build ]; then
            mkdir -p target/stamped/release
            for bin in ck-auth ck-claustrum; do
              printf '#!/bin/bash\necho "binary (0000000000000000000000000000000000000001)"\n' > "target/stamped/release/$bin"
              chmod +x "target/stamped/release/$bin"
            done
          else echo 'test result: ok. 9 passed'; fi''')
        self.executable('codesign', '''echo "codesign $*" >> "$HOME/calls"
          if [ "$1" = -dv ]; then
            echo "Identifier=${IDENTIFIER:-$(basename "${@: -1}")}" >&2
            echo "flags=${RUNTIME:-runtime}" >&2
          fi''')

    def executable(self, name, body):
        path = self.bin / name
        path.write_text('#!/usr/bin/env bash\nset -euo pipefail\n' + body + '\n')
        path.chmod(0o755)

    def release(self, *args, **env):
        return subprocess.run(['bash', 'scripts/release-build.sh', *args], cwd=self.root,
                              env=dict(self.env, **env), text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=15)

    def calls(self):
        path = self.root / 'calls'
        return path.read_text() if path.exists() else ''

    def test_fast_accepts_clean_local_commit_and_records_ancestry(self):
        result = self.release('--fast')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.calls().startswith('fast-check\ncargo build'), self.calls())
        self.assertNotIn('cargo test', self.calls())
        info = next((self.root / 'target/staged').glob('*/build-info.txt')).read_text()
        self.assertIn('fast_path=1\non_origin_master=false', info)
        self.assertIn('staged daemon/admin verification was NOT run', result.stdout)

    def test_default_retains_branch_and_ancestry_refusals(self):
        result = self.release()
        self.assertIn('not master', result.stdout)
        result = self.release(CK_RELEASE_ALLOW_BRANCH='1')
        self.assertIn('not an ancestor', result.stdout)
        self.assertEqual(self.calls(), '')

    def test_default_runs_artifact_suites(self):
        result = self.release(CK_RELEASE_ALLOW_BRANCH='1', ANCESTOR_RC='0')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.calls().startswith('cargo build'), self.calls())
        self.assertIn('--test real_daemon_e2e', self.calls())
        self.assertIn('--test cli_admin', self.calls())
        info = next((self.root / 'target/staged').glob('*/build-info.txt')).read_text()
        self.assertIn('fast_path=0\non_origin_master=true', info)

    def test_dirty_and_missing_probe_refuse_before_checks_or_build(self):
        for env in ({'DIRTY': '1'}, {'PROBE': ''}):
            with self.subTest(env=env):
                result = self.release('--fast', **env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.calls(), '')

    def test_failed_fast_check_refuses_before_build(self):
        result = self.release('--fast', CHECK_RC='1')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls(), 'fast-check\n')

    def test_fast_refuses_missing_runtime_and_wrong_identifier(self):
        for env, reason in (({'RUNTIME': 'none'}, 'without the hardened runtime'),
                            ({'IDENTIFIER': 'wrong'}, 'wrong signing identifier')):
            with self.subTest(env=env):
                result = self.release('--fast', **env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(reason, result.stdout)


if __name__ == '__main__':
    unittest.main()
