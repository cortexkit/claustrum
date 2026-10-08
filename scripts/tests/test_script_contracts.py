#!/usr/bin/env python3
"""Hermetic regression controls for shell diagnostics and release policy.

External commands run through scratch executables; no live vault or forge is changed.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
from typing import Any, cast
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def text(name):
    return (ROOT / name).read_text()


def shell_function(path, name):
    source = text(path)
    start = source.index(name + '() {')
    end = source.index('\n}', start) + 2
    return source[start:end]


class ScriptContracts(unittest.TestCase):
    def test_ckdev_matcher_has_statement_local_controls(self):
        guard = module('check-ckdev-execution')
        rust = '''
        let wrapped = Command::new(ckdev_binary(Path::new(env!("CARGO_BIN_EXE_ck-auth")), &root));
        let direct = Command::new(env!("CARGO_BIN_EXE_ck-auth"));
        let safe = ckdev_binary(Path::new("target/debug/ck-claustrum"), &root);
        let wrapped_alias = Command::new(&safe);
        let direct_alias = "target/debug/ck-claustrum";
        Command::new(direct_alias);
        // Command::new("ck-auth");
        let fixture = r#"Command::new("ck-auth")"#;
        Command::new("curl");
        '''
        self.assertEqual(guard.code_violations(rust), [
            'Command::new(env!("CARGO_BIN_EXE_ck-auth"))',
            'Command::new(direct_alias)',
        ], 'direct spawn immediately after a wrapped spawn must be refused')
        ts = 'Bun.spawn([ckdev_binary(binary, scratch)]);\nBun.spawn(["target/release/ck-auth", "--version"]);'
        self.assertEqual(guard.code_violations(ts, True), ['spawn("target/release/ck-auth")'])
        shell = '''
        smoke_binary="$(ckdev_binary "$STAGE/$bin" "$scratch")"
        "$smoke_binary" --version
        "$STAGE/$bin" --version
        DEPLOYED_BIN="${HOME}/.local/share/cortexkit/bin/ck-auth"
        "$DEPLOYED_BIN" --version
        codesign -dv "$STAGE/$bin"
        for b in ck-auth ck-claustrum; do
          "$b" --version
        done
        '''
        self.assertEqual(guard.shell_violations(shell), ['$STAGE/$bin', '$b'])
        self.assertEqual(guard.python_violations('subprocess.run(["/tmp/ck-auth", "--version"])'),
                         ["subprocess.run(['/tmp/ck-auth', '--version'])"])
        self.assertEqual(len(guard.python_violations('binary = Path("/tmp") / "ck-auth"\nsubprocess.run([binary])')), 1)
        self.assertEqual(guard.code_violations('fn one() { let bin = ckdev_binary(src, root); Command::new(bin); } fn two(bin: &Path) { Command::new(bin); }'), ['Command::new(bin)'])
        self.assertEqual(guard.code_violations('let reason = "long message\\\n next line";\nCommand::new(env!("CARGO_BIN_EXE_ck-auth"));'), ['Command::new(env!("CARGO_BIN_EXE_ck-auth"))'])
        self.assertEqual(guard.code_violations("fn launch(binary: &'static str) { Command::new(binary); }"), ['Command::new(binary)'])
        self.assertEqual(guard.code_violations('Command::new(env!("CUSTOM_BINARY"));'), ['Command::new(env!("CUSTOM_BINARY"))'])
        self.assertEqual(guard.violations(Path('ci.yml'), 'run: target/debug/ck-auth --version'), ['target/debug/ck-auth'])
        self.assertEqual(guard.shell_violations('fake="$(echo ckdev_binary /tmp/ck-auth)"\n"$fake" --version'), ['$fake'])

    def test_ckdev_shared_command_has_argument_local_controls(self):
        guard = module('check-ckdev-execution')
        rust = '''
        use cortexkit_test_support::{ckdev_binary, dev_command};
        dev_command(ckdev_binary(src));
        cortexkit_test_support::dev_command(cortexkit_test_support::ckdev_binary(src));
        let staged = ckdev_binary(src);
        dev_command(&staged);
        dev_command(env!("CARGO_BIN_EXE_ck-auth"));
        cortexkit_test_support::dev_command("target/debug/ck-claustrum");
        let raw = "target/debug/ck-auth";
        dev_command(raw);
        dev_command(ckdev_binary(src)); dev_command(src);
        '''
        self.assertEqual(guard.code_violations(rust), [
            'dev_command(env!("CARGO_BIN_EXE_ck-auth"))',
            'dev_command("target/debug/ck-claustrum")',
            'dev_command(raw)',
            'dev_command(src)',
        ])

    def test_process_measurement_recognizes_only_production_directories(self):
        measure = module('measure-ckdev-processes')
        home = Path.home()
        self.assertFalse(measure.forbidden(os.fspath(home / '.local/share/cortexkit/bin/ck-auth')))
        self.assertFalse(measure.forbidden(os.fspath(home / '.local/share/cortexkit/staging/rev/ck-auth')))
        self.assertFalse(measure.forbidden('/tmp/ckdev-auth'))
        self.assertTrue(measure.forbidden('/tmp/ck-auth'))
        self.assertTrue(measure.forbidden('/repo/target/staged/rev/ck-auth'))

    def test_repo_ckdev_execution_fence(self):
        guard = module('check-ckdev-execution')
        paths, bad = guard.scan(ROOT)
        self.assertGreater(len(paths), 50, 'source population must not disappear')
        self.assertEqual(bad, [], 'development execution bypasses ckdev helper')

    def test_ckdev_shell_helper_copies_and_never_links(self):
        artifact = self.root / 'ck-auth'
        artifact.write_text('artifact bytes')
        artifact.chmod(0o755)
        # A hard link would succeed here, so a helper that still links fails the
        # inode check below rather than slipping through a copy fallback.
        result = self.run_shell('source scripts/lib/ckdev-binary.sh; ckdev_binary "$HOME/ck-auth" "$HOME"')
        self.assertEqual(result.returncode, 0, result.stdout)
        copy = Path(result.stdout.strip())
        self.assertEqual(copy.name, 'ckdev-auth')
        self.assertNotEqual(copy.stat().st_ino, artifact.stat().st_ino)
        self.assertEqual(copy.read_bytes(), artifact.read_bytes())
        self.assertTrue(os.access(copy, os.X_OK), 'the copy must stay executable')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, HOME=os.fspath(self.root), REPO='scratch/repo',
                        PATH=os.fspath(self.bin) + ':' + os.environ['PATH'], OPERATOR_GH_FALLBACK_PATHS='')

    def executable(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o700)
        return path

    def run_shell(self, source, env=None, cwd=None, timeout=10):
        return subprocess.run(['bash', '-c', 'set -euo pipefail\n' + source],
                              env=env or self.env, cwd=cwd or ROOT, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)

    def test_skip_notice_survives_large_output(self):
        source = shell_function('scripts/gate.sh', 'run_expect')
        large = self.root / 'large'
        large.write_text('SKIPPING arm\n' + 'x' * (2 * 1024 * 1024) + '\ntest result: ok. 1 passed\n')
        result = self.run_shell('fail() { echo "$1"; exit 1; }\n' + source + '\nrun_expect 1 probe cat ' + repr(os.fspath(large)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('skipped an arm', result.stdout)

    def ratchet(self, ours, target):
        floor = self.root / 'gate.sh'
        floor.write_text(ours)
        self.executable('git', 'if [ "$1" = show ]; then cat "$TARGET_FILE"; else echo abc1234; fi')
        target_file = self.root / 'target'
        target_file.write_text(target)
        env = dict(self.env, TARGET_FILE=os.fspath(target_file))
        return self.run_shell('fail() { echo "$1"; exit 1; }\n' + shell_function('scripts/gate.sh', 'assert_floor_not_lowered') + '\nassert_floor_not_lowered ' + repr(os.fspath(floor)), env)

    def test_missing_local_floor_has_diagnostic(self):
        result = self.ratchet('', 'run_expect 1 "workspace"\n')
        self.assertIn('cannot read this tree', result.stdout)
        self.assertEqual(result.returncode, 1)

    def test_missing_target_floor_is_unchecked(self):
        result = self.ratchet('run_expect 1 "workspace"\n', '')
        self.assertEqual(result.returncode, 0)
        self.assertIn('UNCHECKED', result.stdout)

    def test_large_target_floor_survives_pipefail(self):
        result = self.ratchet('run_expect 2 "workspace"\n', 'run_expect 1 "workspace"\n' + '# filler\n' * 300000)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('workspace floor 2 >=', result.stdout)

    def test_gate_resolves_relative_script_before_chdir(self):
        source = text('scripts/gate.sh')
        prefix = source[:source.index('BUN=')]
        probe = self.root / 'checkout' / 'scripts'
        probe.mkdir(parents=True)
        (probe / 'gate.sh').write_text(prefix + '\nfile="${SCRIPT_PATH:-$0}"\n[ -f "$file" ]\n')
        result = subprocess.run(['bash', './gate.sh'], cwd=probe, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('"$0")', source[source.index('BUN='):])
        self.assertNotIn('"$0"', source[source.index('BUN='):])

    def ladder(self, mode, staged=False):
        deployed = self.root / '.local/share/cortexkit/bin'
        deployed.mkdir(parents=True)
        body = 'case "$1" in\n--version) echo "binary (abc1234)";;\nstatus) echo "vault: ok";;\nmint-handle) exit 1;;\nesac\n'
        for name in ('ck-auth', 'ck-claustrum'):
            path = deployed / name
            path.write_text('#!/bin/bash\n' + body)
            path.chmod(0o700)
        if mode == 'killed':
            (deployed / 'ck-auth').write_text('#!/bin/bash\nkill -9 $$\n')
        elif mode == 'missing':
            (deployed / 'ck-auth').unlink()
        elif mode == 'degraded':
            (deployed / 'ck-auth').write_text('#!/bin/bash\ncase "$1" in --version) echo "binary (abc1234)";; status) echo "vault: degraded"; exit 1;; *) exit 1;; esac\n')
        self.executable('codesign', 'exit 1' if mode == 'unsigned' else 'echo "Identifier=$(basename "${@: -1}")" >&2')
        self.executable('pgrep', 'printf "12\\n13\\n"' if mode == 'multiple' else 'exit 1')
        args = ['bash', os.fspath(ROOT / 'scripts/accept-deploy.sh'), 'abc1234']
        if staged:
            stage = self.root / 'stage'
            stage.mkdir()
            for name in ('ck-auth', 'ck-claustrum'):
                (stage / name).write_text('staged')
            args.append(os.fspath(stage))
        return subprocess.run(args, env=self.env, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)

    def test_killed_binary_diagnostic_is_reachable(self):
        result = self.ladder('killed')
        self.assertIn('KILLED on exec', result.stdout)
        self.assertIn('REFUSED:', result.stdout)

    def test_missing_binary_digest_is_diagnosed(self):
        result = self.ladder('missing', True)
        self.assertIn('digest could not be read', result.stdout)
        self.assertIn('REFUSED:', result.stdout)

    def test_unsigned_binary_diagnostic_is_reachable(self):
        result = self.ladder('unsigned')
        self.assertIn('<unsigned>', result.stdout)
        self.assertIn('REFUSED:', result.stdout)

    def test_degraded_vault_is_diagnosed(self):
        result = self.ladder('degraded')
        self.assertIn('degraded is not automatically', result.stdout)
        self.assertIn('REFUSED:', result.stdout)

    def test_multiple_daemon_pids_are_refused(self):
        result = self.ladder('multiple')
        self.assertIn('multiple ck-claustrum processes', result.stdout)
        self.assertIn('REFUSED:', result.stdout)

    def test_lsof_large_output_is_drained_before_selecting_fields(self):
        self.executable('pgrep', 'echo 12')
        self.executable('lsof', 'echo "cmd 12 user txt REG 1 2 99 /scratch/ck-claustrum"; echo "cmd 12 user cwd REG 1 2 99 $HOME/.local/share/cortexkit/claustrum/store.db"; python3 -c "print(\'x\' * 2097152)"')
        deployed = self.root / '.local/share/cortexkit/bin'
        deployed.mkdir(parents=True)
        for name in ('ck-auth', 'ck-claustrum'):
            binary = deployed / name
            binary.write_text('#!/bin/bash\ncase "$1" in --version) echo "binary (abc1234)";; status) echo "vault: ok";; *) exit 1;; esac\n')
            binary.chmod(0o700)
        self.executable('codesign', 'echo "Identifier=$(basename "${@: -1}")" >&2')
        result = self.run_shell('bash scripts/accept-deploy.sh abc1234')
        self.assertIn('open store is', result.stdout)
        self.assertIn('REFUSED:', result.stdout)

    def test_first_deployment_is_allowed_and_unknown_revision_diagnosed(self):
        source = text('scripts/release-build.sh')
        start = source.index('DEPLOYED_BIN=') if 'DEPLOYED_BIN=' in source else source.index('DEPLOYED_REV=')
        block = source[start:source.index('find target/staged', start)]
        result = self.run_shell(block + '\necho CONTINUED')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('first deployment', result.stdout)
        deployed = self.root / '.local/share/cortexkit/bin'
        deployed.mkdir(parents=True)
        path = deployed / 'ck-auth'
        path.write_text('#!/bin/bash\necho "binary (unknown)"\n')
        path.chmod(0o700)
        result = self.run_shell(block)
        self.assertIn('cannot name its revision', result.stdout)

    def audit_store(self, corrupt=False, other_key=False, quoted=False):
        data = self.root / ("data'quoted" if quoted else 'data')
        payloads = data / 'signed-payloads'
        payloads.mkdir(parents=True)
        store = data / 'store.db'
        if corrupt:
            store.write_text('not sqlite')
        else:
            payload = payloads / 'manifest-v1.json'
            payload.write_text('{"manifest_version":1}')
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            db = sqlite3.connect(store)
            db.execute('CREATE TABLE audit_log (seq INTEGER, ts_ms INTEGER, op TEXT, credential_id TEXT, payload_hash TEXT)')
            key = 'other:key' if other_key else 'signing:gh-manifest-root:1'
            db.execute('INSERT INTO audit_log VALUES (1,0,?,?,?)', ('approval', key, digest))
            if other_key:
                db.execute('INSERT INTO audit_log VALUES (2,0,?,?,?)', ('approval', 'signing:gh-manifest-root:1', 'deadbeef'))
            db.commit()
            db.close()
        return subprocess.run(['bash', 'scripts/audit-signed-payloads.sh', os.fspath(data)], cwd=ROOT, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_unreadable_store_cannot_report_clean(self):
        result = self.audit_store(corrupt=True)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('REFUSING:', result.stdout)
        self.assertNotIn('CLEAN:', result.stdout)

    def test_payload_approval_is_bound_to_credential(self):
        result = self.audit_store(other_key=True)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('NO APPROVAL ROW', result.stdout)

    def test_payload_filename_is_passed_as_data(self):
        result = self.audit_store(quoted=True)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_trigger_probe_survives_transient_gh_failure_and_cleans_branch(self):
        self.executable('gh', 'if [ ! -e "$HOME/seen" ]; then touch "$HOME/seen"; exit 1; fi; echo 123')
        self.executable('git', 'echo "$*" >> "$HOME/git.log"; [ "$1" != commit-tree ] || echo abc1234')
        self.executable('sleep', ':')
        workflow = self.root / 'ci.yml'
        workflow.write_text('name: CI\n')
        source = shell_function('scripts/train-push.sh', 'run_trigger_probe')
        result = self.run_shell('say() { echo "$*"; }; refuse() { echo "$*"; exit 2; }; remote=origin; head_sha=abc1234; tests_workflow_name=ci.yml; tests_workflow=' + repr(os.fspath(workflow)) + '; probe_marker="$HOME/proven"; repo_slug=scratch/repo; OPERATOR_GH=gh; probe_attempts=2; probe_sleep=0\n' + source + '\nrun_trigger_probe')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('--delete train/trigger-probe', (self.root / 'git.log').read_text())
        self.assertTrue((self.root / 'proven').exists())

    def test_watch_bounds_failed_reads(self):
        self.executable('gh', 'exit 1')
        self.executable('sleep', ':')
        result = subprocess.run(['bash', 'scripts/watch-ci.sh', '123'], cwd=ROOT, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('giving up after 5', result.stdout)

    def test_cancelled_run_is_superseded_not_red(self):
        self.executable('gh', 'case "$*" in *"--json status,conclusion,jobs"*) echo "completed|cancelled|";; *"--json status"*) echo completed;; *"--json conclusion"*) echo cancelled;; esac')
        result = subprocess.run(['bash', 'scripts/watch-ci.sh', '123'], cwd=ROOT, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('CI_SUPERSEDED', result.stdout)

    def test_default_workflow_is_ci(self):
        for path in ('scripts/watch-ci.sh', 'scripts/train-push.sh'):
            self.assertIn('${WATCH_CI_WORKFLOW:-ci.yml}', text(path))

    def test_tags_only_and_filtered_push_do_not_promise_every_train(self):
        gates = module('lib/workflow-gates')
        for body in ({'tags': ['v*']}, {'branches': ['train/*']}, {'branches': ['train/**', '!train/blocked/**']}, {'branches-ignore': ['train/**']}, {'paths': ['src/**']}):
            self.assertFalse(gates.push_matches({'on': {'push': body}}, 'train/blocked/commit'), body)
        self.assertTrue(gates.push_matches({'on': {'push': {'branches': ['train/**']}}}, 'train/blocked/commit'))

    def test_threshold_scan_includes_private_and_indented_constants(self):
        controls = module('threshold-controls')
        for source in ('const MAX_ATTEMPTS: usize = 3;', '    pub const MAX_FILES: usize = 3;'):
            self.assertTrue(controls.THRESHOLD_NAME.search(source), source)

    def test_listed_threshold_must_still_exist(self):
        controls = module('threshold-controls')
        controls.ROOT = self.root
        (self.root / 'crates').mkdir()
        (self.root / 'missing.rs').write_text('const DIFFERENT: usize = 1;')
        controls.NAME_RULE_BLIND = {'GONE': 'missing.rs'}
        with self.assertRaises(SystemExit):
            controls.scan_source()

    def test_new_threshold_and_stale_unchecked_row_fail_closed(self):
        controls = module('threshold-controls')
        controls.ROOT = self.root
        crates = self.root / 'crates'
        crates.mkdir()
        source = crates / 'source.rs'
        source.write_text(''.join(f'const MAX_{i}: usize = 1;\n' for i in range(5)))
        controls.NAME_RULE_BLIND = {}
        controls.MANIFEST = self.root / 'manifest'
        controls.MANIFEST.write_text(''.join(f'UNCHECKED MAX_{i} crates/source.rs no exact boundary test yet\n' for i in range(4)))
        self.assertEqual(controls.main(), 1)
        controls.MANIFEST.write_text(controls.MANIFEST.read_text() + 'UNCHECKED MAX_4 crates/source.rs no exact boundary test yet\n')
        self.assertEqual(controls.main(), 0)
        source.write_text(source.read_text().replace('const MAX_4: usize = 1;', ''))
        self.assertEqual(controls.main(), 1)

    def test_inline_and_catalog_url_hosts_are_discovered(self):
        endpoints = module('endpoint-hosts')
        endpoints.ROOT = self.root
        endpoints.SOURCE_DIRS = [self.root]
        (self.root / 'engine_tests.rs').write_text('get("https://fixture.test/token");')
        (self.root / 'kill9_refresh_helper.rs').write_text('get("https://fixture.test/token");')
        (self.root / 'catalog.rs').write_text('fn probe() { get("https://api.example.test/token"); get("https://{host}/token"); }\n#[cfg(test)] mod tests { const URL: &str = "https://fixture.test"; }')
        self.assertEqual(endpoints.discover(), [('catalog.rs', 'INLINE_001', 'api.example.test')])

    def test_release_uses_committed_lock_without_updates(self):
        workflow = text('.github/workflows/release.yml')
        self.assertNotIn('cargo update', workflow)
        self.assertIn('cargo build --locked', workflow)

    def release_step(self, label, path='.github/workflows/release.yml'):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / path))
        for job in workflow['jobs'].values():
            for step in job.get('steps', []):
                if step.get('name') == label:
                    # Preserve Python heredoc indentation; the workflow summary parser
                    # flattens block scalars and is not an execution-source parser.
                    lines = text(path).splitlines()
                    index = lines.index('      - name: ' + label)
                    while lines[index] != '        run: |':
                        index += 1
                    index += 1
                    body = []
                    while index < len(lines) and (lines[index].startswith('          ') or not lines[index]):
                        body.append(lines[index][10:])
                        index += 1
                    step['run'] = '\n'.join(body) + '\n'
                    return step
        self.fail('missing release step: ' + label)

    def test_published_release_requires_explicit_replacement(self):
        self.executable('gh', 'case "$*" in *--json*isDraft*) echo false;; *) exit 0;; esac')
        step = self.release_step('Create the release if it does not exist')
        env = dict(self.env, TAG='v1', GITHUB_REPOSITORY='scratch/repo', REPLACE_PUBLISHED='false', RELEASE_NOTES='')
        result = self.run_shell(step['run'], env, cwd=self.root)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('is published', result.stdout)
        env['REPLACE_PUBLISHED'] = 'true'
        self.assertEqual(self.run_shell(step['run'], env, cwd=self.root).returncode, 0)

    def test_release_asset_gate_requires_expected_names(self):
        self.executable('gh', 'case "$*" in *--json*) printf "junk\\n%.0s" {1..12};; *) exit 0;; esac')
        step = self.release_step('Undraft the release')
        result = self.run_shell(step['run'], dict(self.env, TAG='v1', GITHUB_REPOSITORY='scratch/repo'), cwd=self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn('missing ck-auth-darwin-arm64.zip', result.stdout)

    def test_release_notes_are_not_tied_to_one_migration(self):
        source = text('.github/workflows/release.yml')
        self.assertNotIn('CARRIES STORE MIGRATION 9', source)
        self.assertIn('RELEASE_NOTES: ${{ inputs.notes }}', source)
        self.assertNotIn('v0.1.2 does not carry this floor', source)
        self.executable('gh', 'case "$*" in *"release view"*) exit 1;; *"release create"*) while [ "$#" -gt 0 ]; do case "$1" in --notes-file) cp "$2" "$HOME/captured-notes"; exit $?;; --notes) printf "%s\\n" "$2" > "$HOME/captured-notes"; exit 0;; esac; shift; done; exit 1;; *) exit 1;; esac')
        step = self.release_step('Create the release if it does not exist')
        permanent = ('SHA-256', 'sidecar', 'ad-hoc signed, not notarized', 'quarantine',
                     'Gatekeeper', 'curl', 'does not self-initialize', 'ck auth bootstrap',
                     'On Linux and Windows', '--key-path', 'CK_MASTER_KEY_PATH',
                     'REQUIRES subc 0.17.20 OR NEWER', 'malformed HELLO body: missing field `consumes`',
                     'three restarts')
        for extra in ('', 'Release-specific migration instructions.'):
            env = dict(self.env, TAG='v1', GITHUB_REPOSITORY='scratch/repo', REPLACE_PUBLISHED='false', RELEASE_NOTES=extra)
            result = self.run_shell(step['run'], env, cwd=self.root)
            self.assertEqual(result.returncode, 0, result.stdout)
            notes = (self.root / 'captured-notes').read_text()
            for phrase in permanent:
                self.assertIn(phrase, notes)
            if extra:
                self.assertTrue(notes.endswith(extra + '\n'), notes)

    def test_workflow_inputs_are_data_not_shell_source(self):
        gates = module('lib/workflow-gates')
        for path in ('.github/workflows/release.yml', '.github/workflows/publish-client.yml'):
            workflow = gates.parse_workflow(os.fspath(ROOT / path))
            for job in workflow['jobs'].values():
                for step in job.get('steps', []):
                    self.assertNotRegex(step.get('run', ''), r'\$\{\{\s*(?:inputs\.|github\.ref_name)')

    def test_npm_publish_is_master_only_and_bun_matches_ci(self):
        # A failing step, not a job `if`: a skipped job reads as green.
        step = self.release_step('Refuse to publish from anything but master', '.github/workflows/publish-client.yml')
        refused = self.run_shell(step['run'], dict(self.env, REF='refs/heads/feature'))
        self.assertEqual(refused.returncode, 1, refused.stdout)
        self.assertIn('REFUSING', refused.stdout)
        self.assertEqual(self.run_shell(step['run'], dict(self.env, REF='refs/heads/master')).returncode, 0)
        self.assertIn('bun-version: 1.3.14', text('.github/workflows/publish-client.yml'))

    def test_ci_clippy_covers_every_gate_seam(self):
        gate = text('scripts/gate.sh')
        ci = text('.github/workflows/ci.yml')
        gate_flags = re.search(r'--features (credentials-core/test-support,kill9[^\s]+)', gate).group(1).split(',')[1:]
        ci_flags = re.search(r'cargo clippy.*--features ([^\s]+)', ci).group(1).split(',')
        self.assertEqual(set(gate_flags), set(ci_flags))

    def test_release_tokens_are_scoped_and_build_is_registry_only(self):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/release.yml'))
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        ci = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/ci.yml'))
        self.assertEqual(ci['permissions'], {'contents': 'read'})
        steps = [step for job in workflow['jobs'].values() for step in job['steps']]
        repositories = [step.get('with', {}).get('repository') for step in steps]
        self.assertNotIn('cortexkit/subconscious', repositories)
        self.assertNotIn('cortexkit/commons', repositories)
        self.assertFalse(any('sibling' in step.get('name', '').lower() for step in steps))
        names = '\n'.join(f'{binary}-{platform}.{suffix}' for platform in ('darwin-arm64', 'linux-x64', 'windows-x64') for binary in ('ck-auth', 'ck-claustrum') for suffix in ('zip', 'zip.sha256'))
        self.executable('gh', 'case "$*" in *"--json assets"*) printf "%s\\n" "$ASSET_NAMES";; *"--json body"*) echo "Permanent notes plus release-specific instructions.";; *"release edit"*) cp release-notes.txt "$HOME/captured-notes";; *) exit 1;; esac')
        publish = self.release_step('Undraft the release')
        result = self.run_shell(publish['run'], dict(self.env, TAG='v1', GITHUB_REPOSITORY='scratch/repo', ASSET_NAMES=names), cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout)
        notes = (self.root / 'captured-notes').read_text()
        self.assertIn('Permanent notes plus release-specific instructions.', notes)

    def test_fixture_prefix_needs_path_boundary(self):
        fixtures = module('check-fixture-line-endings')
        self.assertFalse(fixtures.is_covered('a/fixtures_v2', ['a/fixtures/**']))
        for path, patterns, wanted in fixtures.MATCHER_CONTROL:
            self.assertEqual(fixtures.is_covered(path, list(patterns)), wanted)

    def test_typescript_exclusions_are_checkout_relative(self):
        paths = module('check-path-rendering')
        paths.ROOT = self.root / 'tests' / 'checkout'
        self.assertFalse(paths.is_test_typescript(paths.ROOT / 'packages/src/index.ts'))
        self.assertTrue(paths.is_test_typescript(paths.ROOT / 'packages/tests/index.ts'))
        self.assertIn('SCRIPTS.rglob("*.py")', text('scripts/check-path-rendering.py'))

    def test_inbound_missing_key_has_diagnostic(self):
        source = text('scripts/check-inbound-contracts.sh')
        line = next(line for line in source.splitlines() if line.startswith('theirs_mutable='))
        spec = self.root / 'spec'
        spec.write_text('no key')
        result = self.run_shell('spec=' + repr(os.fspath(spec)) + '\n' + line + '\necho "could not read: $theirs_mutable"')
        self.assertEqual(result.returncode, 0)
        self.assertIn('could not read:', result.stdout)

    def test_doc_status_checks_all_markers_and_identifier_boundaries(self):
        docs = module('check-doc-status')
        docs.DOCS = self.root / 'docs'
        docs.DOCS.mkdir()
        (self.root / 'source.rs').write_text('fn longer_symbol_suffix() {}\nfn shipped() {}')
        doc = docs.DOCS / 'design.md'
        # Markers name repo-relative paths, resolved from the working directory, exactly
        # as real docs do. An absolute path would carry a drive colon on Windows, which
        # the marker grammar (`path::symbol`) cannot hold, and this control also runs
        # there as the doc-status scan's planted violation.
        previous = os.getcwd()
        os.chdir(self.root)
        try:
            doc.write_text('**Status: NOT BUILT**\n<!-- built-when: source.rs::symbol -->\n')
            self.assertEqual(docs.main(), 0)
            doc.write_text(doc.read_text() + '<!-- built-when: source.rs::shipped -->\n')
            self.assertEqual(docs.main(), 1)
        finally:
            os.chdir(previous)

    def test_non_utf8_doc_is_readable(self):
        docs = module('check-doc-status')
        docs.DOCS = self.root / 'docs'
        docs.DOCS.mkdir()
        (docs.DOCS / 'design.md').write_bytes(b'**Status: SHIPPED**\n\xff')
        self.assertEqual(docs.main(), 0)

    def test_custody_scratch_is_removed_on_early_refusal(self):
        self.executable('opencode', 'echo wrong-version')
        self.executable('mktemp', 'mkdir "$HOME/scratch"; echo "$HOME/scratch"')
        source = text('scripts/accept-opencode-custody.sh')
        source = source[:source.index('cargo build')]
        env = dict(self.env, WT=os.fspath(ROOT), TMPDIR=os.fspath(self.root))
        result = self.run_shell(source, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['bin'])

    def test_custody_model_match_drains_large_output(self):
        source = text('scripts/accept-opencode-custody.sh')
        start = source.index('models=') if 'models=' in source else source.index('MODEL_ID=')
        block = source[start:source.index('if [[ -z "$MODEL_ID"', start)]
        self.executable('opencode', 'echo synthetic/hf:moonshotai/Kimi-K3; python3 -c "print(\'x\' * 2097152)"')
        # The defect this guards is a hang (a reader that stops draining leaves the writer
        # blocked forever), so the timeout only has to end a hang, not measure speed. The
        # default 10s failed under a loaded gate with the pipeline still making progress.
        result = self.run_shell(block + '\necho "$MODEL_ID"', timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('synthetic/hf:moonshotai/Kimi-K3', result.stdout)

    def test_windows_skip_is_in_unchecked_verdict(self):
        source = text('scripts/gate.sh')
        start = source.index('if rustup target list')
        block = source[start:source.index('\nfi', start) + 3]
        self.executable('rustup', 'echo aarch64-apple-darwin')
        summary = source[source.rindex('if [ -n "${GATE_UNCHECKED:-}" ]'):]
        result = self.run_shell(block + '\n' + summary)
        self.assertIn('GATE PASSED WITH UNCHECKED ARMS -- windows cross type-check', result.stdout.splitlines()[-1])
        self.assertRegex(source, r"else\s+printf '\\nGATE PASSED --")

    def test_probe_is_required_before_build_work(self):
        source = text('scripts/release-build.sh')
        self.assertLess(source.index('if [ -z "${PROBE:-}" ]'), source.index('ckdev-mutate check'))

    def test_endpoint_host_and_separator_drift_are_refused(self):
        endpoints = cast(Any, module('endpoint-hosts'))
        endpoints.ROOT = self.root
        endpoints.SOURCE_DIRS = [self.root]
        endpoints.MANIFEST = self.root / 'hosts'
        endpoints.DOMAIN_MANIFEST = self.root / 'domains'
        source = self.root / 'adapter.rs'
        source.write_text('const TOKEN_URL: &str = "https://provider.example/token";\n'
                          'const DOMAIN: &[u8] = b"cortexkit-credentials/control/v1";\n')
        endpoints.MANIFEST.write_text(endpoints.render(endpoints.discover()))
        endpoints.DOMAIN_MANIFEST.write_text(endpoints.render_domains(endpoints.discover_domains()))
        self.assertEqual(endpoints.main(), 0)
        source.write_text(source.read_text().replace('provider.example', 'attacker.example'))
        self.assertEqual(endpoints.main(), 1)
        source.write_text(source.read_text().replace('attacker.example', 'provider.example')
                          .replace('cortexkit-credentials/control/v1', 'cortexkit-credentials/control/v2'))
        self.assertEqual(endpoints.main(), 1)

    def test_uncovered_fixture_directory_is_refused(self):
        from unittest.mock import patch
        fixtures = module('check-fixture-line-endings')
        (self.root / 'a' / 'fixtures').mkdir(parents=True)
        attributes = self.root / '.gitattributes'
        attributes.write_text('a/fixtures/** -text\n')
        with patch.object(fixtures.subprocess, 'run', return_value=type('Result', (), {'stdout': os.fspath(self.root)})()):
            self.assertEqual(fixtures.main(), 0)
            (self.root / 'b' / 'fixtures').mkdir(parents=True)
            self.assertEqual(fixtures.main(), 1)

    def test_path_scan_refuses_planted_platform_rendering(self):
        paths = cast(Any, module('check-path-rendering'))
        paths.ROOT = self.root
        paths.SCRIPTS = self.root / 'scripts'
        paths.SCRIPTS.mkdir()
        source = paths.SCRIPTS / 'probe.py'
        source.write_text('rel = path.relative_to(root).as_posix()\n')
        (self.root / 'packages' / 'tests').mkdir(parents=True)
        (self.root / 'packages' / 'tests' / 'control.ts').write_text('')
        paths.TYPESCRIPT_GLOBS = ['packages/**/*.ts']
        paths.MUTATION_CONTROL = self.root / 'packages' / 'tests' / 'control.ts'
        self.assertEqual(paths.main(), 0)
        source.write_text('rel = str(path.relative_to(root))\n')
        self.assertEqual(paths.main(), 1)

    def test_inbound_mismatch_is_refused(self):
        block = shell_function('scripts/check-inbound-contracts.sh', 'compare')
        result = self.run_shell('source_file=fixture; fail=0;\n' + block +
                                '\ncompare control wrong expected\n[ "$fail" = 1 ]')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('MISMATCH in control', result.stdout)

    def test_scan_self_control_must_execute_not_skip(self):
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        from unittest.mock import patch
        control = module('lib/scan_self_test')
        for stderr, expected in [('Ran 1 test\nOK\n', 0),
                                 ('Ran 1 test\nOK (skipped=1)\n', 2),
                                 ('Ran 0 tests\nOK\n', 2)]:
            result = subprocess.CompletedProcess([], 0, stdout='', stderr=stderr)
            with patch.object(control.subprocess, 'run', return_value=result), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(control.check('fixture'), expected)

    def test_stub_startup_budget_exceeds_cold_start(self):
        source = text('scripts/spikes/opencode-config-fetch.sh')
        tries = int(re.search(r'for _ in \{1\.\.(\d+)\}', source).group(1))
        self.assertGreaterEqual(tries * 0.01, 10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
