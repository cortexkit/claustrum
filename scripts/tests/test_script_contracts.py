#!/usr/bin/env python3
"""Hermetic regression controls for shell diagnostics and release policy.

External commands run through scratch executables; no live vault or forge is changed.
"""
import hashlib
import importlib.util
import json
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
RELEASE_RUNNERS = {
    'darwin-arm64': 'macos-latest',
    'linux-x64': 'ubuntu-latest',
    'linux-arm64': 'ubuntu-24.04-arm',
    'windows-x64': 'windows-latest',
    'windows-arm64': 'windows-11-arm',
}


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def text(name):
    return (ROOT / name).read_text()


def workspace_core_version():
    match = re.search(
        r'(?ms)^\[workspace\.metadata\.release\]\s*requires_core\s*=\s*"([^"]+)"',
        text('Cargo.toml'),
    )
    if match is None:
        raise AssertionError('Cargo.toml is missing workspace.metadata.release.requires_core')
    return match.group(1)


def shell_function(path, name):
    source = text(path)
    start = source.index(name + '() {')
    end = source.index('\n}', start) + 2
    return source[start:end]


# watch-ci.sh with a stub gh and a no-op sleep finishes in well under a second; this
# bound only stops a hung watcher from stalling the suite. It once was 3 s, and that
# failed under a load average above 140, where starting bash alone can take seconds.
# Tests assert the outcome, never how fast it arrived.
WATCH_HANG_GUARD_SECONDS = 120


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
                        PATH=os.fspath(self.bin) + ':' + os.environ['PATH'], OPERATOR_GH_FALLBACK_PATHS='',
                        REQUIRES_CORE=workspace_core_version())

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
        source = 'record_arm() { :; }\n' + shell_function('scripts/gate.sh', 'run_expect')
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

    def audit_store(self, corrupt=False, other_key=False, quoted=False, stored_manifest=False, missing_payload=False, broken_manifests=False):
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
            if stored_manifest:
                db.execute('CREATE TABLE gh_manifests (version INTEGER PRIMARY KEY, manifest_bytes BLOB, manifest_sha256 TEXT)')
                db.execute('INSERT INTO gh_manifests VALUES (1,?,?)', (payload.read_bytes(), digest))
            if broken_manifests:
                db.execute('CREATE TABLE gh_manifests (wrong_column TEXT)')
            db.commit()
            db.close()
            if missing_payload:
                payload.unlink()
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

    def test_payload_retained_in_manifest_row_needs_no_file(self):
        result = self.audit_store(stored_manifest=True, missing_payload=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('gh_manifests version 1', result.stdout)
        self.assertNotIn('BYTES NOT RETAINED', result.stdout)

    def test_payload_missing_from_legacy_store_is_still_a_finding(self):
        result = self.audit_store(missing_payload=True)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('BYTES NOT RETAINED', result.stdout)

    def test_payload_unmatched_approval_is_not_hidden_by_manifest_table(self):
        result = self.audit_store(stored_manifest=True, other_key=True, missing_payload=True)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('BYTES NOT RETAINED', result.stdout)
        self.assertNotIn('gh_manifests version 1', result.stdout)

    def test_payload_unreadable_manifest_rows_cannot_report_clean(self):
        result = self.audit_store(broken_manifests=True)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('REFUSING:', result.stdout)
        self.assertNotIn('CLEAN:', result.stdout)

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
        result = subprocess.run(['bash', 'scripts/watch-ci.sh', '123'], cwd=ROOT, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=WATCH_HANG_GUARD_SECONDS)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('giving up after 5', result.stdout)

    def test_cancelled_run_is_superseded_not_red(self):
        self.executable('gh', 'case "$*" in *"--json status,conclusion,jobs"*) echo "completed|cancelled|";; *"--json status"*) echo completed;; *"--json conclusion"*) echo cancelled;; esac')
        result = subprocess.run(['bash', 'scripts/watch-ci.sh', '123'], cwd=ROOT, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=WATCH_HANG_GUARD_SECONDS)
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

    def test_endpoint_scans_cover_split_crates_and_allow_absent_roots(self):
        endpoints = cast(Any, module('endpoint-hosts'))
        endpoints.SOURCE_DIRS = [self.root / path.relative_to(endpoints.ROOT)
                                 for path in endpoints.SOURCE_DIRS]
        endpoints.ROOT = self.root
        hosts = []
        domains = []
        for crates in [('credentials-core', 'credentials-module'),
                       ('claustrum-model', 'claustrum-providers')]:
            for crate in crates:
                relative = f'crates/{crate}/src/probe.rs'
                source = self.root / relative
                source.parent.mkdir(parents=True)
                domain = f'cortexkit-{crate}/scan/v1'
                source.write_text('const URL: &str = "https://api.example.test/token";\n'
                                  f'const DOMAIN: &[u8] = b"{domain}";\n')
                hosts.append((relative, 'URL', 'api.example.test'))
                domains.append((relative, domain, domain))
            with self.subTest(crates=crates):
                self.assertEqual(endpoints.discover(), sorted(hosts))
                self.assertEqual(endpoints.discover_domains(), sorted(domains))

    def test_endpoint_scan_excludes_standalone_oauth_import_tests(self):
        endpoints = cast(Any, module('endpoint-hosts'))
        endpoints.ROOT = self.root
        endpoints.SOURCE_DIRS = [self.root]
        (self.root / 'oauth_import_tests.rs').write_text('get("https://fixture.test/token");')
        (self.root / 'adapter.rs').write_text('get("https://api.example.test/token");')
        self.assertEqual(endpoints.discover(), [('adapter.rs', 'INLINE_001', 'api.example.test')])

    def test_fast_check_selects_core_with_each_split_crate(self):
        from unittest.mock import patch
        fast = module('fast-check')
        names = ['claustrum-model', 'claustrum-providers', 'credentials-core',
                 'credentials-module', 'cortexkit-claustrum-client']
        packages = [dict(id=name, name=name,
                         manifest_path=str(self.root / 'crates' / name / 'Cargo.toml'))
                    for name in names]
        metadata = dict(packages=packages, workspace_members=names)
        for leaf in ('claustrum-model', 'claustrum-providers'):
            for filename in ('Cargo.toml', 'src/lib.rs'):
                for untracked in (False, True):
                    path = f'crates/{leaf}/{filename}'
                    outputs = ['', path + '\0'] if untracked else [path + '\0', '']
                    with self.subTest(path=path, untracked=untracked), \
                            patch.object(fast, 'ROOT', self.root), \
                            patch.object(fast, 'output', side_effect=outputs):
                        crates, paths, members = fast.scope('base', metadata)
                        self.assertEqual(crates, [leaf, 'credentials-core'])
                        self.assertEqual(paths, {path})
                        self.assertEqual(members, packages)
        with patch.object(fast, 'ROOT', self.root), \
                patch.object(fast, 'output', side_effect=['Cargo.lock\0', '']):
            self.assertEqual(fast.scope('base', metadata)[0], sorted(names))

    def test_release_uses_committed_lock_without_updates(self):
        workflow = text('.github/workflows/release.yml')
        self.assertNotIn('cargo update', workflow)
        self.assertIn('cargo build --locked', workflow)

    def test_release_assets_use_only_the_ancestry_checked_commit(self):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/release.yml'))
        prepare = workflow['jobs']['prepare']
        self.assertEqual(prepare.get('outputs', {}).get('checked_sha'), '${{ steps.checked.outputs.sha }}')
        checked = self.release_step('Refuse a commit that is not on master')
        self.assertEqual(checked['id'], 'checked')
        self.assertNotIn('if', checked)
        checkout = next(step for step in prepare['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], '${{ inputs.rehearse && github.sha || inputs.tag || github.ref }}')
        self.assertIn('git merge-base --is-ancestor "$checked_sha" origin/master', checked['run'])
        self.assertIn('echo "sha=$checked_sha" >> "$GITHUB_OUTPUT"', checked['run'])
        self.assertLess(checked['run'].index('exit 1'), checked['run'].index('echo "sha=$checked_sha"'))

        assets = workflow['jobs']['assets']
        self.assertEqual(assets['needs'], 'prepare')
        checkouts = [step for step in assets['steps'] if step.get('uses', '').startswith('actions/checkout@')]
        self.assertTrue(checkouts)
        for checkout in checkouts:
            self.assertEqual(checkout['with']['ref'], '${{ needs.prepare.outputs.checked_sha }}')
        revision = self.release_step('Resolve the built revision')
        self.assertEqual(revision['env']['CHECKED_SHA'], '${{ needs.prepare.outputs.checked_sha }}')
        self.assertLess(assets['steps'].index(next(step for step in assets['steps'] if step.get('id') == 'rev')),
                        next(index for index, step in enumerate(assets['steps']) if 'cargo build' in step.get('run', '')))

    def test_release_runs_serialize_by_resolved_tag_without_cancellation(self):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/release.yml'))
        concurrency = workflow.get('concurrency', {})
        self.assertEqual(concurrency.get('group'), 'release-${{ inputs.tag || github.ref_name }}')
        self.assertEqual(concurrency.get('cancel-in-progress'), 'false')

    def release_matrix(self):
        step = self.release_step('Define release platforms')
        output = self.root / 'matrix-output'
        output.write_text('')
        result = self.run_shell(step['run'], dict(self.env, GITHUB_OUTPUT=os.fspath(output)))
        self.assertEqual(result.returncode, 0, result.stdout)
        key, matrix = output.read_text().strip().split('=', 1)
        self.assertEqual(key, 'matrix')
        return matrix

    def test_release_matrix_matches_installer_platforms(self):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/release.yml'))
        jobs = workflow['jobs']
        entries = json.loads(self.release_matrix())['include']
        self.assertEqual(len(entries), len(RELEASE_RUNNERS))
        self.assertEqual({entry['platform']: entry['runner'] for entry in entries}, RELEASE_RUNNERS)
        self.assertEqual({entry['platform']: entry['arm64_host'] for entry in entries if 'arm64_host' in entry}, {
            'linux-arm64': 'aarch64-unknown-linux-gnu',
            'windows-arm64': 'aarch64-pc-windows-msvc',
        })
        self.assertEqual(jobs['prepare']['outputs']['asset_matrix'], '${{ steps.platforms.outputs.matrix }}')
        self.assertEqual(jobs['assets']['strategy']['matrix'], '${{ fromJSON(needs.prepare.outputs.asset_matrix) }}')
        self.assertEqual(jobs['assets']['strategy']['fail-fast'], 'false')
        verify = self.release_step('Verify uploaded asset names and checksums')
        self.assertEqual(verify['env']['ASSET_MATRIX'], '${{ needs.prepare.outputs.asset_matrix }}')

    def test_release_rehearsal_cannot_touch_github_releases(self):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/release.yml'))
        inputs = workflow['on']['workflow_dispatch']['inputs']
        self.assertEqual(inputs['tag']['required'], 'false')
        self.assertEqual(inputs['rehearse']['type'], 'boolean')
        self.assertEqual(inputs['rehearse']['default'], 'false')

        jobs = workflow['jobs']
        real_only = '${{ !inputs.rehearse }}'
        release_steps = [step for job in jobs.values() for step in job['steps']
                         if re.search(r'\bgh\s+release\b', step.get('run', ''))]
        self.assertEqual({step['name'] for step in release_steps}, {
            'Create the release if it does not exist', 'Upload release manifest',
            'Upload to the release', 'Download draft release assets', 'Undraft the release',
        })
        for step in release_steps:
            with self.subTest(step=step['name']):
                self.assertEqual(step['if'], real_only)
        self.assertEqual(jobs['publish']['if'], real_only)
        self.assertEqual(jobs['publish']['needs'], 'verify')
        self.assertEqual(jobs['verify']['needs'], ['prepare', 'assets'])

        steps = {step.get('name'): step for job in jobs.values() for step in job['steps']}
        for name in ('Generate release manifest', 'Resolve the crate version',
                     'Build release binaries', 'Package assets', 'Verify packaged versions and revisions',
                     'Verify uploaded asset names and checksums'):
            self.assertNotIn('if', steps[name], name)
        self.assertEqual(steps['Refuse a tag that disagrees with the crate version']['if'], real_only)
        for name, artifact_name, path in (('Upload rehearsal manifest', 'rehearsal-manifest', 'release-manifest.json'),
                                          ('Upload rehearsal archives', 'rehearsal-${{ matrix.platform }}', 'claustrum/dist/')):
            upload = steps[name]
            self.assertEqual(upload['if'], 'inputs.rehearse')
            self.assertTrue(upload['uses'].startswith('actions/upload-artifact@'))
            self.assertEqual(upload['with']['name'], artifact_name)
            self.assertEqual(upload['with']['path'], path)
            self.assertEqual(upload['with']['if-no-files-found'], 'error')
        download = steps['Download rehearsal artifacts']
        self.assertEqual(download['if'], 'inputs.rehearse')
        self.assertTrue(download['uses'].startswith('actions/download-artifact@'))
        self.assertEqual(download['with'], {'pattern': 'rehearsal-*', 'path': '${{ env.ASSET_DIR }}',
                                            'merge-multiple': 'true'})

    def test_manual_public_release_still_requires_a_tag(self):
        step = self.release_step('Require a tag for a manual release')
        self.assertEqual(step['if'], "github.event_name == 'workflow_dispatch' && !inputs.rehearse")
        self.assertEqual(step['env']['TAG'], '${{ inputs.tag }}')
        missing = self.run_shell(step['run'], dict(self.env, TAG=''))
        self.assertEqual(missing.returncode, 1, missing.stdout)
        self.assertIn('specify an existing tag', missing.stdout)
        present = self.run_shell(step['run'], dict(self.env, TAG='v1'))
        self.assertEqual(present.returncode, 0, present.stdout)

    def test_release_dev_marker_refuses_public_release_but_warns_in_rehearsal(self):
        (self.root / 'crates').mkdir()
        (self.root / 'docs').mkdir()
        marker = self.root / 'crates' / 'development.rs'
        marker.write_text('// remove before the next public release\n')
        step = self.release_step('Refuse development-only code')
        self.assertNotIn('if', step)
        self.assertEqual(step['env']['REHEARSE'], '${{ inputs.rehearse || false }}')
        live = self.run_shell(step['run'], dict(self.env, REHEARSE='false'), cwd=self.root)
        self.assertEqual(live.returncode, 1, live.stdout)
        self.assertIn('REFUSING:', live.stdout)
        rehearsal = self.run_shell(step['run'], dict(self.env, REHEARSE='true'), cwd=self.root)
        self.assertEqual(rehearsal.returncode, 0, rehearsal.stdout)
        self.assertIn('crates/development.rs:1:', rehearsal.stdout)
        self.assertIn('::warning::', rehearsal.stdout)
        marker.unlink()
        # The frozen v1 desktop sample keeps the phrase in its published README.
        frozen = self.root / 'crates' / 'tests' / 'vectors' / 'desktop-dev-approval-vectors-v1'
        frozen.mkdir(parents=True)
        (frozen / 'README.md').write_text('Development only; remove before the next public release.\n')
        clean = self.run_shell(step['run'], dict(self.env, REHEARSE='false'), cwd=self.root)
        self.assertEqual(clean.returncode, 0, clean.stdout)

    def release_verify_env(self, assets):
        return dict(self.env, ASSET_DIR=os.fspath(assets), ASSET_MATRIX=self.release_matrix())

    def uploaded_release(self):
        assets = self.root / 'uploaded'
        assets.mkdir()
        for platform in RELEASE_RUNNERS:
            for binary in ('ck-auth', 'ck-claustrum'):
                name = f'{binary}-{platform}.zip'
                payload = (name + ' uploaded bytes').encode()
                (assets / name).write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                (assets / (name + '.sha256')).write_text(f'{digest}  {name}\n')
        (assets / 'release-manifest.json').write_text(json.dumps({'requires_core': workspace_core_version()}))
        self.executable('gh', '''case "$*" in
          *"--json body"*) echo "Permanent notes plus release-specific instructions.";;
          *"release download"*)
            shift 3
            destination=.; patterns=()
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --dir) destination="$2"; shift 2;;
                --pattern|-p) patterns+=("$2"); shift 2;;
                --repo) shift 2;;
                *) exit 99;;
              esac
            done
            mkdir -p "$destination"
            for pattern in "${patterns[@]}"; do
              cp "$HOME/uploaded/"$pattern "$destination/"
            done;;
          *"release edit"*) cp release-notes.txt "$HOME/captured-notes";;
          *) exit 99;;
        esac''')
        return assets

    def test_release_asset_gate_checks_downloaded_zip_bytes_against_sidecars(self):
        assets = self.uploaded_release()
        step = self.release_step('Verify uploaded asset names and checksums')
        env = self.release_verify_env(assets)
        for archive in sorted(assets.glob('*.zip')):
            with self.subTest(archive=archive.name):
                original = archive.read_bytes()
                archive.write_bytes(original + b'changed after packaging')
                result = self.run_shell(step['run'], env, cwd=self.root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(f'{archive.name}: FAILED', result.stdout)
                archive.write_bytes(original)
        result = self.run_shell(step['run'], env, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_release_asset_gate_rejects_a_sidecar_for_a_different_zip(self):
        assets = self.uploaded_release()
        sidecar = 'ck-auth-linux-arm64.zip.sha256'
        step = self.release_step('Verify uploaded asset names and checksums')
        env = self.release_verify_env(assets)
        path = assets / sidecar
        path.write_bytes(path.read_bytes().replace(b'  ', b' *', 1).replace(b'\n', b'\r\n'))
        valid = self.run_shell(step['run'], env, cwd=self.root)
        self.assertEqual(valid.returncode, 0, valid.stdout)
        path.write_bytes((assets / 'ck-auth-linux-x64.zip.sha256').read_bytes())
        result = self.run_shell(step['run'], env, cwd=self.root)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f'{sidecar} must describe ck-auth-linux-arm64.zip', result.stdout)

    def test_release_asset_gate_rejects_a_wrong_core_floor(self):
        assets = self.uploaded_release()
        step = self.release_step('Verify uploaded asset names and checksums')
        env = self.release_verify_env(assets)
        for body in ('', '{"requires_core":"0.0.0"}'):
            with self.subTest(body=body):
                (assets / 'release-manifest.json').write_text(body)
                result = self.run_shell(step['run'], env, cwd=self.root)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('release-manifest.json does not match the minimum core version', result.stdout)

    def test_release_asset_revision_refuses_a_different_checked_commit(self):
        built_sha = 'a' * 40
        self.executable('git', f'[[ "$*" == "rev-parse HEAD" ]] || exit 1; echo {built_sha}')
        step = self.release_step('Resolve the built revision')
        output = self.root / 'output'
        for checked_sha in (built_sha, 'b' * 40, ''):
            with self.subTest(checked_sha=checked_sha):
                output.write_text('')
                env = dict(self.env, CHECKED_SHA=checked_sha, GITHUB_OUTPUT=os.fspath(output))
                result = self.run_shell(step['run'], env, cwd=self.root)
                if checked_sha == built_sha:
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(output.read_text(), f'sha={built_sha}\n')
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn('REFUSING:', result.stdout)
                    self.assertEqual(output.read_text(), '')

    def test_release_smoke_checks_the_packaged_version_and_revision_without_a_tag(self):
        step = self.release_step('Verify packaged versions and revisions')
        self.assertEqual(step['env']['CRATE_VERSION'], '${{ steps.version.outputs.version }}')
        self.assertEqual(step['env']['BUILT_REV'], '${{ steps.rev.outputs.sha }}')
        library = self.root / 'scripts/lib'
        library.mkdir(parents=True)
        shutil.copyfile(ROOT / 'scripts/lib/ckdev-binary.sh', library / 'ckdev-binary.sh')
        dist = self.root / 'dist'
        dist.mkdir()
        (dist / 'artifact.zip').touch()
        self.executable('unzip', 'cp -p "$HOME/bin/ck-auth" "$HOME/bin/ck-claustrum" .')
        for binary in ('ck-auth', 'ck-claustrum'):
            self.executable(binary, f'''[ "$*" = --version ] || exit 99
printf '%s %s (%s)\\n' '{binary}' "$STUB_VERSION" "$STUB_REV"''')
        sha = 'a' * 40
        env = dict(self.env, RUNNER_OS='Linux', CRATE_VERSION='1.2.3', BUILT_REV=sha)
        for version, revision, refusal in (
                ('1.2.3', sha, None),
                ('1.2.30', sha, 'does not report crate version'),
                ('1.2.3', 'b' * 40, 'reports a revision that is not the checked-out source')):
            with self.subTest(version=version, revision=revision):
                result = self.run_shell(step['run'], dict(env, STUB_VERSION=version, STUB_REV=revision), cwd=self.root)
                if refusal is None:
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertIn('ck-auth ->', result.stdout)
                    self.assertIn('ck-claustrum ->', result.stdout)
                else:
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(refusal, result.stdout)

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
                        if lines[index].startswith('        run: '):
                            step['run'] = lines[index][len('        run: '):] + '\n'
                            return step
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
        assets = self.uploaded_release()
        step = self.release_step('Verify uploaded asset names and checksums')
        env = self.release_verify_env(assets)
        for asset in sorted(assets.iterdir()):
            with self.subTest(asset=asset.name):
                hold = self.root / asset.name
                asset.rename(hold)
                result = self.run_shell(step['run'], env, cwd=self.root)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f'missing {asset.name}', result.stdout)
                hold.rename(asset)

    def test_release_manifest_is_uploaded_from_workspace_core_floor(self):
        version = workspace_core_version()
        resolve = self.release_step('Resolve minimum core version')
        output = self.root / 'core-output'
        result = self.run_shell(resolve['run'], dict(self.env, GITHUB_OUTPUT=os.fspath(output)), cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(output.read_text(), f'requires_core={version}\n')
        self.assertIn('python3 scripts/release-manifest.py', resolve['run'])

        generate = self.release_step('Generate release manifest')
        self.assertEqual(generate['env']['REQUIRES_CORE'], '${{ steps.core.outputs.requires_core }}')
        result = self.run_shell(generate['run'], dict(self.env, REQUIRES_CORE=version), cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout)

        upload = self.release_step('Upload release manifest')
        self.executable('gh', 'printf "%s\\n" "$*" > "$HOME/upload-args"\ncp release-manifest.json "$HOME/uploaded-manifest"')
        env = dict(self.env, TAG='v1', GITHUB_REPOSITORY='scratch/repo', REQUIRES_CORE=version)
        result = self.run_shell(upload['run'], env, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.root / 'uploaded-manifest').read_bytes(),
                         f'{{"requires_core":"{version}"}}\n'.encode())
        self.assertIn('release-manifest.json', (self.root / 'upload-args').read_text())
        self.assertIn('--clobber', (self.root / 'upload-args').read_text())

    def test_release_notes_use_workspace_core_floor(self):
        version = workspace_core_version()
        self.executable('gh', 'case "$*" in *"release view"*) exit 1;; *"release create"*) while [ "$#" -gt 0 ]; do case "$1" in --notes-file) cp "$2" "$HOME/captured-notes"; exit $?;; --notes) printf "%s\\n" "$2" > "$HOME/captured-notes"; exit 0;; esac; shift; done; exit 1;; *) exit 1;; esac')
        step = self.release_step('Create the release if it does not exist')
        env = dict(self.env, TAG='v1', GITHUB_REPOSITORY='scratch/repo', REPLACE_PUBLISHED='false',
                   RELEASE_NOTES='', REQUIRES_CORE=version)
        result = self.run_shell(step['run'], env, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(f'REQUIRES subc-core {version} OR NEWER',
                      (self.root / 'captured-notes').read_text())
        self.assertEqual(step['env']['REQUIRES_CORE'], '${{ steps.core.outputs.requires_core }}')

    def test_acceptance_docs_describe_staged_identity_not_old_build_comparison(self):
        accept = text('docs/operator-runbook.md').split('### Accept\n', 1)[1]
        digest = next(line for line in accept.splitlines() if line.startswith('| ') and 'hash' in line)
        self.assertIn('staged artifact', digest)
        self.assertIn('installed', digest)
        self.assertNotIn('differs from the **old**', digest)
        self.assertIn('no-op deployment', accept)
        self.assertIn('optional staged directory', accept)

    def test_acceptance_docs_describe_healthy_retired_credentials(self):
        accept = text('docs/operator-runbook.md').split('### Accept\n', 1)[1]
        status = next(line for line in accept.splitlines() if line.startswith('| `ck auth status`'))
        self.assertIn('vault: ok', status)
        self.assertIn('retired', status)
        self.assertNotIn('N/N serving', text('scripts/accept-deploy.sh'))

    def test_post_deploy_train_command_supplies_required_name(self):
        post = text('docs/operator-runbook.md').split('After `accept-deploy.sh` and the live probe pass', 1)[1]
        post = post.split('`scripts/gate.sh` is post-deploy', 1)[0]
        self.assertIn('./scripts/train-push.sh <train-name>', post)
        self.assertIn('reuse', post)

    def test_contributor_docs_match_enabled_windows_offline_bun_cache(self):
        document = ' '.join(text('CONTRIBUTING.md').split())
        self.assertIn('Windows Bun install/build/typecheck and package tests run in both GitHub CI and the full gate', document)
        self.assertIn('WINDOWS_MOTOR_HAS_OFFLINE_BUN_CACHE=0', document)
        self.assertIn('--frozen-lockfile --offline', document)
        self.assertNotIn('not yet available', document)

    def test_operator_docs_require_workspace_core_floor(self):
        version = workspace_core_version()
        for path in ('README.md', 'docs/operator-runbook.md'):
            document = ' '.join(text(path).split())
            match = re.search(r'subc-core(?: \(the supervisor core\), version)? ([0-9]+\.[0-9]+\.[0-9]+)', document)
            if match is None:
                raise AssertionError(f'{path} does not name a numeric subc-core floor')
            self.assertEqual(match.group(1), version, path)

    def test_release_notes_are_not_tied_to_one_migration(self):
        source = text('.github/workflows/release.yml')
        self.assertNotIn('CARRIES STORE MIGRATION 9', source)
        self.assertIn('RELEASE_NOTES: ${{ inputs.notes }}', source)
        self.assertNotIn('v0.1.2 does not carry this floor', source)
        # Linux and Windows gained native master-key stores; the notes must not tell
        # users those platforms have none.
        self.assertNotIn('there is no keychain', source)
        self.executable('gh', 'case "$*" in *"release view"*) exit 1;; *"release create"*) while [ "$#" -gt 0 ]; do case "$1" in --notes-file) cp "$2" "$HOME/captured-notes"; exit $?;; --notes) printf "%s\\n" "$2" > "$HOME/captured-notes"; exit 0;; esac; shift; done; exit 1;; *) exit 1;; esac')
        step = self.release_step('Create the release if it does not exist')
        permanent = ('SHA-256', 'sidecar', 'ad-hoc signed, not notarized', 'quarantine',
                     'Gatekeeper', 'curl', 'does not self-initialize', 'ck auth bootstrap',
                     'Credential Manager', 'Secret Service', '--key-path', 'CK_MASTER_KEY_PATH',
                     'no automatic fallback', 'key-source', 'REQUIRES subc-core ')
        for extra in ('', 'Release-specific migration instructions.'):
            env = dict(self.env, TAG='v1', GITHUB_REPOSITORY='scratch/repo', REPLACE_PUBLISHED='false',
                       RELEASE_NOTES=extra, REQUIRES_CORE=workspace_core_version())
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

    def test_landing_ci_matrix_and_required_macos_keychain_test(self):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/ci.yml'))
        job = workflow['jobs']['test']
        runners = job['strategy']['matrix']['include']
        self.assertCountEqual(runners, [
            {'os': 'ubuntu', 'runner': 'ubuntu-latest'},
            {'os': 'windows', 'runner': 'windows-latest'},
            {'os': 'macos', 'runner': 'macos-latest'},
        ])
        steps = {step.get('name'): step for step in job['steps']}
        native = steps['macOS Keychain round trips and locked refusal']
        self.assertEqual(native['if'], "runner.os == 'macOS'")
        self.assertEqual(native['env']['CK_NATIVE_STORE_TESTS'], '1')
        self.assertEqual(native['timeout-minutes'], '8')
        self.assertIn("perl -e 'alarm 60; exec @ARGV' /usr/bin/security", native['run'])
        self.assertLess(native['run'].index("probe_find 'read existing Current while locked'"),
                        native['run'].index('cargo test'))
        self.assertIn('--test native_store -- --ignored', native['run'])
        self.assertNotIn('continue-on-error', native)
        cleanup = steps['Restore macOS Keychain settings']
        self.assertEqual(cleanup['if'], "always() && runner.os == 'macOS'")

    def test_windows_runtime_workflows_are_a_required_ci_and_gate_arm(self):
        workflow = module('lib/workflow-gates').parse_workflow(os.fspath(ROOT / '.github/workflows/ci.yml'))
        steps = workflow['jobs']['test']['steps']
        step = next(step for step in steps if step.get('name') == 'Windows CI checks')
        self.assertEqual(step.get('if'), "runner.os == 'Windows'")
        self.assertNotIn('continue-on-error', step)
        self.assertEqual(step['shell'], 'bash')
        self.assertEqual(step['run'], 'bash scripts/gate.sh --lane windows-ci')
        self.assertIn('windows-ci) windows_ci ;;', text('scripts/gate.sh'))
        self.assertIn('source scripts/windows-ci.sh', text('scripts/gate.sh'))
        gate = text('scripts/windows-ci.sh').replace('\\\n', '').splitlines()
        arm = next(line for line in gate if 'run_expect 4 "Windows operator filesystem workflows"' in line)
        self.assertIn('--features windows-runtime-test-seam', arm)
        self.assertIn('--test windows_runtime -- --nocapture --test-threads=1', arm)

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
        self.uploaded_release()
        destination = self.root / workflow['jobs']['verify']['env']['ASSET_DIR']
        env = dict(self.release_verify_env(destination), TAG='v1', GITHUB_REPOSITORY='scratch/repo')
        download = self.release_step('Download draft release assets')
        verify = self.release_step('Verify uploaded asset names and checksums')
        publish = self.release_step('Undraft the release')
        for step in (download, verify, publish):
            result = self.run_shell(step['run'], env, cwd=self.root)
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

    def test_windows_skip_is_in_unchecked_verdict(self):
        source = text('scripts/gate.sh')
        start = source.index('if rustup target list')
        block = source[start:source.index('\nfi', start) + 3]
        self.executable('rustup', 'echo aarch64-apple-darwin')
        summary = shell_function('scripts/gate.sh', 'lane_verdict') + '\nlane_verdict'
        result = self.run_shell('record_arm() { :; }\n' + block + '\n' + summary)
        self.assertIn('GATE PASSED WITH UNCHECKED ARMS -- windows cross type-check', result.stdout.splitlines()[-1])
        self.assertRegex(source, r"else\s+printf '\\nGATE PASSED --")

    def test_probe_is_required_before_build_work(self):
        source = text('scripts/release-build.sh')
        self.assertLess(source.index('if [ -z "${PROBE:-}" ]'), source.index('cargo build --locked --release'))

    def test_endpoint_host_and_separator_drift_are_refused(self):
        endpoints = cast(Any, module('endpoint-hosts'))
        endpoints.ROOT = self.root
        endpoints.SOURCE_DIRS = [self.root]
        endpoints.MANIFEST = self.root / 'hosts'
        endpoints.DOMAIN_MANIFEST = self.root / 'domains'
        source = self.root / 'adapter.rs'
        source.write_text('const TOKEN_URL: &str = "https://provider.example/token";\n'
                          'const DOMAIN: &[u8] = b"cortexkit-credentials/control/v1";\n'
                          'const COOKIE: &[u8] = b"ck-control-cookie/v1";\n'
                          'const NOT_A_SEPARATOR: &[u8] = b"plain bytes v1";\n')
        # A separator without the `cortexkit-` prefix must be found too, and an
        # unrelated byte string must not be.
        self.assertEqual([value for _, value, _ in endpoints.discover_domains()],
                         ['ck-control-cookie/v1', 'cortexkit-credentials/control/v1'])
        endpoints.MANIFEST.write_text(endpoints.render(endpoints.discover()))
        endpoints.DOMAIN_MANIFEST.write_text(endpoints.render_domains(endpoints.discover_domains()))
        self.assertEqual(endpoints.main(), 0)
        source.write_text(source.read_text().replace('provider.example', 'attacker.example'))
        self.assertEqual(endpoints.main(), 1)
        source.write_text(source.read_text().replace('attacker.example', 'provider.example')
                          .replace('cortexkit-credentials/control/v1', 'cortexkit-credentials/control/v2'))
        self.assertEqual(endpoints.main(), 1)
        source.write_text(source.read_text()
                          .replace('cortexkit-credentials/control/v2', 'cortexkit-credentials/control/v1')
                          .replace('ck-control-cookie/v1', 'ck-control-cookie/v2'))
        self.assertEqual(endpoints.main(), 1)

    def test_tls_certificate_verify_context_is_pinned_and_update_is_stable(self):
        import sys
        from unittest.mock import patch
        endpoints = cast(Any, module('endpoint-hosts'))
        endpoints.ROOT = self.root
        endpoints.SOURCE_DIRS = [self.root]
        endpoints.MANIFEST = self.root / 'hosts'
        endpoints.DOMAIN_MANIFEST = self.root / 'domains'
        context = r'TLS 1.3, server CertificateVerify\0'
        (self.root / 'signing.rs').write_text(
            'const TOKEN_URL: &str = "https://provider.example/token";\n'
            f'pub const TLS_SERVER_CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"{context}";\n'
            'const UNRELATED: &[u8] = b"TLS 1.3, unrelated context";\n')
        pinned = context.replace(' ', r'\x20')
        self.assertEqual(endpoints.discover_domains(), [('signing.rs', pinned, pinned)])
        with patch.object(sys, 'argv', ['endpoint-hosts.py', '--update']):
            self.assertEqual(endpoints.main(), 0)
            first = (endpoints.MANIFEST.read_bytes(), endpoints.DOMAIN_MANIFEST.read_bytes())
            self.assertEqual(endpoints.main(), 0)
        self.assertEqual((endpoints.MANIFEST.read_bytes(), endpoints.DOMAIN_MANIFEST.read_bytes()), first)
        with patch.object(sys, 'argv', ['endpoint-hosts.py']):
            self.assertEqual(endpoints.main(), 0)

    def test_login_catalog_hosts_must_match_manifest_and_be_canonical(self):
        endpoints = cast(Any, module('endpoint-hosts'))
        endpoints.ROOT = self.root
        endpoints.SOURCE_DIRS = [self.root]
        endpoints.MANIFEST = self.root / 'hosts'
        endpoints.DOMAIN_MANIFEST = self.root / 'domains'
        catalog = self.root / 'catalog.rs'
        source = (
            'const DOMAIN: &[u8] = b"ck-control-cookie/v1";\n'
            'pub const LOGIN_PROVIDERS: &[LoginProvider] = &[\n'
            '    LoginProvider {\n'
            '        key: "first",\n'
            '        hosts: &["api.example"],\n'
            '    },\n'
            '    LoginProvider {\n'
            '        key: "second",\n'
            '        hosts: &[],\n'
            '    },\n'
            '];\n'
            'pub const OTHER_PROVIDERS: &[LoginProvider] = &[\n'
            '    LoginProvider {\n'
            '        key: "other",\n'
            '        hosts: &["not-a-login.example"],\n'
            '    },\n'
            '];\n'
        )
        catalog.write_text(source)
        rows = endpoints.discover()
        self.assertEqual(rows, [('catalog.rs', 'LOGIN_first_001', 'api.example')])
        endpoints.MANIFEST.write_text(endpoints.render(rows))
        endpoints.DOMAIN_MANIFEST.write_text(endpoints.render_domains(endpoints.discover_domains()))
        self.assertEqual(endpoints.main(), 0)
        for drift in [source.replace('api.example', 'new.example'),
                      source.replace('hosts: &[]', 'hosts: &["new.example"]')]:
            catalog.write_text(drift)
            self.assertEqual(endpoints.main(), 1)
        for host in ['Api.example', 'https://api.example', 'api.example:443',
                     'api.example/path', '*.example']:
            with self.subTest(host=host):
                catalog.write_text(source.replace('api.example', host))
                with self.assertRaisesRegex(SystemExit, 'invalid login host'):
                    endpoints.discover()

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
        self.assertEqual(paths.main(), 0)
        source.write_text('rel = str(path.relative_to(root))\n')
        self.assertEqual(paths.main(), 1)

    def test_inbound_mismatch_is_refused(self):
        block = shell_function('scripts/check-inbound-contracts.sh', 'compare')
        for ours, theirs, diagnostic in [
            ('wrong', 'expected', 'MISMATCH in control'),
            ('', 'expected', 'could not read control from fixture'),
            ('expected', '', 'could not read control from the spec'),
        ]:
            with self.subTest(ours=ours, theirs=theirs):
                result = self.run_shell('source_file=fixture; fail=0;\n' + block +
                                        f'\ncompare control "{ours}" "{theirs}"\n[ "$fail" = 1 ]')
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn(diagnostic, result.stdout)

    def test_inbound_contracts_follow_apns_source_across_crate_split(self):
        script = text('scripts/check-inbound-contracts.sh')
        spec = self.root / 'spec.md'
        spec.write_text(' "sealed":"<base64 of version and ciphertext>"\n'
                        '"mutable-content":1\n'
                        'version : 1 byte\n'
                        'enc     : 32 bytes\n'
                        'ct      : N bytes includes the 16-byte tag\n')
        good = ('pub const SEALED_BLOB_KEY: &str = "sealed";\n'
                'pub const MUTABLE_CONTENT_KEY: &str = "mutable-content";\n'
                'pub const MIN_SEALED_LEN: usize = 1 + 32 + 16;\n')
        bad = good.replace('"sealed"', '"wrong"')
        core = self.root / 'crates/credentials-core/src/apns_submit.rs'
        providers = self.root / 'crates/claustrum-providers/src/apns_submit.rs'
        for path in (core, providers):
            path.parent.mkdir(parents=True)
        for layout, core_text, providers_text, expected, diagnostic in [
            ('unsplit', good, None, 0, 'all transcribed facts agree'),
            ('split', None, good, 0, 'all transcribed facts agree'),
            ('prefer providers', bad, good, 0, 'all transcribed facts agree'),
            ('reject providers mismatch', good, bad, 1, 'MISMATCH in sealed blob payload key'),
            ('missing source', None, None, 1, 'apns_submit.rs not found'),
        ]:
            with self.subTest(layout=layout):
                for path, contents in ((core, core_text), (providers, providers_text)):
                    if contents is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_text(contents)
                result = self.run_shell('set -- "$SPEC"\n' + script,
                                        env=dict(self.env, SPEC=str(spec)), cwd=self.root)
                self.assertEqual(result.returncode, expected, result.stdout)
                self.assertIn(diagnostic, result.stdout)

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
