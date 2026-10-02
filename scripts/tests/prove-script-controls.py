#!/usr/bin/env python3
"""Replay predecessor behavior against individual hermetic regression controls.

The index must hold the implementation first. Each mutation is restored by content,
and a clean worktree diff is required before the next control can run.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BASE = 'cb923c1edd71c21d180e5fb1244917ede5f9185b'
CONTROLS = {
    'scripts/gate.sh': [
        'skip_notice_survives_large_output', 'large_target_floor_survives_pipefail',
        'missing_local_floor_has_diagnostic', 'missing_target_floor_is_unchecked',
        'gate_resolves_relative_script_before_chdir', 'windows_skip_is_in_unchecked_verdict'],
    'scripts/accept-deploy.sh': [
        'killed_binary_diagnostic_is_reachable', 'missing_binary_digest_is_diagnosed',
        'unsigned_binary_diagnostic_is_reachable', 'degraded_vault_is_diagnosed',
        'multiple_daemon_pids_are_refused', 'lsof_large_output_is_drained_before_selecting_fields'],
    'scripts/release-build.sh': ['first_deployment_is_allowed_and_unknown_revision_diagnosed', 'probe_is_required_before_build_work'],
    'scripts/audit-signed-payloads.sh': ['unreadable_store_cannot_report_clean', 'payload_approval_is_bound_to_credential', 'payload_filename_is_passed_as_data'],
    'scripts/train-push.sh': ['trigger_probe_survives_transient_gh_failure_and_cleans_branch', 'default_workflow_is_ci'],
    'scripts/watch-ci.sh': ['watch_bounds_failed_reads', 'cancelled_run_is_superseded_not_red'],
    'scripts/lib/workflow-gates.py': ['tags_only_and_filtered_push_do_not_promise_every_train'],
    'scripts/threshold-controls.py': ['threshold_scan_includes_private_and_indented_constants', 'listed_threshold_must_still_exist'],
    'scripts/endpoint-hosts.py': ['inline_and_catalog_url_hosts_are_discovered'],
    '.github/workflows/release.yml': ['registry_pin_additions_and_multiple_versions_are_refused', 'published_release_requires_explicit_replacement', 'release_asset_gate_requires_expected_names', 'release_notes_are_not_tied_to_one_migration', 'workflow_inputs_are_data_not_shell_source', 'release_tokens_are_scoped_and_siblings_recorded'],
    '.github/workflows/publish-client.yml': ['npm_publish_is_master_only_and_bun_matches_ci', 'workflow_inputs_are_data_not_shell_source'],
    '.github/workflows/ci.yml': ['ci_clippy_covers_every_gate_seam', 'release_tokens_are_scoped_and_siblings_recorded'],
    'scripts/check-fixture-line-endings.py': ['fixture_prefix_needs_path_boundary'],
    'scripts/check-path-rendering.py': ['typescript_exclusions_are_checkout_relative'],
    'scripts/check-inbound-contracts.sh': ['inbound_missing_key_has_diagnostic'],
    'scripts/check-doc-status.py': ['doc_status_checks_all_markers_and_identifier_boundaries', 'non_utf8_doc_is_readable'],
    'scripts/accept-opencode-custody.sh': ['custody_scratch_is_removed_on_early_refusal', 'custody_model_match_drains_large_output'],
    'scripts/spikes/opencode-config-fetch.sh': ['stub_startup_budget_exceeds_cold_start'],
}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def main():
    if git('diff', '--stat'):
        sys.exit('Stage the implementation first; unstaged changes would be lost in the mutation.')
    evidence = []
    for rel, tests in CONTROLS.items():
        path = ROOT / rel
        live = path.read_bytes()
        old = subprocess.check_output(['git', 'show', f'{BASE}:{rel}'], cwd=ROOT)
        for suffix in tests:
            name = 'test_script_contracts.ScriptContracts.test_' + suffix
            try:
                mutant = old
                control = f'Restore predecessor {rel}'
                if suffix == 'missing_binary_digest_is_diagnosed':
                    # Keep execution diagnostics intact so the mutation reaches hashing.
                    source = live.decode()
                    start = source.index('        if ! a=')
                    end = source.index('        if [ "$a" = "$b" ]', start)
                    digest = '        a="$(shasum -a 256 "$STAGED_DIR/$name" | cut -d\' \' -f1)"\n        b="$(shasum -a 256 "$BIN_DIR/$name" | cut -d\' \' -f1)"\n'
                    mutant = (source[:start] + digest + source[end:]).encode()
                    control = f'Restore predecessor digest leg in {rel}'
                path.write_bytes(mutant + b'\n# NON-VACUITY BREAK: predecessor behavior\n')
                during = git('diff', '--stat')
                assert during
                try:
                    run = subprocess.run([sys.executable, '-m', 'unittest', '-v', name],
                                         cwd=ROOT / 'scripts/tests', text=True,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
                    failure = next((line for line in run.stdout.splitlines() if line.startswith(('FAIL:', 'ERROR:'))), '')
                    # A single selected test is the only test run; no other can redden.
                    outcome = 'reddened' if run.returncode and failure else 'undefended'
                    output = failure + '\n' + run.stdout[-250:]
                except subprocess.TimeoutExpired:
                    outcome = 'hung'
                    output = f'{name} did not terminate within 12s under predecessor behavior'
            finally:
                path.write_bytes(live)
                os.utime(path, None)
            after = git('diff', '--stat')
            assert not after, after
            entry = dict(control=control, expected_red=name,
                         captured_output=output[:400], applied_evidence=f'{rel}: during {during}; after restore empty git diff --stat', outcome=outcome)
            evidence.append(entry)
            print(f'{outcome}: {name}', flush=True)
    rel = 'scripts/threshold-controls.py'
    path = ROOT / rel
    live = path.read_text()
    for predicate in ('if name not in manifest:', 'if source.get(name) != path:'):
        name = 'test_script_contracts.ScriptContracts.test_new_threshold_and_stale_unchecked_row_fail_closed'
        try:
            assert predicate in live
            replacement = 'if False:  # NON-VACUITY BREAK'
            if predicate == 'if name not in manifest:':
                replacement = predicate + '  # NON-VACUITY BREAK\n            continue\n        ' + predicate
            path.write_text(live.replace(predicate, replacement, 1))
            during = git('diff', '--stat')
            assert during
            run = subprocess.run([sys.executable, '-m', 'unittest', '-v', name],
                                 cwd=ROOT / 'scripts/tests', text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
            failure = next((line for line in run.stdout.splitlines() if line.startswith(('FAIL:', 'ERROR:'))), '')
        finally:
            path.write_text(live)
            os.utime(path, None)
        assert not git('diff', '--stat')
        outcome = 'reddened' if run.returncode and failure else 'undefended'
        evidence.append(dict(control=f'Neutralize {predicate}', expected_red=name,
                             captured_output=(failure + '\n' + run.stdout[-250:])[:400],
                             applied_evidence=f'{rel}: during {during}; after restore empty git diff --stat', outcome=outcome))
        print(f'{outcome}: {name} ({predicate})', flush=True)
    Path(sys.argv[1]).write_text(json.dumps(evidence, indent=2))
    return int(any(e['outcome'] not in ('reddened', 'hung') for e in evidence))


if __name__ == '__main__':
    sys.exit(main())
