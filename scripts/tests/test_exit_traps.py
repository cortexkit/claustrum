#!/usr/bin/env python3
"""Fail-closed EXIT traps, including macOS's Bash 3.2 nounset behaviour."""
import os
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'
NOUNSET = re.compile(r'^\s*set[ \t]+(?:[^\n;]*[ \t]+)?(?:-[A-Za-z]*u[A-Za-z]*(?:\s|$)|-o[ \t]+nounset\b)', re.M)
TRAP = re.compile(
    r'^\s*trap\s+(?:--\s+)?(?P<action>\'[^\']*\'|"(?:[^"\\]|\\.)*"|\S+)'
    r'[ \t]+(?P<signals>[^\n;]+)', re.M,
)
SOURCE = re.compile(r'^\s*(?:source|\.)[ \t]+([^\n]+)', re.M)
GUARD = '''if [ "$status" -eq 0 ] && [ "${{finished:-0}}" -ne 1 ]; then
  echo "{script}: exited before successful completion" >&2
  status=1
fi'''


def shell_sources():
    result = {}
    for path in SCRIPTS.rglob('*'):
        if not path.is_file():
            continue
        content = path.read_bytes()
        if path.suffix == '.sh' or re.match(rb'#![^\n]*\b(?:bash|sh)\b', content):
            result[path] = content.decode()
    return result


def sourced_files(path, text, sources):
    """Resolve repository helpers without executing operator scripts or hooks."""
    for match in SOURCE.finditer(text):
        name = shlex.split(match[1], comments=True)[0]
        name = re.sub(r'\$\{?script_dir\}?', path.parent.as_posix(), name)
        candidates = {(ROOT / name).resolve(), (path.parent / name).resolve()}
        for helper in sources:
            # A dirname/BASH_SOURCE expression still names its helper by suffix.
            # Missing optional hooks are outside the checked-in scripts tree.
            relative = os.path.relpath(helper, path.parent)
            if helper in candidates or name.endswith('/' + relative):
                yield helper


def workflow_runs():
    parse = runpy.run_path(str(SCRIPTS / 'lib/workflow-gates.py'))['parse_workflow']
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        for job, body in parse(os.fspath(path))['jobs'].items():
            for index, step in enumerate(body.get('steps', [])):
                if 'run' in step:
                    yield path, f'{job}/{step.get("name", index)}', step['run']


def source_closure(path, sources):
    pending = [path]
    found = set()
    while pending:
        current = pending.pop()
        if current in found:
            continue
        found.add(current)
        pending.extend(sourced_files(current, sources[current], sources))
    return found


def exit_traps(text):
    for match in TRAP.finditer(text):
        if not {'EXIT', '0'}.intersection(match['signals'].split()):
            continue
        action = shlex.split(match['action'])[0]
        if action not in ('-', ''):
            yield match.start(), action


def trap_body(text, action):
    if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', action):
        function = re.search(r'^' + action + r'\(\) \{\n(.*?)^\}', text, re.M | re.S)
        if function is None:
            raise AssertionError('EXIT handler function not found: ' + action)
        return function[1]
    return action


def statements(text):
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


class ExitTrapContracts(unittest.TestCase):
    def test_nounset_exit_traps_require_finished_guard(self):
        sources = shell_sources()
        entries = [(path, '', text) for path, text in sources.items()]
        entries.extend(workflow_runs())
        checked = set()
        for path, step, text in entries:
            scope = dict(sources)
            scope[path] = text
            closure = source_closure(path, scope)
            if not any(NOUNSET.search(scope[helper]) for helper in closure):
                continue
            traps = [(helper, offset, action) for helper in closure
                     for offset, action in exit_traps(scope[helper])]
            if not traps:
                continue
            with self.subTest(script=path.relative_to(ROOT).as_posix(), step=step):
                self.assertRegex(text, r'(?m)^finished=0$', 'initialize the completion flag')
                self.assertEqual(statements(text)[-1], 'finished=1',
                                 'successful fallthrough must set the completion flag last')
                executable = '\n'.join(statements(text))
                for success in re.finditer(r'\bexit[ \t]+0\b', executable):
                    self.assertRegex(executable[:success.start()], r'finished=1[;\s]*$',
                                     'set finished=1 immediately before each successful exit')
                for helper, offset, action in traps:
                    checked.add(helper.relative_to(ROOT).as_posix())
                    body = statements(trap_body(scope[helper], action))
                    self.assertIn(body[0], ('status=$?', 'local status=$?'),
                                  'EXIT handlers must capture $? before doing anything else')
                    expected = statements(GUARD.format(script=helper.name))
                    self.assertEqual(body[1:1 + len(expected)], expected,
                                     'EXIT handlers must reject a zero status without completion')
                    self.assertEqual(body[-1], 'exit "$status"', 'preserve the captured status')
                    if helper == path:
                        self.assertIn('finished=0', text[:offset])
        self.assertTrue(checked, 'the tree-wide contract must exercise real EXIT traps')

    def test_workflow_cleanup_rejects_unfinished_exit_and_nounset(self):
        checked = 0
        for path, step, text in workflow_runs():
            if not NOUNSET.search(text):
                continue
            for _offset, action in exit_traps(text):
                checked += 1
                for injected, expected in (('exit 0', 1), (': "${EXIT_TRAP_UNSET}"', None),
                                           ('exit 7', 7), ('finished=1\nexit 0', 0)):
                    with self.subTest(workflow=path.name, step=step, injected=injected), \
                            tempfile.TemporaryDirectory() as directory:
                        temporary = Path(directory) / 'cleanup'
                        temporary.mkdir()
                        handler = trap_body(text, action)
                        # Run the real handler without building or unpacking release assets.
                        script = ('set -eu\nfinished=0\nt=' + shlex.quote(str(temporary))
                                  + '\ncleanup() {\n' + handler + '\n}\ntrap cleanup EXIT\n' + injected)
                        env = dict(os.environ)
                        env.pop('EXIT_TRAP_UNSET', None)
                        result = subprocess.run(['/bin/bash', '-c', script], env=env,
                                                text=True, capture_output=True, timeout=10)
                        if expected is None:
                            self.assertNotEqual(result.returncode, 0, result.stderr)
                            self.assertIn('unbound variable', result.stderr)
                        else:
                            self.assertEqual(result.returncode, expected, result.stderr)
                        self.assertFalse(temporary.exists(), 'the EXIT handler must remove its temporary directory')
        self.assertGreater(checked, 0, 'exercise real workflow cleanup handlers')

    def run_native_store_trap(self, injected):
        # Execute the actual script, stopping immediately after its trap is installed.
        # The prerequisite stubs are only queried with command -v; no bus, keyring,
        # cargo, or operator HOME is used before the injected exit.
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            scripts = scratch / 'scripts'
            scripts.mkdir()
            bin_dir = scratch / 'bin'
            bin_dir.mkdir()
            for name in ('dbus-run-session', 'gnome-keyring-daemon'):
                stub = bin_dir / name
                stub.write_text('#!/bin/sh\nexit 99\n')
                stub.chmod(0o755)
            source = (SCRIPTS / 'test-native-store.sh').read_text()
            trap = re.search(r'^trap cleanup EXIT$', source, re.M)
            if trap is None:
                raise AssertionError('inject only after the real cleanup trap is installed')
            script = scripts / 'test-native-store.sh'
            script.write_text(source[:trap.end()] + '\n' + injected
                              + '\necho "injection unexpectedly returned" >&2\nexit 99\n')
            env = dict(os.environ, PATH=os.fspath(bin_dir) + os.pathsep + os.environ['PATH'],
                       TMPDIR=str(scratch))
            env.pop('finished', None)
            env.pop('EXIT_TRAP_UNSET', None)
            result = subprocess.run(['/bin/bash', str(script)], env=env, cwd=scratch,
                                    text=True, capture_output=True, timeout=120)
            self.assertNotIn('injection unexpectedly returned', result.stderr)
            self.assertEqual(sorted(path.name for path in scratch.iterdir()), ['bin', 'scripts'],
                             'the EXIT trap must still remove its temporary root')
            return result

    def test_native_store_unbound_variable_fails_closed(self):
        # Bash 3.2 reports $?=0 to EXIT after either nounset failure. Running
        # /bin/bash exercises that bug on macOS, rather than a newer PATH bash.
        for injected in (': "${EXIT_TRAP_UNSET}"', 'empty=(); : "${empty[@]}"'):
            with self.subTest(injected=injected):
                # Newer Bash permits empty arrays under nounset; explicitly exit
                # without completion so that version still checks the guard.
                result = self.run_native_store_trap(injected + '\nexit 0')
                self.assertNotEqual(result.returncode, 0, result.stderr)
                if 'EXIT_TRAP_UNSET' in injected:
                    self.assertIn('unbound variable', result.stderr)

    def test_native_store_trap_preserves_exit_status(self):
        for injected, expected in (('exit 0', 1), ('exit 7', 7),
                                   ('finished=1; exit 0', 0), ('finished=1; exit 9', 9)):
            with self.subTest(injected=injected):
                result = self.run_native_store_trap(injected)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 1:
                    self.assertIn('test-native-store.sh: exited before successful completion',
                                  result.stderr)


if __name__ == '__main__':
    unittest.main()
