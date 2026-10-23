#!/usr/bin/env python3
"""Exercise real lane commands with a fake runner: no builds or bus credentials."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import gate_runtime as runtime


class RunnerContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bin = Path(self.temp.name)
        bash = shutil.which("bash")
        assert bash is not None
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        REAL_BASH=bash, CALLS=str(self.bin / "calls"))
        self.executable("bash", r'''
case "$*" in
  *--lane\ preflight*) echo preflight >> "$CALLS"; exit 0;;
  *--lane\ typescript*|*--lane\ release*) echo host >> "$CALLS"; exit 0;;
esac
exec "$REAL_BASH" "$@"
''')
        self.executable("ck", '''
echo "$*" >> "$CALLS"
case "${SCENARIO:-}" in
  200|201|202|203|204) exit "$SCENARIO";;
  empty) echo CK_GATE_DONE; exit 0;;
esac
"$REAL_BASH" scripts/gate.sh --lane linux || exit $?
echo CK_GATE_DONE
''')
        self.executable("cargo", '''
echo "cargo $*" >> "$CALLS"
case "$*" in
  *clippy*) if [ "${SCENARIO:-}" = fail ]; then echo 'planted remote clippy failure'; exit 1; fi;;
  *test*)
    n=1150
    if [ "${SCENARIO:-}" = floor ]; then n=1; fi
    echo "test result: ok. $n passed; 0 failed; 0 ignored";;
esac
''')
        self.executable("uname", "echo Linux")
        self.executable("rustup", "echo x86_64-unknown-linux-gnu")
        self.executable("ckdev-mutate", "echo 'catalogue checked'")

    def executable(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def gate(self, scenario=""):
        return subprocess.run([sys.executable, "scripts/gate-driver.py"], cwd=ROOT,
                              env=dict(self.env, SCENARIO=scenario), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)

    def test_remote_failure_fails_full_gate(self):
        result = self.gate("fail")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("planted remote clippy failure", result.stdout)
        self.assertIn("GATE FAILED: Linux Rust + mutation catalogue: remote arm failed", result.stdout)

    def test_runner_unreachable_and_other_transport_codes_fail_gate(self):
        for code, meaning in runtime.RUNNER_ERRORS.items():
            with self.subTest(code=code):
                result = self.gate(str(code))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(meaning, result.stdout)

    def test_remote_no_counts_fails_gate(self):
        result = self.gate("empty")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("remote job returned no counts", result.stdout)

    def test_remote_floor_shortfall_fails_gate(self):
        result = self.gate("floor")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("workspace unit + integration ran 1 tests, expected at least 1150", result.stdout)

    def test_linux_lane_enforces_floor_before_returning(self):
        result = subprocess.run([self.env["REAL_BASH"], "scripts/gate.sh", "--lane", "linux"],
            cwd=ROOT, env=dict(self.env, SCENARIO="floor"), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("workspace unit + integration ran 1 tests, expected at least 1150", result.stdout)

    def test_success_keeps_counts_and_uses_one_remote_submission(self):
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('"passed": 1150, "floor": 1150', result.stdout)
        self.assertIn("Slowest arms:", result.stdout)
        calls = (self.bin / "calls").read_text().splitlines()
        self.assertEqual(calls[0], "preflight")
        self.assertEqual(sum(line.startswith("motor run ") for line in calls), 1)
        self.assertIn("--vcpus 8", "\n".join(calls))
        self.assertIn("--sibling ../subconscious", "\n".join(calls))
        self.assertTrue(any(line == "cargo build --release --locked --offline -p credentials-module --bin ck-auth" for line in calls))
        self.assertTrue(any("ckdev-mutate" in line for line in result.stdout.splitlines()) or "catalogue checked" in result.stdout)

    def test_fast_transport_has_scope_and_no_supervisor(self):
        plan = {"crates": ["credentials-core"], "paths": ["crates/credentials-core/src/lib.rs"]}
        command = runtime.remote_command("fast", plan)
        self.assertNotIn("--sibling", command)
        self.assertIn("CK_FAST_PLAN=" + json.dumps(plan), command)
        self.assertEqual(command[-3:], ["python3", "scripts/gate-remote.py", "fast"])

    def test_fast_gate_propagates_transport_failure_and_missing_counts(self):
        metadata = dict(packages=[dict(id="core", name="credentials-core",
                        manifest_path=str(ROOT / "crates/credentials-core/Cargo.toml"))],
                        workspace_members=["core"])
        self.executable("cargo", '''
case "$*" in
  *metadata*) echo "$METADATA";;
  *) echo "cargo stub";;
esac
''')
        self.executable("python3", '''
case "$*" in
  *unittest*) echo 'Ran 87 tests'; exit 0;;
  *--typescript-worker*) exit 0;;
esac
exec "$REAL_PYTHON" "$@"
''')
        for scenario, message in (("200", "runner unreachable"), ("empty", "no counts")):
            result = subprocess.run([sys.executable, "scripts/fast-check.py", "--base", "HEAD"],
                cwd=ROOT, env=dict(self.env, SCENARIO=scenario, METADATA=json.dumps(metadata),
                                   REAL_PYTHON=sys.executable), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("FAST CHECK FAILED:", result.stdout)
            self.assertIn(message, result.stdout)

    def test_parent_rechecks_remote_floor_and_completion(self):
        row = dict(label="probe", seconds=1, passed=1, floor=2, status="passed")
        with self.assertRaisesRegex(RuntimeError, "expected at least 2"):
            runtime.validate_remote(0, runtime.PREFIX + json.dumps(row) + "\nCK_GATE_DONE\n")
        row["passed"] = 2
        with self.assertRaisesRegex(RuntimeError, "missing completion receipt"):
            runtime.validate_remote(0, runtime.PREFIX + json.dumps(row))

    def test_lanes_overlap_and_all_are_joined_on_failure(self):
        gate = runtime.Gate()
        import threading
        barrier = threading.Barrier(2)
        completed = []

        def job(label, command, remote=False):
            barrier.wait(timeout=5)
            completed.append(label)
            if label == "broken":
                raise RuntimeError("planted")

        with patch.object(gate, "job", job), self.assertRaisesRegex(RuntimeError, "planted"):
            gate.parallel([("broken", []), ("joined", [])])
        self.assertCountEqual(completed, ["broken", "joined"])

    def test_writable_copy_preserves_dirty_content_and_history(self):
        spec = importlib.util.spec_from_file_location("gate_remote", ROOT / "scripts/gate-remote.py")
        assert spec is not None and spec.loader is not None
        remote = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(remote)
        source = self.bin / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        def git(*args):
            return subprocess.run(["git", "-C", str(source), *args], check=True, stdout=subprocess.PIPE)
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "test")
        (source / "file").write_text("committed")
        git("add", ".")
        git("commit", "-qm", "initial")
        (source / "file").write_text("dirty")
        (source / "untracked").write_text("new")
        (source / "target").mkdir()
        copy = self.bin / "copy"
        remote.copy_checkout(source, copy)
        self.assertEqual((copy / "file").read_text(), "dirty")
        self.assertEqual((copy / "untracked").read_text(), "new")
        self.assertTrue((copy / ".git").is_dir())
        subprocess.run(["git", "-C", str(copy), "checkout", "--", "file"], check=True)
        self.assertEqual((source / "file").read_text(), "dirty")


if __name__ == "__main__":
    unittest.main()
