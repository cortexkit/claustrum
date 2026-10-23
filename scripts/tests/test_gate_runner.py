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
                self.assertIn("no ck motor run: stderr line was printed", result.stdout)

    def test_runner_failure_summary_keeps_last_stderr_reason(self):
        self.executable("ck", '''
echo 'ck motor run: earlier connection warning' >&2
echo 'ck motor run: refused before start: build server disk full' >&2
echo 'ck motor run: stdout is not a runner diagnostic'
exit "$SCENARIO"
''')
        for code in runtime.RUNNER_ERRORS:
            with self.subTest(code=code):
                result = self.gate(str(code))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                last = result.stdout.splitlines()[-1]
                self.assertIn(f"runner exit {code}:", last)
                self.assertIn("ck motor run: refused before start: build server disk full", last)
                self.assertNotIn("earlier connection warning", last)
                self.assertNotIn("stdout is not", last)
                self.assertIn("earlier connection warning", result.stdout)

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
        self.assertNotIn("--env", command)
        self.assertEqual(command[command.index("--") + 1:],
                         ["python3", "scripts/gate-remote.py", "fast", "--plan", json.dumps(plan)])

    def test_runner_inputs_use_argv_and_missing_sibling_is_clear(self):
        sibling = "../supervisor snapshot"
        with patch.dict(os.environ, CRED_SUBCONSCIOUS_ROOT=sibling):
            command = runtime.remote_command("full")
        self.assertNotIn("--env", command)
        self.assertEqual(command[command.index("--") + 1:],
                         ["python3", "scripts/gate-remote.py", "full", "--sibling", sibling])
        self.assertEqual(command[command.index("--sibling") + 1], sibling)
        self.assertFalse(any("RUSTC_WRAPPER" in argument for argument in command))
        missing = self.bin / "missing supervisor"
        result = subprocess.run([sys.executable, "scripts/gate-remote.py", "full", "--sibling", str(missing)],
                                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(f"supervisor snapshot not found inside runner: {missing}", result.stdout)
        self.assertNotIn("Traceback", result.stdout)

    def test_remote_argv_reaches_workers_without_forwarded_environment(self):
        spec = importlib.util.spec_from_file_location("gate_remote", ROOT / "scripts/gate-remote.py")
        assert spec is not None and spec.loader is not None
        remote = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(remote)
        sibling = self.bin / "supervisor snapshot"
        sibling.mkdir()
        plan = json.dumps(dict(crates=["credentials-core"], paths=["crates/credentials-core/new.rs"]))
        env = dict(os.environ, RUSTC_WRAPPER="unusable", CARGO_BUILD_RUSTC_WRAPPER="unusable",
                   CARGO_TARGET_DIR="unusable")
        env.pop("CRED_SUBCONSCIOUS_ROOT", None)
        env.pop("CK_FAST_PLAN", None)
        for mode, arguments in (("full", ["--sibling", str(sibling)]), ("fast", ["--plan", plan])):
            with self.subTest(mode=mode):
                def worker(command, cwd):
                    self.assertEqual(os.environ["RUSTC_WRAPPER"], "")
                    self.assertEqual(os.environ["CARGO_BUILD_RUSTC_WRAPPER"], "")
                    self.assertNotIn("CARGO_TARGET_DIR", os.environ)
                    if mode == "full":
                        self.assertEqual(Path(os.environ["CRED_SUBCONSCIOUS_ROOT"]), cwd.parent / "subconscious")
                    else:
                        self.assertEqual(os.environ["CK_FAST_PLAN"], plan)
                    return subprocess.CompletedProcess(command, 0)

                with patch.dict(os.environ, env, clear=True), \
                        patch.object(remote, "copy_checkout") as copy, \
                        patch.object(remote.subprocess, "run", side_effect=worker):
                    self.assertEqual(remote.main([mode, *arguments]), 0)
                self.assertEqual(copy.call_args_list[0].args[0], ROOT)
                if mode == "full":
                    self.assertEqual(copy.call_args_list[1].args[0], sibling)

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

    def test_snapshot_clones_trust_only_each_exact_git_directory(self):
        spec = importlib.util.spec_from_file_location("gate_remote", ROOT / "scripts/gate-remote.py")
        assert spec is not None and spec.loader is not None
        remote = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(remote)
        run = subprocess.run
        config = self.bin / "gitconfig"
        config.write_text("# Global configuration must remain unchanged.\n")

        def clone_as_other_owner(command, **kwargs):
            if "clone" in command:
                source = Path(command[-2])
                # Git's own ownership test switch exercises the real refusal without
                # requiring chown or access to another user's files.
                kwargs["env"] = dict(os.environ, GIT_TEST_ASSUME_DIFFERENT_OWNER="1", GIT_CONFIG_COUNT="0")
                kwargs.update(check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                result = run(command, **kwargs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(command[:3], ["git", "-c", f"safe.directory={source / '.git'}"])
                self.assertNotIn("*", " ".join(command))
                self.assertNotIn("--global", command)
                return result
            return run(command, **kwargs)

        with patch.dict(os.environ, GIT_CONFIG_GLOBAL=str(config), GIT_CONFIG_NOSYSTEM="1"):
            for name in ("claustrum", "subconscious"):
                source = self.bin / name
                run(["git", "init", "-q", str(source)], check=True)
                run(["git", "-C", str(source), "config", "user.email", "test@example.invalid"], check=True)
                run(["git", "-C", str(source), "config", "user.name", "test"], check=True)
                (source / "file").write_text(name)
                run(["git", "-C", str(source), "add", "."], check=True)
                run(["git", "-C", str(source), "commit", "-qm", "initial"], check=True)
                (source / "target").mkdir()
                with patch.object(remote.subprocess, "run", side_effect=clone_as_other_owner):
                    remote.copy_checkout(source, self.bin / (name + "-copy"))
        self.assertEqual(config.read_text(), "# Global configuration must remain unchanged.\n")


if __name__ == "__main__":
    unittest.main()
