"""Pin the native Windows lane's shared CI entry point and command contracts."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import gate_runtime as runtime


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class WindowsLane(unittest.TestCase):
    def test_windows_setup_uses_installed_bun_1_versions_without_installing(self):
        setup = module("windows_setup", "scripts/windows-setup.py")
        for version in ("1.3.14", "1.4.2", "1.99.0"):
            with self.subTest(version=version):
                output = io.StringIO()
                with patch.object(setup.subprocess, "check_output", side_effect=[
                        "clippy 1.99.0\n", "rustfmt 1.99.0\n", version + "\n"]) as probe, \
                        patch.object(setup.subprocess, "run", side_effect=AssertionError("setup must not install tools")), \
                        patch("urllib.request.urlretrieve", side_effect=AssertionError("setup must not download tools")), \
                        contextlib.redirect_stdout(output):
                    setup.main()
                self.assertEqual([call.args[0] for call in probe.call_args_list], [
                    ["cargo", "clippy", "--version"], ["cargo", "fmt", "--version"], ["bun", "--version"]])
                self.assertIn(f"Bun {version} from PATH", output.getvalue())
                self.assertIn("clippy 1.99.0; rustfmt 1.99.0", output.getvalue())

    def test_windows_setup_refuses_missing_tools_or_unsupported_bun_without_installing(self):
        setup = module("windows_setup", "scripts/windows-setup.py")
        with patch.object(setup.subprocess, "run", side_effect=AssertionError("setup must not install tools")):
            with patch.object(setup.subprocess, "check_output", side_effect=FileNotFoundError("cargo absent")):
                with self.assertRaisesRegex(FileNotFoundError, "cargo absent"):
                    setup.main()
            with patch.object(setup.subprocess, "check_output", side_effect=["clippy", "rustfmt", "2.0.0"]):
                with self.assertRaisesRegex(RuntimeError, "expected Bun major version 1"):
                    setup.main()

    def test_windows_ci_and_gate_use_only_the_shared_windows_commands(self):
        workflow = module("workflow_gates", "scripts/lib/workflow-gates.py").parse_workflow(
            str(ROOT / ".github/workflows/ci.yml"))
        steps = workflow["jobs"]["test"]["steps"]
        # Unknown conditions refuse here: adding a new Windows run step must not
        # silently bypass the shared lane that the local gate runs.
        conditions = {None, "runner.os != 'Windows'", "runner.os == 'Windows'",
                      "runner.os == 'Linux'", "matrix.os == 'ubuntu'"}
        run_steps = []
        for step in steps:
            if "run" not in step:
                continue
            self.assertIn(step.get("if"), conditions, step)
            if step.get("if") in (None, "runner.os == 'Windows'"):
                run_steps.append(step)
        self.assertEqual([step["run"] for step in run_steps], ["bash scripts/gate.sh --lane windows-ci"])
        self.assertEqual(run_steps[0]["shell"], "bash")
        self.assertNotIn("continue-on-error", run_steps[0])
        driver = (ROOT / "scripts/gate-driver.py").read_text()
        self.assertIn('("Windows CI", remote_command("windows"), "Windows")', driver)
        bun_step = next(step for step in steps if step.get("uses") == "oven-sh/setup-bun@v2")
        self.assertEqual(bun_step["with"]["bun-version"].partition(".")[0], "1")

    def test_windows_command_order_features_environment_and_floors(self):
        # Spy at the command boundary, not on source text: shell quoting and
        # continuations must deliver the same argv to CI and the remote runner.
        spy = 'import json,sys; print(json.dumps(sys.argv[1:]))'
        shell = '''
source scripts/windows-ci.sh
uname() { echo MINGW64_NT; }
run_check() { python3 -c "$SPY" check "$@"; }
run_expect() { python3 -c "$SPY" expect "$@"; }
windows_ci
'''
        result = subprocess.run(["bash", "-c", shell], cwd=ROOT, text=True,
                                env={**os.environ, "SPY": spy, "CK_WINDOWS_GATE_OFFLINE": "1"},
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        labels = [row[2] if row[0] == "expect" else row[1] for row in rows]
        self.assertEqual(labels, [
            "Windows setup", "Bun install", "Bun build", "Bun typecheck", "Bun test packages",
            "Inbound contract check", "Endpoint hosts", "Path rendering", "Outside path deps",
            "Check development binary execution names", "Design doc status claims",
            "Windows Credential Manager round trips", "Fixture line endings", "Threshold boundary controls",
            "Format check", "Clippy", "Clippy (conformance seams)", "Test", "Client without transport",
            "Windows operator filesystem workflows", "Security-conformance suite (crash-safety seams)"])
        commands = {label: row[3:] if row[0] == "expect" else row[2:] for label, row in zip(labels, rows)}
        self.assertEqual(commands["Bun install"], ["bun", "install", "--frozen-lockfile", "--offline"])
        self.assertEqual(commands["Inbound contract check"], [
            "bash", "scripts/check-inbound-contracts.sh",
            os.environ.get("CRED_SUBCONSCIOUS_ROOT", "../subconscious") + "/docs/push-sealed-payload.md"])
        self.assertEqual(commands["Clippy"], ["cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"])
        self.assertEqual(commands["Clippy (conformance seams)"], [
            "cargo", "clippy", "--locked", "--workspace", "--all-targets", "--features",
            "kill9-test-seam,rotate-test-seam,login-test-seam,migration-tools,import-prompt-seam,windows-runtime-test-seam",
            "--", "-D", "warnings"])
        self.assertEqual(commands["Test"], ["cargo", "test", "--locked", "--workspace", "--all-targets"])
        self.assertEqual(commands["Windows Credential Manager round trips"], [
            "env", "CK_NATIVE_STORE_TESTS=1", "cargo", "test", "--locked", "--workspace",
            "--test", "native_store", "--", "--ignored", "--nocapture", "--test-threads=1"])
        self.assertEqual(commands["Windows operator filesystem workflows"], [
            "timeout", "600", "cargo", "test", "--locked", "-p", "credentials-module", "--features",
            "windows-runtime-test-seam", "--test", "windows_runtime", "--", "--nocapture", "--test-threads=1"])
        bun = commands["Bun test packages"]
        self.assertEqual(bun[:4], ["env", "XDG_RUNTIME_DIR=/nonexistent",
                                   "CLAUSTRUM_SUBC_CONNECTION=/nonexistent/x.json", "timeout"])
        self.assertEqual(bun[4], "1200")
        self.assertEqual(bun[6:], ["test", "packages/client"])
        floors = {row[2]: int(row[1]) for row in rows if row[0] == "expect"}
        self.assertGreater(floors["Test"], 0)
        self.assertEqual(floors["Windows Credential Manager round trips"], 1)
        self.assertEqual(floors["Windows operator filesystem workflows"], 4)
        self.assertEqual(floors["Security-conformance suite (crash-safety seams)"], 3)

    def test_only_github_ci_can_populate_dependency_caches(self):
        spy = ('import json,os,sys; print(json.dumps(dict(args=sys.argv[1:], '
               'cargo_offline=os.getenv("CARGO_NET_OFFLINE"), toolchain=os.getenv("RUSTUP_TOOLCHAIN"))))')
        shell = '''
source scripts/windows-ci.sh
uname() { echo MINGW64_NT; }
run_check() { if [[ "$1" = "Bun install" ]]; then python3 -c "$SPY" "${@:2}"; fi; }
run_expect() { :; }
windows_ci
'''
        for github, forced, offline in (("false", "", True), ("true", "", False), ("true", "1", True)):
            with self.subTest(github=github, forced=forced):
                result = subprocess.run(["bash", "-c", shell], cwd=ROOT, text=True, check=True,
                                        env={**os.environ, "SPY": spy, "GITHUB_ACTIONS": github,
                                             "CK_WINDOWS_GATE_OFFLINE": forced, "CARGO_NET_OFFLINE": "",
                                             "RUSTUP_TOOLCHAIN": "preinstalled-toolchain"},
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                row = json.loads(result.stdout)
                self.assertEqual(row["args"], ["bun", "install", "--frozen-lockfile"] + (["--offline"] if offline else []))
                self.assertEqual(row["cargo_offline"], "true" if offline else "")
                self.assertEqual(row["toolchain"], "preinstalled-toolchain")

    def test_windows_target_junction_treats_paths_as_data(self):
        remote = module("gate_remote", "scripts/gate-remote.py")
        link, target = Path("checkout & caller/target"), Path("cache %PATH% 'quoted'")
        with patch.object(remote.os, "name", "nt"), patch.object(remote.subprocess, "run") as run:
            remote.link_target(link, target)
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "powershell.exe")
        self.assertNotIn(str(link), " ".join(args[0]))
        self.assertNotIn(str(target), " ".join(args[0]))
        self.assertEqual(kwargs["env"]["CK_GATE_LINK"], str(link))
        self.assertEqual(kwargs["env"]["CK_GATE_TARGET"], str(target))
        self.assertTrue(kwargs["check"])

    def test_local_lanes_wait_for_both_captures_and_remotes_overlap(self):
        gate = runtime.Gate()
        submitted = threading.Barrier(2)
        local_started = threading.Event()
        captures = []

        def job(label, command, remote=False, captured=None):
            if remote:
                assert captured is not None
                submitted.wait(timeout=5)
                self.assertFalse(local_started.is_set())
                captures.append(label)
                captured.set()
                self.assertTrue(local_started.wait(timeout=5))
            else:
                self.assertCountEqual(captures, ["Linux", "Windows"])
                local_started.set()

        with patch.object(gate, "job", job):
            gate.parallel([("Linux", [], True), ("Windows", [], "Windows"), ("local", [])])

    def test_windows_worker_reuses_readonly_snapshot_as_writable_copy(self):
        remote = module("gate_remote", "scripts/gate-remote.py")
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            sibling = scratch / "supervisor snapshot"
            contract = sibling / "docs/push-sealed-payload.md"
            contract.parent.mkdir(parents=True)
            contract.write_text("contract document")

            def worker(command, cwd):
                self.assertEqual(command, ["bash", "scripts/gate.sh", "--lane", "windows-ci"])
                self.assertEqual(os.environ["CK_WINDOWS_GATE_OFFLINE"], "1")
                self.assertEqual(os.environ["CARGO_NET_OFFLINE"], "true")
                self.assertEqual((scratch / "subconscious/docs/push-sealed-payload.md").read_text(), "contract document")
                return subprocess.CompletedProcess(command, 0)

            with patch.object(remote, "stable_scratch", return_value=scratch), \
                    patch.object(remote, "copy_checkout") as copy, \
                    patch.object(remote, "forget_binaries_from_another_copy"), \
                    patch.dict(remote.os.environ), \
                    patch.object(remote.subprocess, "run", side_effect=worker):
                self.assertEqual(remote.main(["windows", "--sibling", str(sibling)]), 0)
            copy.assert_called_once()


if __name__ == "__main__":
    unittest.main()
