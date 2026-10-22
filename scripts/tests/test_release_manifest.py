#!/usr/bin/env python3
"""Tests for release manifest version extraction and validation."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_manifest", ROOT / "scripts" / "release-manifest.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load release-manifest.py")
release_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_manifest)


class ReleaseManifestTests(unittest.TestCase):
    def cargo_toml(self, version: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "Cargo.toml"
        path.write_text(
            "[workspace.metadata.release]\n"
            f'requires_core = "{version}"\n'
        )
        return path

    def test_reads_plain_three_component_version(self):
        path = self.cargo_toml("9.8.7")
        self.assertEqual(release_manifest.read_required_core(path), "9.8.7")

    def test_rejects_malformed_version(self):
        path = self.cargo_toml("0.20")
        with self.assertRaisesRegex(ValueError, "plain X.Y.Z"):
            release_manifest.read_required_core(path)

    def test_rejects_v_prefixed_version(self):
        path = self.cargo_toml("v0.20.83")
        with self.assertRaisesRegex(ValueError, "plain X.Y.Z"):
            release_manifest.read_required_core(path)


if __name__ == "__main__":
    unittest.main()
