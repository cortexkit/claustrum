"""Check the single-writer corpus, independent byte layouts and legacy compatibility."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/secret-multi-host-vectors.py"
SPEC = importlib.util.spec_from_file_location("secret_multi_host_vectors", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


def unframe(hex_string):
    """Independent decoder: no generator framing or scope helpers are reused."""
    data = bytes.fromhex(hex_string)
    fields = []
    while data:
        if len(data) < 8:
            raise AssertionError("truncated length")
        size = int.from_bytes(data[:8], "little")
        if len(data) < 8 + size:
            raise AssertionError("truncated field")
        fields.append(data[8:8 + size])
        data = data[8 + size:]
    return fields


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class MultiHostVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = GEN.documents()
        cls.scope = {row["case"]: row for row in cls.documents["secret-scope-match-v1.json"]["cases"]}
        cls.deposits = {row["case"]: row for row in cls.documents["secret-deposit-v2.json"]["cases"]}

    def test_corpus_is_byte_pinned_and_manifest_covers_exactly_five_files(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("checked 6 byte-identical multi-host files", result.stdout)
        expected = {"secret-scope-match-v1.json", "secret-approval-v3.json", "secret-flow-approval-v3.json",
                    "secret-deposit-v2.json", "secret-list-v2.json", "SHA256SUMS"}
        self.assertEqual({path.name for path in GEN.OUTPUT.iterdir()}, expected)
        sums = (GEN.OUTPUT / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(sums), 5)
        self.assertEqual([line[66:] for line in sums], sorted(expected - {"SHA256SUMS"}))
        for line in sums:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((GEN.OUTPUT / name).read_bytes()).hexdigest(), digest)

    def test_jcs_bytes_have_independent_literal_and_utf16_order_controls(self):
        self.assertEqual(GEN.jcs({"z": [True, False, None], "a": 'é\n"'}),
                         b'{"a":"\xc3\xa9\\n\\\"","z":[true,false,null]}')
        self.assertEqual(GEN.jcs({"\ue000": 2, "\U00010000": 1}),
                         '{"\U00010000":1,"\ue000":2}'.encode())
        for value in [1.5, 2**53, "\ud800", {1: "not-a-string-key"}]:
            with self.subTest(value=repr(value)), self.assertRaises((ValueError, UnicodeError)):
                GEN.jcs(value)
        self.assertEqual(GEN.frames("A", "", b"\xff").hex(),
                         "01000000000000004100000000000000000100000000000000ff")

    def test_existing_published_statement_bytes_and_deposit_framing_agree(self):
        vector_root = GEN.OUTPUT.parent
        count = 0
        for name in ["secret-approval-v1.json", "secret-approval-v2.json",
                     "secret-flow-approval-v1.json", "secret-flow-approval-v2.json"]:
            document = json.loads((vector_root / name).read_text())
            for row in document["vectors"]:
                samples = row.get("statements", [row])
                for sample in samples:
                    raw = unb64(sample["statement_b64url"])
                    obj = json.loads(raw)
                    self.assertEqual(GEN.jcs(obj), raw, (name, row["case"]))
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), sample["statement_sha256"])
                    count += 1
        self.assertGreaterEqual(count, 12)
        published = json.loads((vector_root / "secret-approval-v1.json").read_text())["deposit"]
        legacy = self.deposits["legacy-ignores-gate-false"]
        self.assertEqual(bytes.fromhex(legacy["aad_hex"]), unb64(published["aad_b64url"]))
        self.assertEqual(bytes.fromhex(legacy["plaintext_hex"]), unb64(published["plaintext_b64url"]))
        self.assertEqual(unframe(legacy["sealed_body_hex"]),
                         [b"ck-secret-sealed-body/v1", b"agent_api_key", b"x.test", b"/repos/a",
                          b"header:X-Api-Key", b"ckios-fixed-api-key"])

    def test_deposit_sent_order_and_sealed_canonical_order_are_independent(self):
        sample = self.deposits["noncanonical-sent-order"]
        self.assertEqual(unframe(sample["aad_hex"]),
                         [b"ck-secret-deposit-aad/v2", GEN.REQUEST.encode(), GEN.MEMBER.encode(),
                          b"key", b"agent_api_key", b"2", b"z.x.test", b"/v1", b"a.x.test", b"",
                          b"header:X-Api-Key"])
        self.assertEqual(unframe(sample["sealed_body_hex"]),
                         [b"ck-secret-sealed-body/v2", b"agent_api_key", b"2", b"a.x.test", b"",
                          b"z.x.test", b"/v1", b"header:X-Api-Key", b"ckios-fixed-api-key"])
        reorder = self.deposits["reordered-replay-conflicts"]
        self.assertNotEqual(sample["aad_hex"], reorder["aad_hex"])
        self.assertEqual(sample["sealed_body_hex"], reorder["sealed_body_hex"])
        self.assertEqual(reorder["expect"], {"code": "deposit_conflict"})
        login = self.deposits["two-origins"]
        self.assertEqual(unframe(login["sealed_body_hex"]),
                         [b"ck-secret-sealed-body/v2", b"site_login", b"2", b"https://x.test",
                          b"https://y.test:443", b"test-user", b"test-only-password", b""])
        self.assertEqual(unframe(login["plaintext_hex"]),
                         [b"ck-secret-deposit-plaintext/v1", b"test-user", b"test-only-password", b""])
        self.assertEqual(unframe(self.deposits["eight-rules"]["sealed_body_hex"])[2], b"8")
        self.assertEqual(unframe(self.deposits["four-origins"]["sealed_body_hex"])[2], b"4")

    def test_scope_corpus_has_only_crate_inputs_and_explicit_refusal_forms(self):
        document = self.documents["secret-scope-match-v1.json"]
        self.assertEqual(set(document), {"v", "psl_snapshot", "cases"})
        self.assertEqual(set(document["psl_snapshot"]), {"url", "date", "sha256"})
        cases = document["cases"]
        self.assertEqual(len({row["case"] for row in cases}), len(cases))
        for row in cases:
            with self.subTest(case=row["case"]):
                self.assertIn(row["form"], {"input", "stored"})
                self.assertIn(row["kind"], {"agent_api_key", "site_login"})
                self.assertFalse({"location", "setup", "gate", "state"} & set(row["scope"]))
                expected_keys = {"case", "form", "kind", "scope", "expect"}
                if isinstance(row["expect"], dict):
                    self.assertEqual(set(row["expect"]), {"scope_refused"})
                    self.assertIn(row["expect"]["scope_refused"], {"invalid_params", "limit_exceeded"})
                else:
                    self.assertIn(row["expect"], {"match", "no_match"})
                    expected_keys.add("target")
                    self.assertIn(set(row["target"]), [{"origin"}, {"scheme", "host", "port", "path"}])
                self.assertEqual(set(row), expected_keys)
        self.assertEqual(self.scope["stored-private-suffix-still-usable"]["form"], "stored")
        self.assertEqual(self.scope["stored-private-suffix-still-usable"]["expect"], "match")
        self.assertEqual(self.scope["stored-empty-prefix-is-absent"]["expect"], "match")
        self.assertEqual(self.scope["stored-exact-singleton"]["expect"], {"scope_refused": "invalid_params"})

    def test_required_boundary_psl_grammar_and_matching_examples_are_present(self):
        matching = {"eight-rules", "four-origins", "wildcard-child", "psl-foo.github.io", "psl-x.test",
                    "psl-www.ck", "overlapping-wildcard-exact", "overlapping-prefixes", "legacy-exact-prefix",
                    "legacy-trailing-slash", "legacy-child", "legacy-no-prefix-/", "legacy-no-prefix-/x/y",
                    "legacy-login-https://x.test:443", "host-253-bytes", "wildcard-host-253-bytes",
                    "prefix-1024-bytes", "literal-star-/v1/*", "literal-star-/v1/*/x"}
        no_match = {"wildcard-base", "wildcard-grandchild", "login-target-is-not-api-key", "literal-star-/v1/items",
                    "legacy-http", "legacy-port", "legacy-other-host", "legacy-segment-boundary",
                    "legacy-no-percent-decoding", "legacy-login-http://x.test", "legacy-login-https://y.test",
                    "legacy-login-https://x.test:444"}
        invalid = {"psl-com", "psl-github.io", "psl-xn--55qx5d.cn", "psl-a.ck", "psl-test",
                   "exact-singleton", "origin-singleton", "duplicate-rules", "duplicate-canonical-origins",
                   "login-origin-wildcard", "input-empty-prefix", "host-grammar-before-cap",
                   "legacy-host-uppercase", "legacy-host-trailing-dot", "legacy-host-ipv4", "legacy-host-ipv6",
                   "legacy-host-empty-label", "legacy-host-leading-hyphen", "legacy-host-trailing-hyphen",
                   "legacy-host-unicode", "legacy-host-wildcard", "legacy-prefix-'/'", "legacy-prefix-'/repos/a/'",
                   "legacy-prefix-''", "misplaced-wildcard-*", "misplaced-wildcard-*.", "misplaced-wildcard-a.*.b",
                   "misplaced-wildcard-*a.b", "misplaced-wildcard-*.*.b"}
        limited = {"nine-rules", "five-origins", "host-254-bytes", "wildcard-host-254-bytes", "prefix-1025-bytes",
                   "precedence-count-before-entry", "precedence-host-cap-before-prefix",
                   "precedence-sent-entry-order", "precedence-entry-before-singleton"}
        for names, expected in [(matching, "match"), (no_match, "no_match"),
                                (invalid, {"scope_refused": "invalid_params"}),
                                (limited, {"scope_refused": "limit_exceeded"})]:
            for name in names:
                with self.subTest(case=name):
                    self.assertEqual(self.scope[name]["expect"], expected)

    def test_vault_cases_have_setup_and_statement_bytes_are_hash_pinned(self):
        statements = 0
        for name, document in self.documents.items():
            if name == "secret-scope-match-v1.json":
                continue
            self.assertEqual(len({row["case"] for row in document["cases"]}), len(document["cases"]))
            for row in document["cases"]:
                self.assertTrue(row["operation"])
                self.assertIsInstance(row["setup"], dict)
                if "statement" not in row:
                    continue
                statements += 1
                raw = bytes.fromhex(row["statement_jcs_hex"])
                self.assertEqual(json.loads(raw), row["statement"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row["statement_sha256"])
                statement = row["statement"]
                self.assertEqual(statement["v"], "ck-secret-flow-statement/v3" if "flow" in statement
                                 else "ck-secret-use-statement/v3")
                if row["expect"] == {"status": "approval_required"}:
                    self.assertEqual(statement.get("asking_member_id", ""), row["setup"]["pending_asking_member_id"])
                use = statement["use"]
                self.assertFalse({"host", "path_prefix", "origin"} & set(use))
                for rule in use.get("rules", []):
                    self.assertEqual(set(rule), {"host", "path_prefix"})
        self.assertEqual(statements, 22)


if __name__ == "__main__":
    unittest.main()
