import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_file_size", ROOT / "scripts/check-file-size.py")
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class FileSizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)

    def tracked(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "add", "--", name], cwd=self.root, check=True)

    def scan(self, exceptions=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = checker.check(self.root, {} if exceptions is None else exceptions)
        return result, output.getvalue()

    def test_product_limit_and_test_exemptions(self):
        self.tracked("product.py", "x\n" * 4999)
        self.tracked("large_tests.rs", "x\n" * 5001)
        self.tracked("src/tests/large.ts", "x\n" * 5001)
        self.tracked("test/large.py", "x\n" * 5001)
        self.tracked("vectors/large.rs", "x\n" * 5001)
        self.tracked("fixtures/large.sh", "x\n" * 5001)
        self.tracked("large.test.ts", "x\n" * 5001)
        self.tracked("large.test.tsx", "x\n" * 5001)
        self.assertEqual(self.scan()[0], 0)
        self.tracked("product.py", "x\n" * 5000)
        self.assertIn("product.py: 5000", self.scan()[1])
        self.tracked("product.py", "x\n" * 5001)
        result, output = self.scan()
        self.assertEqual(result, 1)
        self.assertIn("product.py: 5001", output)

    def test_exception_baseline_and_shrink_note(self):
        exceptions = {"large.py": (5001, "split it")}
        self.tracked("large.py", "x\n" * 5001)
        self.assertEqual(self.scan(exceptions)[0], 0)
        self.tracked("large.py", "x\n" * 5002)
        result, output = self.scan(exceptions)
        self.assertEqual(result, 1)
        self.assertIn("large.py: 5002 product lines exceeds baseline 5001", output)
        self.tracked("large.py", "x\n" * 4800)
        self.assertIn("lower the baseline", self.scan(exceptions)[1])

    def test_rust_test_module_excludes_lines_and_ignores_literal_braces(self):
        product = "let _ = 1;\n" * 1000
        tests = ("#[cfg(test)]\nmod tests {\n"
                 'let _ = "{";\nlet _ = \'}\';\n'
                 'let _ = r##" } { "##;\n'
                 "/* nested { /* } */ { */\n"
                 + "let _ = 0; // }\n" * 4993 + "}\n")
        self.assertEqual(len((product + tests).splitlines()), 6000)
        self.assertEqual(checker.product_lines(product + tests), 1000)
        self.tracked("src/lib.rs", product + tests)
        self.assertEqual(self.scan()[0], 0)

    def test_only_top_level_test_module_is_excluded(self):
        source = ("fn f<'a>() {\n"
                  "    #[cfg(test)] mod nested { let _ = \"}\"; }\n"
                  "}\n"
                  "#[cfg(test)]\nmod tests {\n}\n"
                  "fn product() {}\n")
        self.assertEqual(checker.product_lines(source), 4)

    def test_real_repository_passes(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = checker.check(ROOT)
        self.assertEqual(result, 0, output.getvalue())
        for path in checker.EXCEPTIONS:
            self.assertIn(path, output.getvalue())


if __name__ == "__main__":
    unittest.main()
