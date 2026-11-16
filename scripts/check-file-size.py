#!/usr/bin/env python3
"""Keep tracked hand-written source below the file-size boundary."""
import re
import subprocess
from pathlib import Path

MAX_SOURCE_FILE_LINES = 5000
SOURCE_EXTENSIONS = {".rs", ".ts", ".tsx", ".py", ".sh"}

# Exempt test paths and names, plus generated or vendored fixture/vector trees.
EXEMPT_DIRECTORIES = {"test", "tests", "vectors", "fixtures"}
EXEMPT_SUFFIXES = ("_tests.rs", "tests.rs", ".test.ts", ".test.tsx")
RAW_STRING = re.compile(r'(?:br|r)(\#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")

# Oversized files may shrink, but must not grow before they are split by area.
EXCEPTIONS = {
    "crates/credentials-module/src/main.rs": (
        3140, "daemon dispatch and per-operation handlers; split by area (admin, federation, secrets, health) when next worked in"
    ),
    "crates/credentials-core/src/store.rs": (
        10025, "EncryptedStore core and migrations; continue moving areas into store_*.rs when next worked in"
    ),
    "crates/credentials-module/src/bin/credentials_cli.rs": (
        8227, "ck auth verb table and verb bodies; move verb bodies into cli_support/ by area when next worked in"
    ),
    "crates/credentials-core/src/catalog.rs": (
        5583, "provider catalog rows plus login checks; move the row table out when next worked in"
    ),
}


def exempt(path):
    return bool(set(path.parts[:-1]) & EXEMPT_DIRECTORIES) or path.name.endswith(EXEMPT_SUFFIXES)


def rust_code(source):
    """Blank comments and literals while retaining offsets and line breaks."""
    result = list(source)
    i = 0

    def blank(start, end):
        for index in range(start, end):
            if source[index] != "\n":
                result[index] = " "

    while i < len(source):
        start = i
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
        elif source.startswith("/*", i):
            i += 2
            depth = 1
            while i < len(source) and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
        else:
            raw = RAW_STRING.match(source, i) if source[i] in "br" else None
            if raw and (i == 0 or not (source[i - 1].isalnum() or source[i - 1] == "_")):
                closing = '"' + raw.group(1)
                end = source.find(closing, i + len(raw.group(0)))
                i = len(source) if end < 0 else end + len(closing)
            elif source[i] == '"':
                i += 1
                while i < len(source):
                    if source[i] == "\\":
                        i += 2
                    elif source[i] == '"':
                        i += 1
                        break
                    else:
                        i += 1
            elif source[i] == "'":
                # A lifetime such as 'a is not a character literal.
                char = CHAR_LITERAL.match(source, i)
                if not char:
                    i += 1
                    continue
                i += len(char.group(0))
            else:
                i += 1
                continue
        blank(start, min(i, len(source)))
    return "".join(result)


def product_lines(source):
    code = rust_code(source)
    module = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+\w+\s*\{")
    matches = {match.start(): match for match in module.finditer(code)}
    depth = 0
    i = 0
    excluded = set()
    while i < len(code):
        match = matches.get(i)
        if depth == 0 and match:
            start = i
            i = match.end()
            nested = 1
            while i < len(code) and nested:
                if code[i] == "{":
                    nested += 1
                elif code[i] == "}":
                    nested -= 1
                i += 1
            if nested:
                raise ValueError("unclosed cfg(test) module")
            first = source.count("\n", 0, start)
            last = source.count("\n", 0, i - 1)
            excluded.update(range(first, last + 1))
            continue
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
        i += 1
    return len(source.splitlines()) - len(excluded)


def check(root, exceptions=EXCEPTIONS):
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    failed = False
    for name in tracked:
        if not name:
            continue
        path = Path(name.decode("utf-8", errors="surrogateescape"))
        if path.suffix not in SOURCE_EXTENSIONS or exempt(path):
            continue
        source = (root / path).read_text(encoding="utf-8")
        count = product_lines(source) if path.suffix == ".rs" else len(source.splitlines())
        key = path.as_posix()
        if key in exceptions:
            baseline, reason = exceptions[key]
            if count > baseline:
                print(f"{key}: {count} product lines exceeds baseline {baseline}")
                failed = True
            else:
                print(f"{key}: {count} product lines (baseline {baseline}; {reason})")
                if baseline - count > 200:
                    print(f"  note: lower the baseline for {key}")
        elif count >= MAX_SOURCE_FILE_LINES:
            print(f"{key}: {count} product lines reaches limit {MAX_SOURCE_FILE_LINES}")
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(check(Path(__file__).resolve().parents[1]))
