#!/usr/bin/env python3
"""Refuse platform-dependent path rendering and common unsafe path component derivation.

WHY THIS EXISTS RATHER THAN A COMMENT. `str(Path)` renders backslashes on
Windows, so any comparison against a posix literal -- a manifest row, a
`"/tests/"` fragment -- fails there and passes everywhere else. It has now
appeared three times:

  2026-08-11  endpoint-hosts.py    all 29 manifest rows failed on the Windows leg
  2026-08-12  threshold-controls.py  every manifest row reported "moved"
  2026-08-12  threshold-controls.py  a "/tests/" exclusion, LATENT, one line below
                                     the comment warning about the previous one

The third is the argument. I had just fixed the second, written a comment about
it, and left an instance of the same defect immediately above that comment --
and CI passed, because no threshold is currently defined in a test file. Knowing
about a defect does not prevent it; a check does.

It also does not depend on remembering to run it against a new script: the sweep
is over `scripts/*.py`, so a file added tomorrow is covered by existing code.

The permitted form is `Path.as_posix()`. Where a genuine platform-native string
is wanted -- passing a path to a subprocess -- use `os.fspath()`, which says so
at the call site and is not what a comparison against a literal ever wants.

THE TYPESCRIPT ARM IS A DIFFERENT DEFECT. Splitting a full path on `'/'` and then
rejoining the result as a component is safe on POSIX but not Windows: a backslash
path has no slash, so the "basename" becomes the whole path. The quarantine sweep
then fails CLOSED because its bad prefix only fails to MATCH a directory entry;
the atomic temp name instead fails to CREATE because `O_CREAT|O_EXCL` rejects the
embedded separators and drive-letter colon. Same root cause, opposite blast radius.

The discriminator is decompose-then-rejoin, not string manipulation generally.
Suffixes appended to a full path and fixed names passed to `join()` are safe. This
is a TRIPWIRE for the common `.split('/')` and `.lastIndexOf('/')` spellings, not
proof that the class is closed: it does not catch `p.substring(p.lastIndexOf(sep) +
1)`, `p.match(/[^/\\]+$/)?.[0]`, `p.replace(/^.*\\//, '')`,
`p.split(path.sep).pop()`, or a locally-written basename-alike helper. The
`path.sep` spelling reads as correct but is still wrong when a stored path came
from the other platform; sweep by hand when the shape differs.

Zero legitimate occurrences is a measurement of today's tree, not a property of
the rule. `// not-a-path: <reason>` on the offending line or the line above it
records a deliberate exemption; a bare pragma does not suppress. That makes an
unexpected URL or content-type split an auditable six-word exception rather than
pressure to delete the gate. The glob sweep covers files added tomorrow and refuses
a zero-file TypeScript sweep rather than silently claiming protection that did not
run. Use `basename()` or `dirname()` from `node:path` before rejoining a component.
"""

from __future__ import annotations

import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
TYPESCRIPT_GLOBS = ("packages/*/src/**/*.ts", "packages/*/src/**/*.tsx")
MUTATION_CONTROL = ROOT / "packages/client/src/tests/manifest-lock.test.ts"

# `str(` applied to something path-shaped. Deliberately narrow: a broad "no str()"
# rule would fire on every f-string and be switched off within a week.
BAD = re.compile(r"\bstr\(\s*(?:[A-Za-z_][A-Za-z0-9_]*)?(?:path|Path|_dir|file)\w*\s*[).]")

# `Path.relative_to()` returns a Path, and interpolating it into an f-string calls
# str() implicitly -- the same rendering, with no `str(` to match. Only worth
# flagging when the result is COMPARED; in a print it is cosmetic.
IMPLICIT = re.compile(r"relative_to\([^)]*\)\s*(?:==|!=|\bin\b)")
PATH_COMPONENT_CALL = re.compile(r"\.(?:split|lastIndexOf)\s*\(\s*$")
NOT_A_PATH = re.compile(r"//\s*not-a-path:\s*\S")



def code_only(source: str, raw_lines: list[str]) -> list[str]:
    """Blank out comments and string literals, keeping line numbers intact.

    A LINE DESCRIBING THE DEFECT IS NOT THE DEFECT, and this used to be enforced
    with `stripped.startswith("#")` -- which covers one of the two ways a line is
    prose. A DOCSTRING is not a comment, so the module docstring of any script
    explaining `str(Path)` was scanned as code. That fired on
    `check-fixture-line-endings.py`, whose docstring explains why it calls
    `.as_posix()` -- the checker penalising a file for documenting the rule it
    follows.

    `tokenize` is exact where a `startswith` is a guess: COMMENT and STRING tokens
    are blanked, everything else is kept verbatim, so a real call is still matched
    on its own line. On a file that will not tokenize (a syntax error) the raw
    lines are returned rather than skipped -- refusing to scan a broken file would
    make a parse error a way to smuggle a defect past this check.
    """
    blanked = list(raw_lines)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return blanked
    for tok in tokens:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (srow, scol), (erow, ecol) = tok.start, tok.end
        for row in range(srow, erow + 1):
            if row - 1 >= len(blanked):
                break
            line = blanked[row - 1]
            start = scol if row == srow else 0
            end = ecol if row == erow else len(line)
            blanked[row - 1] = line[:start] + " " * (end - start) + line[end:]
    return blanked


def typescript_path_component_calls(source: str) -> list[int]:
    """Return code lines where `'/'` is passed to a path-decomposing method.

    The scanner blanks comments and string/template literals, except it records a
    slash literal only when code directly before it formed `.split(` or
    `.lastIndexOf(`. This keeps prose and unrelated literals out of the policy.
    """
    calls: list[int] = []
    code: list[str] = []
    index = 0
    line = 1
    length = len(source)
    in_template = False
    template_expression_depth = 0

    def blank(character: str) -> None:
        code.append("\n" if character == "\n" else " ")

    while index < length:
        character = source[index]
        following = source[index + 1] if index + 1 < length else ""
        if in_template:
            if character == "`":
                blank(character)
                index += 1
                in_template = False
                continue
            if character == "$" and following == "{":
                blank(character)
                blank(following)
                index += 2
                in_template = False
                template_expression_depth = 1
                continue
            if character == "\n":
                line += 1
            blank(character)
            index += 1
            continue
        if character == "/" and following == "/":
            while index < length and source[index] != "\n":
                blank(source[index])
                index += 1
            continue
        if character == "/" and following == "*":
            blank(character)
            blank(following)
            index += 2
            while index < length:
                if source[index] == "*" and index + 1 < length and source[index + 1] == "/":
                    blank(source[index])
                    blank(source[index + 1])
                    index += 2
                    break
                if source[index] == "\n":
                    line += 1
                blank(source[index])
                index += 1
            continue
        if character == "/" and following not in "/ *":
            previous = next((item for item in reversed(code) if not item.isspace()), "")
            if previous and previous in "=(:,[!&|?":
                in_character_class = False
                blank(character)
                index += 1
                while index < length:
                    current = source[index]
                    if current == "\\" and index + 1 < length:
                        blank(current)
                        blank(source[index + 1])
                        index += 2
                        continue
                    if current == "[":
                        in_character_class = True
                    elif current == "]":
                        in_character_class = False
                    elif current == "/" and not in_character_class:
                        blank(current)
                        index += 1
                        break
                    if current == "\n":
                        line += 1
                    blank(current)
                    index += 1
                continue
        if character == "`":
            blank(character)
            index += 1
            in_template = True
            continue
        if character in "'\"":
            quote = character
            call_line = line
            is_path_component_call = bool(PATH_COMPONENT_CALL.search("".join(code)))
            literal: list[str] = []
            blank(character)
            index += 1
            while index < length:
                current = source[index]
                if current == "\\" and index + 1 < length:
                    literal.extend((current, source[index + 1]))
                    blank(current)
                    blank(source[index + 1])
                    index += 2
                    continue
                if current == quote:
                    blank(current)
                    index += 1
                    break
                literal.append(current)
                if current == "\n":
                    line += 1
                blank(current)
                index += 1
            if is_path_component_call and "".join(literal) == "/":
                calls.append(call_line)
            continue
        if template_expression_depth:
            if character == "{":
                template_expression_depth += 1
            elif character == "}":
                template_expression_depth -= 1
                if template_expression_depth == 0:
                    blank(character)
                    index += 1
                    in_template = True
                    continue
        code.append(character)
        if character == "\n":
            line += 1
        index += 1
    return calls


def is_test_typescript(path: Path) -> bool:
    return "tests" in path.parts or path.name.endswith((".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx"))


def has_not_a_path_pragma(raw_lines: list[str], lineno: int) -> bool:
    return any(NOT_A_PATH.search(raw_lines[candidate - 1]) for candidate in (lineno - 1, lineno) if candidate > 0)


def main() -> int:
    script_files = sorted(SCRIPTS.glob("*.py"))
    if not script_files:
        print("REFUSING: no scripts found to check -- the sweep is broken", file=sys.stderr)
        return 1

    typescript_files = sorted({path for pattern in TYPESCRIPT_GLOBS for path in ROOT.glob(pattern)})
    if not typescript_files:
        print("REFUSING: no TypeScript files found to check -- the sweep is broken", file=sys.stderr)
        return 1
    if MUTATION_CONTROL not in typescript_files or not is_test_typescript(MUTATION_CONTROL):
        print(
            "REFUSING: manifest-lock mutation control must be excluded by design -- "
            "it contains the slash-split regression control this gate must not scan",
            file=sys.stderr,
        )
        return 1

    problems: list[str] = []
    for path in script_files:
        if path.name == Path(__file__).name:
            continue
        source = path.read_text(encoding="utf-8")
        raw_lines = source.splitlines()
        code_lines = code_only(source, raw_lines)
        for lineno, line in enumerate(code_lines, 1):
            stripped = raw_lines[lineno - 1].strip()
            rel = path.relative_to(ROOT).as_posix()
            if BAD.search(line):
                problems.append(
                    f"  {rel}:{lineno}: str() on a path renders backslashes on Windows\n"
                    f"      {stripped}\n"
                    f"      Use .as_posix() for comparison, or os.fspath() when a\n"
                    f"      platform-native string is genuinely wanted."
                )
            elif IMPLICIT.search(line):
                problems.append(
                    f"  {rel}:{lineno}: relative_to() result compared without .as_posix()\n"
                    f"      {stripped}\n"
                    f"      The f-string/comparison renders it platform-natively."
                )

    for path in typescript_files:
        if is_test_typescript(path):
            continue
        source = path.read_text(encoding="utf-8")
        raw_lines = source.splitlines()
        rel = path.relative_to(ROOT).as_posix()
        for lineno in typescript_path_component_calls(source):
            if has_not_a_path_pragma(raw_lines, lineno):
                continue
            stripped = raw_lines[lineno - 1].strip()
            problems.append(
                f"  {rel}:{lineno}: slash-based path component derivation breaks on Windows\n"
                f"      {stripped}\n"
                f"      Use basename() or dirname() from node:path before rejoining a path component.\n"
                f"      Add // not-a-path: <reason> only for a deliberate non-path exemption."
            )

    if problems:
        print(
            "REFUSING: platform-dependent path rendering:\n" + "\n".join(problems),
            file=sys.stderr,
        )
        return 1

    print(f"path rendering: {len(script_files)} script(s), {len(typescript_files)} TypeScript file(s) clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
