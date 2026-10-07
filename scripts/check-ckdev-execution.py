#!/usr/bin/env python3
"""Fence executable names, not production names used as data.

Rust/TS calls are balanced expressions inside individual statements. Only the
argument of that call (or its current binding) can authorize it; a wrapped call
on the previous line cannot excuse a direct spawn. Shell commands use command
positions, with bindings tracked separately from artifact/signing arguments.
This is a source fence, not a full compiler: new dynamic spawn factories must
use the shared helper explicitly rather than rely on unreviewed data flow.
"""
import ast
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CK = re.compile(r"(?:^|[/_])ck-[\w-]+")
# Comments and string literals are tokens, so fixture strings aren't code.
TOKEN_PATTERN = r'//[^\n]*|/\*[\s\S]*?\*/|r(\#+)"[\s\S]*?"\1|r"[^"]*"|"(?:\\[\s\S]|[^"\\])*"|{single}|[A-Za-z_][\w]*|::|=>|[^\s]'


def tokens(source, typescript=False):
    single = r"'(?:\\[\s\S]|[^'\\])*'" if typescript else r"'(?:\\[^\n]+?|[^'\\\n])'"
    matcher = re.compile(TOKEN_PATTERN.replace('{single}', single))
    return [m.group() for m in matcher.finditer(source)
            if not m.group().startswith(('//', '/*'))]


def argument(ts, opening):
    depth = 0
    end = opening
    for end in range(opening, len(ts)):
        if ts[end] in ('(', '[', '{'):
            depth += 1
        elif ts[end] in (')', ']', '}'):
            depth -= 1
            if not depth:
                return ts[opening + 1:end], end
    return [], end


def safe_expr(ts, bindings):
    expr = ''.join(ts).strip('&')
    if expr in bindings:
        return bindings[expr]
    if re.match(r'^(?:\w+::)*ckdev_(?:binary|command)\(', expr):
        return True
    # Bare system executables and non-fleet Cargo helper binaries are not ck-*.
    if len(ts) == 1 and ts[0].startswith(('"', "'")):
        return CK.search(ts[0][1:-1]) is None
    if ts[:3] == ['env', '!', '(']:
        return (any('CARGO_BIN_EXE_' in t or t == '"CARGO"' for t in ts)
                and not any('CARGO_BIN_EXE_ck-' in t for t in ts))
    # Crash-cut helpers have underscore names, not the fleet's ck- prefix.
    if expr.startswith('common::warmed('):
        return not any('CARGO_BIN_EXE_ck-' in t for t in ts)
    return False


def first_argument(ts):
    depth = 0
    for i, token in enumerate(ts):
        if token in ('(', '[', '{'):
            depth += 1
        elif token in (')', ']', '}'):
            depth -= 1
        elif token == ',' and depth == 0:
            return ts[:i]
    return ts


def code_violations(source, typescript=False):
    ts = tokens(source, typescript)
    bindings = {}
    bad = []
    start = 0
    for end in range(len(ts) + 1):
        if end < len(ts) and ts[end] != ';':
            continue
        statement = ts[start:end]
        if 'fn' in statement or 'function' in statement:
            bindings.clear()
        # Inspect each constructor, not the surrounding statement's helper text.
        for i, token in enumerate(statement):
            if token == 'new' and statement[max(0, i-2):i] == ['Command', '::'] and statement[i+1:i+2] == ['(']:
                arg, _ = argument(statement, i+1)
                if not safe_expr(arg, bindings):
                    bad.append('Command::new(' + ''.join(arg) + ')')
            if typescript and token in ('spawn', 'spawnSync', 'execFile', 'execFileSync') and statement[i+1:i+2] == ['(']:
                arg, _ = argument(statement, i+1)
                # For TS arrays and argument lists only argv[0] is executable.
                executable = first_argument(arg[1:-1] if arg[:1] == ['['] else arg)
                if executable and not safe_expr(executable, bindings):
                    bad.append(token + '(' + ''.join(executable) + ')')
        # Track the last assignment, with no proximity-based authorization.
        for i, token in enumerate(statement):
            if token == '=' and i and statement[i-1].isidentifier():
                bindings[statement[i-1]] = safe_expr(statement[i+1:], bindings)
        start = end + 1
    return bad


# Executable words at command/substitution/pipeline positions. Shell assignments
# and system-command arguments are data, even when they name production artifacts.
def shell_words(line):
    """Keep quoted arguments opaque, but recurse into executable substitutions."""
    words, substitutions = [], []
    i = 0
    word = ''
    quote = None
    while i < len(line):
        char = line[i]
        if quote != "'" and line[i:i+2] == '$(':
            start = i + 2
            depth, inner_quote = 1, None
            i = start
            while i < len(line) and depth:
                c = line[i]
                if c == '\\':
                    i += 2
                    continue
                if inner_quote:
                    if c == inner_quote:
                        inner_quote = None
                elif c in ('"', "'"):
                    inner_quote = c
                elif c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                i += 1
            substitutions.append(line[start:i-1])
            word += line[start-2:i]
            continue
        if char == '\\' and i + 1 < len(line):
            word += line[i:i+2]
            i += 2
            continue
        if quote:
            word += char
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
            word += char
        elif char.isspace() or char in ';|&()':
            if word:
                words.append(word)
                word = ''
            if not char.isspace():
                words.append(char)
        elif char == '#' and not word:
            break
        else:
            word += char
        i += 1
    if word:
        words.append(word)
    return words, substitutions


PRODUCTION = re.compile(r'^(?:\$HOME|\$\{HOME\}|~)/\.local/(?:share/cortexkit/(?:bin|staging)(?:/|$)|bin/ck$)')


def shell_violations(source, bindings=None):
    bindings = {} if bindings is None else bindings
    bad = []
    for raw in source.replace('\\\n', ' ').splitlines():
        words, substitutions = shell_words(raw.strip())
        for sub in substitutions:
            bad.extend(shell_violations(sub, bindings))
        loop = re.search(r'\bfor\s+(\w+)\s+in\s+([^;]+)', raw)
        if loop:
            bindings[loop[1]] = 'ck' if CK.search(loop[2]) else 'unknown'
        command = True
        for word in words:
            if word in (';', '|', '&', '(', ')', 'then', 'do', 'if', 'elif', '!'):
                command = True
                continue
            assignment = re.match(r'^([A-Za-z_]\w*)=(.*)', word)
            if command and assignment:
                name, value = assignment.groups()
                value = value.strip('"\'')
                bindings[name] = ('dev' if re.match(r'^\$\(\s*ckdev_binary\s', value)
                                  else 'prod' if PRODUCTION.match(value)
                                  else 'ck' if CK.search(value) else 'unknown')
                continue
            if not command:
                continue
            command = False
            word = word.strip('"\'')
            if word.startswith('${{'):
                continue
            variables = re.findall(r'\$\{?([A-Za-z_]\w*)', word)
            state = bindings.get(variables[0], 'unknown') if variables else 'unknown'
            dynamic_path = word.startswith('$') and ('/' in word and re.search(r'/\$\{?\w+\}?$', word) or state == 'ck')
            if CK.search(word) or dynamic_path:
                if state not in ('dev', 'prod') and not PRODUCTION.match(word):
                    bad.append(word)
    return bad


def python_violations(source):
    bad = []
    bindings = {}
    def executable(node):
        if isinstance(node, ast.Name):
            return bindings.get(node.id, '')
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            return executable(node.elts[0])
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            return executable(node.left) + '/' + executable(node.right)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('Path', 'str') and node.args:
            return executable(node.args[0])
        return ''
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = executable(node.value)
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in ('run', 'Popen', 'call', 'check_call', 'check_output', 'execv', 'execve'):
            continue
        if CK.search(executable(node.args[0])):
            bad.append(ast.unparse(node))
    return bad


def violations(path, source):
    if path.suffix in ('.rs', '.ts', '.tsx', '.js'):
        return code_violations(source, path.suffix != '.rs')
    if path.suffix in ('.sh', '.yml', '.yaml'):
        if path.suffix in ('.yml', '.yaml'):
            source = re.sub(r'(?m)^\s*run:\s*', '', source)
        return shell_violations(source)
    if path.suffix == '.py':
        return python_violations(source)
    return []


def source_paths(root):
    scopes = ('crates/credentials-module/tests', 'crates/credentials-core/tests',
              'crates/credentials-module/examples', 'crates/credentials-core/examples',
              'crates/credentials-core/src/bin', 'scripts',
              'packages/client/src/tests', 'packages/opencode/src/tests', '.github/workflows')
    return sorted({p for scope in scopes for p in (root / scope).rglob('*')
                   if p.is_file() and p.suffix in ('.rs', '.ts', '.tsx', '.js', '.sh', '.py', '.yml', '.yaml')})


def scan(root):
    paths = source_paths(root)
    bad = [f'{p.relative_to(root).as_posix()}: {spawn}' for p in paths
           for spawn in violations(p, p.read_text(encoding='utf-8'))]
    return paths, bad


def main():
    from lib.scan_self_test import check
    control = check('test_ckdev_matcher_has_statement_local_controls')
    if control:
        return control
    paths, bad = scan(ROOT)
    if bad:
        print('REFUSING: development execution bypasses ckdev helper:\n' + '\n'.join(bad), file=sys.stderr)
        return 1
    print(f'ckdev execution fence: {len(paths)} sources checked')
    return 0


if __name__ == '__main__':
    sys.exit(main())
