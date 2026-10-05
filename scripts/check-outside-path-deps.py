#!/usr/bin/env python3
"""Refuse Cargo path packages outside the repository, including patched crates."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

VIOLATION = 1
CHECK_ERROR = 2
ROOT = Path(__file__).resolve().parents[1]


def check(root):
    """Read only Cargo's stdout: progress and lock-wait messages use stderr."""
    root = root.resolve()
    try:
        result = subprocess.run(
            ['cargo', 'metadata', '--locked', '--format-version', '1'],
            cwd=root, capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise ValueError(f'cargo metadata exited {result.returncode}: {result.stderr.strip()}')
        packages = json.loads(result.stdout)['packages']
        if not isinstance(packages, list):
            raise ValueError('metadata packages is not a list')
        paths = []
        for package in packages:
            if package['source'] is None:
                paths.append((package['name'], Path(package['manifest_path']).resolve()))
        if not paths:
            raise ValueError('metadata contained zero path packages')
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'outside path deps: CHECK ERROR: {error}', file=sys.stderr)
        return CHECK_ERROR
    print(f'outside path deps: checked {len(paths)} path packages')
    outside = [(name, path) for name, path in paths if not path.is_relative_to(root)]
    for name, path in outside:
        print(f'outside path deps: REFUSING {name}: {path}', file=sys.stderr)
    return VIOLATION if outside else 0


def self_test():
    """Exercise Cargo itself with both a planted outside dependency and a clean graph."""
    with tempfile.TemporaryDirectory(prefix='claustrum-path-check-') as directory:
        base = Path(directory)
        root = base / 'workspace'
        outside = base / 'outside'
        for path, name in ((root, 'inside-control'), (outside, 'outside-control')):
            (path / 'src').mkdir(parents=True)
            (path / 'src/lib.rs').write_text('')
            (path / 'Cargo.toml').write_text(
                f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n'
            )
        manifest = root / 'Cargo.toml'
        clean = manifest.read_text()
        for planted in (True, False):
            manifest.write_text(clean + ('[dependencies]\noutside-control = { path = "../outside" }\n' if planted else ''))
            try:
                lock = subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root,
                                      capture_output=True, text=True, check=False)
                if lock.returncode:
                    raise ValueError(lock.stderr.strip())
                result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                         '--repo-root', str(root), '--skip-self-test'],
                                        capture_output=True, text=True, check=False)
            except (OSError, ValueError) as error:
                print(f'outside path deps: SELF-TEST ERROR: {error}', file=sys.stderr)
                return CHECK_ERROR
            expected = VIOLATION if planted else 0
            if result.returncode != expected or (planted and 'REFUSING outside-control:' not in result.stderr):
                print(f'outside path deps: SELF-TEST FAILED ({"planted" if planted else "clean"}): '
                      f'exit {result.returncode}\n{result.stdout}{result.stderr}', file=sys.stderr)
                return CHECK_ERROR
    print('outside path deps: self-test passed (2 controls: planted refusal, clean pass)')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--skip-self-test', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.skip_self_test:
        result = self_test()
        if result:
            return result
    return check(args.repo_root)


if __name__ == '__main__':
    sys.exit(main())
