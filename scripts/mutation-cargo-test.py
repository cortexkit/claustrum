#!/usr/bin/env python3
"""Run one feature-gated core guard with separate build and test deadlines.

ck-mutate 0.7.0 accepts target selectors, not feature flags, and its package-wide
name listing drops the selector. Core integration tests require test-support, so
command rows explicitly build the selected target before running the exact test.
A build error or timeout must not look like a failing test to the command runner.
"""
import argparse
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--features", default="test-support")
    parser.add_argument("test")
    args = parser.parse_args()
    cargo = ["cargo", "test", "--locked", "-p", "credentials-core",
             *args.target.split(), "--features", args.features]
    try:
        build = subprocess.run([*cargo, "--no-run"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=3600)
        if build.returncode:
            sys.stderr.buffer.write(build.stdout)
            return 126  # infrastructure refusal, never a test catch
        test = subprocess.run([*cargo, args.test, "--", "--exact"],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=600)
    except subprocess.TimeoutExpired:
        # Do not emit a partial test count: an interrupted run proves no catch.
        print("mutation guard exceeded its build (3600s) or test (600s) deadline",
              file=sys.stderr)
        return 126
    except OSError as error:
        print(f"could not invoke cargo: {error}", file=sys.stderr)
        return 127
    sys.stdout.buffer.write(test.stdout)
    return test.returncode


if __name__ == "__main__":
    sys.exit(main())
