#!/usr/bin/env python3
"""Full gate: cheap refusals first, then native Linux, Windows and host lanes."""
import platform
import sys
from gate_runtime import Gate, remote_command


def main():
    gate = Gate()
    error = None
    try:
        gate.job("preflight", ["bash", "scripts/gate.sh", "--lane", "preflight"])
        jobs = [("Linux Rust", remote_command("full"), True),
                ("Windows CI", remote_command("windows"), "Windows"),
                ("TypeScript", ["bash", "scripts/gate.sh", "--lane", "typescript"], False)]
        if platform.system() == "Darwin":
            jobs.append(("host release artifact", ["bash", "scripts/gate.sh", "--lane", "release"], False))
        gate.parallel(jobs)
    except RuntimeError as caught:
        error = str(caught)
    finally:
        gate.summary()
    if error:
        print(f"GATE FAILED: {error}", file=sys.stderr)
        return 1
    print("NOT covered: macOS Keychain round trips, deployment or release signing.")
    if gate.unchecked:
        print("GATE PASSED WITH UNCHECKED ARMS -- " + "; ".join(gate.unchecked))
    else:
        print("GATE PASSED -- Linux, native Windows CI and host checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
