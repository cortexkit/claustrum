#!/usr/bin/env python3
"""Sample executable paths during a genuine daemon suite, retaining raw evidence.

Usage: python3 scripts/measure-ckdev-processes.py REPORT.json -- cargo test ...
The test command must succeed and ckdev-subc/ckdev-claustrum must both be seen;
a skipped suite or a sampler that sees nothing cannot count as a measurement.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def snapshot():
    return subprocess.check_output(['ps', '-axo', 'pid=,comm='], text=True)


def rows(text):
    return [(int(parts[0]), parts[1]) for line in text.splitlines()
            if len(parts := line.strip().split(None, 1)) == 2 and parts[0].isdigit()]


def forbidden(comm):
    path = Path(comm)
    if not path.name.startswith('ck-'):
        return False
    home = Path.home()
    return not any(path.is_relative_to(folder) for folder in (
        home / '.local/share/cortexkit/bin', home / '.local/share/cortexkit/staging'))


def main():
    report = Path(sys.argv[1])
    command = sys.argv[3:]
    if sys.argv[2:3] != ['--'] or not command:
        sys.exit('usage: measure-ckdev-processes.py REPORT.json -- COMMAND ...')
    samples = []
    baseline = snapshot()
    report.parent.mkdir(parents=True, exist_ok=True)
    # Put every test scratch executable beneath this worktree. This also makes
    # ownership measurable without confusing concurrent workers' temp processes
    # with this run. Keep the directory alive until the post-run sample.
    scratch = tempfile.TemporaryDirectory(prefix='ckdev-measure-', dir=report.parent.resolve())
    env = dict(os.environ, TMPDIR=scratch.name, TMP=scratch.name, TEMP=scratch.name)
    process = subprocess.Popen(command, env=env)
    next_sample = time.monotonic()
    while True:
        samples.append({'time': time.time(), 'ps': snapshot()})
        if process.poll() is not None:
            break
        # This is the measurement cadence, not waiting for a background tool task.
        next_sample += 0.5
        time.sleep(max(0, next_sample - time.monotonic()))
    after = snapshot()
    queries = {}
    for name in ('ck-subc', 'ck-claustrum', 'ck-auth', 'ckdev-subc', 'ckdev-claustrum', 'ckdev-auth'):
        probe = subprocess.run(['pgrep', '-a', '-x', name], capture_output=True, text=True)
        if probe.returncode not in (0, 1):
            sys.exit(f'pgrep failed: {probe.stderr}')
        queries[name] = {'returncode': probe.returncode, 'stdout': probe.stdout}
    observed = [pair for sample in samples for pair in rows(sample['ps'])]
    root = Path.cwd().resolve()
    bad = sorted({comm for _, comm in observed if forbidden(comm) and Path(comm).is_relative_to(root)})
    external = sorted({comm for _, comm in observed if forbidden(comm) and not Path(comm).is_relative_to(root)})
    dev = sorted({comm for _, comm in observed if Path(comm).name.startswith('ckdev-') and Path(comm).is_relative_to(root)})
    # Only this run's observed development PIDs/paths are ours; don't assert that
    # other workers' ckdev processes must be absent on a shared machine.
    residual = [pair for pair in rows(after) if Path(pair[1]).is_relative_to(Path(scratch.name))]
    data = {'command': command, 'interval_s': 0.5, 'exit_code': process.returncode,
            'baseline': baseline, 'samples': samples, 'after': after, 'pgrep_after': queries,
            'scope': os.fspath(root), 'test_scratch': scratch.name,
            'forbidden': bad, 'development_paths': dev, 'residual': residual,
            'external_violations': [{'path': comm, 'samples': sum(
                any(path == comm for _, path in rows(sample['ps'])) for sample in samples)} for comm in external]}
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(data, indent=2))
    scratch.cleanup()
    seen = {Path(comm).name for comm in dev}
    print(f'process measurement: {len(samples)} samples, {len(dev)} development paths, '
          f'{len(bad)} forbidden ck-* paths, {len(residual)} residual test processes; report={os.fspath(report)}')
    return int(process.returncode != 0 or bool(bad) or bool(residual)
               or not {'ckdev-subc', 'ckdev-claustrum'}.issubset(seen))


if __name__ == '__main__':
    sys.exit(main())
