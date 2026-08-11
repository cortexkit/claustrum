#!/usr/bin/env bash
# The full pre-release gate, as one command.
#
# WHY THIS EXISTS AS A SCRIPT AND NOT A LIST IN THE RUNBOOK: every safety in this
# repo is strongest where a mistake would be caught anyway and weakest where one
# person is working alone at speed. CI passes the feature flags and sets the
# anti-masking switch, so CI cannot be fooled. A hand-composed local command can be,
# and silently -- a suite whose feature is missing prints "running 0 tests ... ok",
# and the end-to-end arms skip to a pass unless the switch is set.
#
# So the invocations below are not a convenience. Typing most of them, or dropping
# one --features argument, produces a green run that proves less than it appears to,
# in the exact loop where nobody is reviewing.
#
# THE SET MUST MATCH CI. Every arm here corresponds to a step in
# .github/workflows/ci.yml; when a step is added there, add it here. A local gate
# that covers a subset is worse than none, because it earns trust and then lets
# through exactly what it was trusted to catch.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { printf '\nGATE FAILED: %s\n' "$1" >&2; exit 1; }

# Run a command that produces no test counts, failing the gate if it does.
run_check() {
  local label="$1"; shift
  printf '\n=== %s ===\n' "$label"
  local out
  out="$("$@" 2>&1)" || { printf '%s\n' "$out"; fail "$label"; }
  printf '  ok\n'
}

# FORMAT AND LINT COME FIRST, because they are what CI fails on while a local run
# of the test arms alone passes.
#
# This gate was built to stop a hand-composed command proving less than it appears
# to -- and then omitted two of the checks CI runs, so "GATE PASSED" locally was
# followed by a red build on formatting. A gate that covers a subset of CI teaches
# people to trust it and then contradicts them, which is worse than no gate: it
# converts a fast local failure into a slow remote one.
#
# The clippy arms are run BOTH ways for the same reason the test arms are: code
# behind a feature flag is not compiled without it, so a lint error inside a
# crash-cut seam is invisible to the default invocation.
run_check "format" cargo fmt --all -- --check
run_check "clippy" \
  cargo clippy --locked --workspace --all-targets -- -D warnings
run_check "clippy (seam features)" \
  cargo clippy --locked --workspace --all-targets \
    --features kill9-test-seam,rotate-test-seam,login-test-seam,migration-tools -- -D warnings

# Run a cargo invocation and require at least `min` tests to have PASSED, and that
# no arm announced a skip.
#
# THE COUNT IS NECESSARY: `test result: ok` survives a suite that ran nothing, since
# a file gated behind an absent feature is not compiled and reports "running 0 tests".
#
# THE COUNT IS NOT SUFFICIENT: an arm that skips still reports itself as passed, so
# eight skipped e2e arms count as eight. Only the skip notice distinguishes them --
# and cargo CAPTURES test output unless --nocapture is passed, so callers that can
# skip must pass it or this check reads an empty stream and finds nothing. Measured:
# without --nocapture the notice is invisible here, with it all eight appear.
run_expect() {
  local min="$1" label="$2"; shift 2
  printf '\n=== %s ===\n' "$label"
  local out
  out="$("$@" 2>&1)" || { printf '%s\n' "$out"; fail "$label"; }
  printf '%s\n' "$out" | grep -E '^test result:' || true
  if printf '%s\n' "$out" | grep -q 'SKIPPING'; then
    printf '%s\n' "$out" | grep 'SKIPPING' >&2
    fail "$label skipped an arm — it reported ok without running"
  fi
  local passed
  passed="$(printf '%s\n' "$out" | grep -oE '^test result: ok\. [0-9]+ passed' \
    | grep -oE '[0-9]+' | paste -sd+ - | bc 2>/dev/null || echo 0)"
  [ -n "$passed" ] || passed=0
  if [ "$passed" -lt "$min" ]; then
    fail "$label ran $passed tests, expected at least $min — a suite that shrank is indistinguishable from one that passed"
  fi
}

# The floor is the MEASURED total, not a round number below it. A floor with slack
# is a check that tolerates exactly the defect it exists to catch: tests vanish one
# at a time (a misplaced #[test] attribute silently unregisters the function that
# follows it), and any gap between the floor and the real count is how many can go
# before anyone is told. Measured 314 across the workspace's suites at the time of
# writing; an earlier floor of 200 left a third of them free to disappear.
#
# Raise this when tests are added. A failure here is normally that, not a defect --
# but it should be a deliberate edit rather than a number nobody revisits.
run_expect 314 "workspace unit + integration" \
  cargo test --locked --workspace

# Two independent defences, because each catches what the other misses:
#   - CRED_REQUIRE_DAEMON=1 turns an unreachable sibling ck-subc into a failure at
#     source, before any arm can skip.
#   - --nocapture surfaces the skip notice so run_expect's check can see it, in case
#     an arm ever skips for a reason the switch does not cover.
# The count covers neither: skipped arms still report as passed.
CRED_REQUIRE_DAEMON=1 run_expect 8 "real-daemon e2e (ship gate)" \
  cargo test --locked -p credentials-module --test real_daemon_e2e -- --ignored --nocapture

# The crash-safety proofs are gated at FILE level: without the feature the file is
# not compiled and the run reports "running 0 tests ... ok". Nothing inside a file
# that does not exist can warn, so the counts are the only available instrument.
run_expect 1 "kill-9 mid-refresh crash cut" \
  cargo test --locked -p credentials-core --features kill9-test-seam --test kill9_mid_refresh
run_expect 4 "master-key rotation crash cuts" \
  cargo test --locked -p credentials-core --features rotate-test-seam --test rotate_crash_cut
run_expect 2 "login crash cut" \
  cargo test --locked -p credentials-core --features login-test-seam --test login_crash_cut

printf '\nGATE PASSED\n'
