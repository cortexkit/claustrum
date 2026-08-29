#!/usr/bin/env bash
# Prove that the load-bearing tests still reject four known bad implementations.
#
# WHY THIS RUNS IN THE RELEASE PATH, NOT scripts/gate.sh: measured on this machine,
# one mutation in a throwaway worktree with a shared CARGO_TARGET_DIR costs about
# 31 seconds because the mutated crate must rebuild. Four arms therefore cost about
# two minutes. gate.sh currently takes 100–150 seconds and runs on every push, so
# putting this check there would roughly double the push loop to catch a decay event
# of unknown frequency. Releases happen a few times a day, and that is the moment
# this signal is useful; the extra two minutes are free there. Keeping it out of the
# gate also preserves gate.sh's arm-count parity with CI.
#
# SAFETY: the live worktree is never mutated. Each arm is applied, tested, restored,
# and removed inside its own detached worktree. The EXIT trap removes a worktree on
# every failure and interrupt path, including a failed `git worktree add`.

set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$(pwd -P)"
TARGET_DIR="$ROOT/target"
# Path dependencies resolve relative to the repository checkout, so place the
# temporary worktree beside that checkout rather than under /tmp. This keeps the
# sibling repositories (../commons and ../subconscious) addressable in Cargo.toml.
COMMON_DIR="$(git rev-parse --git-common-dir)"
case "$COMMON_DIR" in
  /*) ;;
  *) COMMON_DIR="$ROOT/$COMMON_DIR" ;;
esac
MAIN_ROOT="$(cd "$(dirname "$COMMON_DIR")" && pwd -P)"
WORKTREE=""

fail() {
  printf 'MUTATION CHECK FAILED: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ -n "$WORKTREE" ]; then
    local path="$WORKTREE"
    WORKTREE=""
    if ! git worktree remove --force "$path" >/dev/null 2>&1; then
      # A failed `git worktree add` can leave only the empty temporary directory.
      # Remove that directory as a last resort, but never fall back to the live tree.
      if ! rm -rf "$path"; then
        printf 'MUTATION CHECK FAILED: could not remove throwaway worktree %s\n' "$path" >&2
        status=1
      fi
    fi
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

replace_exact() {
  local file="$1"
  local old="$2"
  local new="$3"
  python3 - "$file" "$old" "$new" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text()
count = text.count(old)
if count != 1:
    print(
        f"expected one mutation target in {path}, found {count}; refusing an unmeasured arm",
        file=sys.stderr,
    )
    raise SystemExit(1)
path.write_text(text.replace(old, new, 1))
PY
}

run_arm() {
  local arm="$1"
  local label=""
  local source=""
  local expected=""
  local cargo_args=()

  case "$arm" in
    1)
      label="grant listing keeps read and sign rows separate"
      source="crates/credentials-core/src/store.rs"
      expected="grants_keep_read_and_sign_rows_separate_and_sort_by_prefix_then_operation"
      cargo_args=("-p" "credentials-module" "--test" "cli_admin")
      ;;
    2)
      label="stale reports reach invalid-grant terminal state"
      source="crates/credentials-core/src/engine.rs"
      expected="report_stale_then_invalid_grant_latches_needs_reauth"
      cargo_args=("-p" "credentials-core" "--lib")
      ;;
    3)
      label="scoped get refuses signing-key private material"
      source="crates/credentials-module/src/read_surface.rs"
      expected="scoped_get_reveals_signing_kind_only_after_read_grant"
      cargo_args=("-p" "credentials-module" "--bin" "ck-claustrum")
      ;;
    4)
      label="status wire key changes require announcement"
      source="crates/credentials-module/src/read_surface.rs"
      expected="the_status_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement"
      cargo_args=("-p" "credentials-module" "--bin" "ck-claustrum")
      ;;
    *)
      fail "unknown arm $arm"
      ;;
  esac

  printf '\n=== arm %s: %s ===\n' "$arm" "$label"
  WORKTREE="$(mktemp -d "$MAIN_ROOT.mutation.XXXXXX")"
  if ! git worktree add -q --detach "$WORKTREE" HEAD; then
    printf 'REFUSING: could not create throwaway worktree for arm %s; the live tree was not used.\n' "$arm" >&2
    exit 1
  fi

  (
    cd "$WORKTREE"

    case "$arm" in
      1)
        replace_exact "$source" \
          '                    "SELECT principal_kind, principal_id, credential_prefix, operation, created_at_ms \
                     FROM read_grants \
                     ORDER BY principal_kind, principal_id, credential_prefix, operation",' \
          '                    "SELECT principal_kind, principal_id, credential_prefix, operation, created_at_ms \
                     FROM read_grants \
                     GROUP BY credential_prefix \
                     ORDER BY principal_kind, principal_id, credential_prefix, operation",'
        ;;
      2)
        # Without this stale marker forcing a refresh, the named test never reaches the
        # invalid_grant branch that must latch NeedsReauth.
        replace_exact "$source" \
          '        let wants_refresh = force_refresh || stale_pending || self.is_stale(&initial, min_ttl_ms);' \
          '        let wants_refresh = force_refresh || self.is_stale(&initial, min_ttl_ms);'
        ;;
      3)
        replace_exact "$source" \
          '        match self.engine.get(&params.credential_id, None, false).await {
            Ok(record) => {
                if record.kind == credentials_core::record::CredentialKind::SigningKey {' \
          '        match self.engine.get(&params.credential_id, None, false).await {
            Ok(record) => {
                if false {'
        ;;
      4)
        replace_exact "$source" \
          '    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_pending: Option<bool>,' \
          '    #[serde(rename = "stalePending")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_pending: Option<bool>,'
        ;;
    esac

    # A non-matching replacement is UNMEASURED. Show the diff and refuse it before
    # compilation so "the test did not fail" cannot hide "the mutant never applied".
    if git diff --quiet -- "$source"; then
      fail "arm $arm mutation did not apply to $source"
    fi
    git diff -- "$source"

    local compile_output
    if compile_output="$(
      CARGO_TERM_COLOR=never CARGO_TARGET_DIR="$TARGET_DIR" \
        cargo test --locked "${cargo_args[@]}" --no-run 2>&1
    )"; then
      printf '  mutant compiled\n'
    else
      printf '%s\n' "$compile_output" >&2
      fail "arm $arm mutant did not compile; no test verdict is measurable"
    fi

    local red_output
    if red_output="$(
      CARGO_TERM_COLOR=never CARGO_TARGET_DIR="$TARGET_DIR" \
        cargo test --locked "${cargo_args[@]}" -- "$expected" --nocapture 2>&1
    )"; then
      printf '%s\n' "$red_output" >&2
      fail "arm $arm expected $expected to redden, but it passed"
    fi

    local failed_count
    failed_count="$(printf '%s\n' "$red_output" | grep -Ec '^test .* \.\.\. FAILED$' || true)"
    if [ "$failed_count" -ne 1 ]; then
      printf '%s\n' "$red_output" >&2
      fail "arm $arm reddened more than one test instead of only $expected"
    fi
    local red_line
    red_line="$(printf '%s\n' "$red_output" | grep -E '^test .* \.\.\. FAILED$')"
    local red_name
    red_name="$(printf '%s\n' "$red_line" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/')"
    case "$red_name" in
      "$expected"|*::"$expected") ;;
      *)
        printf '%s\n' "$red_output" >&2
        fail "arm $arm reddened $red_name, not the named test $expected"
        ;;
    esac
    printf '  reddened: %s\n' "$red_line"

    git checkout -- "$source"
    if ! git diff --quiet -- "$source"; then
      fail "arm $arm could not restore $source"
    fi

    local green_output
    if green_output="$(
      CARGO_TERM_COLOR=never CARGO_TARGET_DIR="$TARGET_DIR" \
        cargo test --locked "${cargo_args[@]}" -- "$expected" --nocapture 2>&1
    )"; then
      :
    else
      printf '%s\n' "$green_output" >&2
      fail "arm $arm did not return green after restoring $source"
    fi

    local green_count
    green_count="$(printf '%s\n' "$green_output" | grep -Ec '^test .* \.\.\. ok$' || true)"
    if [ "$green_count" -ne 1 ]; then
      printf '%s\n' "$green_output" >&2
      fail "arm $arm restored run did not report exactly one passing test $expected"
    fi
    local green_line
    green_line="$(printf '%s\n' "$green_output" | grep -E '^test .* \.\.\. ok$')"
    local green_name
    green_name="$(printf '%s\n' "$green_line" | sed -E 's/^test (.*) \.\.\. ok$/\1/')"
    case "$green_name" in
      "$expected"|*::"$expected") ;;
      *)
        printf '%s\n' "$green_output" >&2
        fail "arm $arm restored run reported $green_name, not the named test $expected"
        ;;
    esac
    printf '  restored and green: %s\n' "$green_line"
  )

  if ! git worktree remove --force "$WORKTREE"; then
    fail "could not remove throwaway worktree for arm $arm"
  fi
  WORKTREE=""
  printf '  outcome: arm %s passed (compiled, named test reddened, restored, named test green)\n' "$arm"
}

run_arm 1
run_arm 2
run_arm 3
run_arm 4

printf '\nMUTATION CHECK PASSED -- all four named tests rejected their known mutants\n'
