#!/usr/bin/env bash
# Shared by the Windows CI job and the full gate's native Windows runner.
# gate.sh supplies run_check/run_expect, so both callers apply the same checks and the
# same minimum test counts.
# Flip to 1 once offline Windows jobs have a cache of bun.lock packages.
WINDOWS_MOTOR_HAS_OFFLINE_BUN_CACHE=0

windows_ci() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) ;;
    *) fail "Windows CI lane refuses to run on this host" ;;
  esac
  # CI invokes this Bash lane directly rather than through the motor launcher.
  # Preserve native paths on all child argv, including Cargo and Python probes.
  export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
  run_check "Windows setup" python3 scripts/windows-setup.py
  export CARGO_TERM_COLOR=always
  BUN=bun
  local install_args=(--frozen-lockfile)
  local offline=0
  # Only GitHub CI can fetch dependencies. The full gate's Windows runner stays
  # offline even if GitHub's environment is inherited; enabled Bun installs cannot
  # fetch missing packages.
  if [[ "${GITHUB_ACTIONS:-}" != true || "${CK_WINDOWS_GATE_OFFLINE:-}" = 1 ]]; then
    offline=1
    export CARGO_NET_OFFLINE=true
    install_args+=(--offline)
  fi
  if [[ "$offline" = 0 || "$WINDOWS_MOTOR_HAS_OFFLINE_BUN_CACHE" = 1 ]]; then
    run_check "Bun install" "$BUN" install "${install_args[@]}"
    run_check "Bun build" "$BUN" run build
    run_check "Bun typecheck" "$BUN" run typecheck
    run_check "Bun test packages" env XDG_RUNTIME_DIR=/nonexistent CLAUSTRUM_SUBC_CONNECTION=/nonexistent/x.json \
      timeout 1200 "$BUN" test packages/client
  else
    local label reason="Windows jobs have no offline Bun cache yet; GitHub CI runs these"
    for label in "Bun install" "Bun build" "Bun typecheck" "Bun test packages"; do
      windows_unchecked "$label" "$reason"
    done
  fi
  run_check "Inbound contract check" bash scripts/check-inbound-contracts.sh \
    "${CRED_SUBCONSCIOUS_ROOT:-../subconscious}/docs/push-sealed-payload.md"
  run_check "Endpoint hosts" python3 scripts/endpoint-hosts.py
  run_check "Path rendering" python3 scripts/check-path-rendering.py
  run_check "Outside path deps" python3 scripts/check-outside-path-deps.py
  run_check "Check development binary execution names" python3 scripts/check-ckdev-execution.py
  run_check "Design doc status claims" python3 scripts/check-doc-status.py
  run_expect 1 "Windows Credential Manager round trips" env CK_NATIVE_STORE_TESTS=1 \
    cargo test --locked --workspace --test native_store -- --ignored --nocapture --test-threads=1
  windows_git_check "Fixture line endings" python3 scripts/check-fixture-line-endings.py
  run_check "Threshold boundary controls" python3 scripts/threshold-controls.py
  run_check "Format check" windows_format
  run_check "Clippy" cargo clippy --locked --workspace --all-targets -- -D warnings
  run_check "Clippy (conformance seams)" cargo clippy --locked --workspace --all-targets \
    --features kill9-test-seam,rotate-test-seam,login-test-seam,migration-tools,import-prompt-seam,windows-runtime-test-seam -- -D warnings
  run_expect 1 "Test" cargo test --locked --workspace --all-targets
  run_check "Client without transport" windows_client_without_transport
  run_expect 4 "Windows operator filesystem workflows" timeout 600 \
    cargo test --locked -p credentials-module --features windows-runtime-test-seam \
    --test windows_runtime -- --nocapture --test-threads=1
  # The kill-9, rotation and login targets are Unix-gated; Windows runs the three
  # migration-tool tests in key_verify_takes_nothing from this same CI invocation.
  run_expect 3 "Security-conformance suite (crash-safety seams)" \
    cargo test --locked --workspace --features credentials-core/test-support,credentials-core/kill9-test-seam,credentials-core/rotate-test-seam,credentials-core/login-test-seam,credentials-core/migration-tools \
    --test kill9_mid_refresh --test rotate_crash_cut --test login_crash_cut --test key_verify_takes_nothing
}

windows_git_check() {
  local label="$1"; shift
  if [[ -e .git ]] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    run_check "$label" "$@"
  else
    windows_unchecked "$label" "Git metadata unavailable in this Windows checkout (.git missing or unusable)"
  fi
}

windows_unchecked() {
  local label="$1" reason="$2"
  printf '\n=== %s: UNCHECKED ===\nSKIPPING %s: %s\n' "$label" "$label" "$reason"
  GATE_UNCHECKED="${GATE_UNCHECKED:-}$label ($reason) "
  record_arm "$label" 0 unchecked
}

windows_format() {
  local pkgs
  pkgs=$(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(" ".join("-p "+p["name"] for p in json.load(sys.stdin)["packages"]))') || return
  test -n "$pkgs" || { echo "empty format scope; refusing" >&2; return 1; }
  echo "format scope: $pkgs"
  # shellcheck disable=SC2086
  cargo fmt $pkgs -- --check
}

windows_client_without_transport() {
  cargo build --locked -p cortexkit-claustrum-client --no-default-features || return
  run_expect 50 "Client without transport tests" \
    cargo test --locked -p cortexkit-claustrum-client --no-default-features
  local tree forbidden
  tree="$(cargo tree --locked -p cortexkit-claustrum-client --no-default-features -e normal --prefix none --color never)" || return
  if forbidden="$(printf '%s\n' "$tree" | grep -E '^(subc-transport|subc-os|tokio) v')"; then
    echo "client_no_default_features_excludes_transport: FAILED" >&2
    printf '%s\n' "$forbidden" >&2
    return 1
  fi
  echo "client_no_default_features_excludes_transport: passed (3 forbidden packages absent)"
}
