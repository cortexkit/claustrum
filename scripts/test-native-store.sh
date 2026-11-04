#!/usr/bin/env bash
# Exercise Linux custody on a disposable session bus and unlocked login keyring.
# A private HOME keeps the lock test away from any operator's real keyring.
set -euo pipefail
# Bash 3.2 can give EXIT traps status 0 after a nounset error. Require explicit
# completion so an unset scalar or empty array cannot turn an abort into success.
finished=0
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v dbus-run-session >/dev/null || { echo 'native store tests require dbus-run-session' >&2; exit 1; }
command -v gnome-keyring-daemon >/dev/null || { echo 'native store tests require gnome-keyring-daemon' >&2; exit 1; }
root=$(mktemp -d)
# gnome-keyring-daemon forks into the background and can still be flushing its
# keyring file under $root/data when dbus-run-session returns, so a bare `rm -rf`
# races it ("Directory not empty"). Stop every process left running with this run's
# private XDG_RUNTIME_DIR, wait until each has exited, and only then remove $root.
# The value is this run's fresh mktemp path, so in practice only processes this run
# started carry it. It is not an OS-enforced boundary, but /proc only shows another
# user's environ to root, so an ordinary run cannot signal another user's daemon.
# A zombie has already closed its files, so it counts as exited: in a container whose
# PID 1 does not reap, it would otherwise never go away.
running() {
  local state
  state=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1) || return 1
  [ -n "$state" ] && [ "$state" != Z ]
}
cleanup() {
  local status=$?
  if [ "$status" -eq 0 ] && [ "${finished:-0}" -ne 1 ]; then
    echo "test-native-store.sh: exited before successful completion" >&2
    status=1
  fi
  local env pid pids=()
  for env in /proc/[0-9]*/environ; do
    pid=${env#/proc/}
    pid=${pid%/environ}
    [ "$pid" = "$$" ] && continue
    if tr '\0' '\n' < "$env" 2>/dev/null | grep -qxF "XDG_RUNTIME_DIR=$root/runtime"; then
      kill "$pid" 2>/dev/null && pids+=("$pid")
    fi
  done
  # The `+` form expands to nothing for an empty array; a bare "${pids[@]}" is an
  # unbound-variable error under `set -u` in bash 3.2, which macOS ships.
  for pid in ${pids[@]+"${pids[@]}"}; do
    for _ in $(seq 50); do running "$pid" || break; sleep 0.1; done
    if running "$pid"; then
      kill -KILL "$pid" 2>/dev/null || true
      for _ in $(seq 50); do running "$pid" || break; sleep 0.1; done
    fi
  done
  rm -rf "$root"
  exit "$status"
}
trap cleanup EXIT
mkdir -m 700 "$root/home" "$root/runtime"
# An explicit CARGO_HOME/RUSTUP_HOME is needed if the caller relied on HOME.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export HOME="$root/home" XDG_RUNTIME_DIR="$root/runtime"
export XDG_DATA_HOME="$root/data" XDG_CONFIG_HOME="$root/config" XDG_CACHE_HOME="$root/cache"
unset GNOME_KEYRING_CONTROL DBUS_SESSION_BUS_ADDRESS
dbus-run-session -- bash -euo pipefail -c '
  printf "ci-test-only-password\n" | gnome-keyring-daemon --unlock --components=secrets
  CK_NATIVE_STORE_TESTS=1 cargo test --locked -p credentials-core --test native_store -- --ignored --nocapture --test-threads=1 --skip secret_service_locked_collection_refuses_without_prompt
  CK_NATIVE_STORE_TESTS=1 CK_NATIVE_STORE_DISPOSABLE_SESSION=1 cargo test --locked -p credentials-core --test native_store secret_service_locked_collection_refuses_without_prompt -- --ignored --exact --nocapture
'
finished=1
