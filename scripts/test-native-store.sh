#!/usr/bin/env bash
# Exercise Linux custody on a disposable session bus and unlocked login keyring.
# A private HOME keeps the lock test away from any operator's real keyring.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v dbus-run-session >/dev/null || { echo 'native store tests require dbus-run-session' >&2; exit 1; }
command -v gnome-keyring-daemon >/dev/null || { echo 'native store tests require gnome-keyring-daemon' >&2; exit 1; }
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -m 700 "$root/home" "$root/runtime"
# An explicit CARGO_HOME/RUSTUP_HOME is needed if the caller relied on HOME.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export HOME="$root/home" XDG_RUNTIME_DIR="$root/runtime"
export XDG_DATA_HOME="$root/data" XDG_CONFIG_HOME="$root/config" XDG_CACHE_HOME="$root/cache"
unset GNOME_KEYRING_CONTROL DBUS_SESSION_BUS_ADDRESS
dbus-run-session -- bash -euo pipefail -c '
  printf "ci-test-only-password\n" | gnome-keyring-daemon --unlock --components=secrets
  CK_NATIVE_STORE_TESTS=1 cargo test --locked -p credentials-core --test native_store -- --nocapture --test-threads=1 --skip secret_service_locked_collection_refuses_without_prompt
  CK_NATIVE_STORE_TESTS=1 CK_NATIVE_STORE_DISPOSABLE_SESSION=1 cargo test --locked -p credentials-core --test native_store secret_service_locked_collection_refuses_without_prompt -- --exact --nocapture
'
