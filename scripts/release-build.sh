#!/usr/bin/env bash
# Build and sign the vault's release binaries with their source revision stamped in.
#
# WHY THIS EXISTS RATHER THAN A cargo build INCANTATION IN THE RUNBOOK: three things
# have to be true of every release binary, and each has silently failed at least once.
#
#   1. IT MUST NAME ITS SOURCE. `--version` used to print only CARGO_PKG_VERSION, a
#      constant unchanged in the project's lifetime, so it answered "is this ck-auth"
#      and never "which ck-auth". LC_UUID cannot substitute: measured 2026-08-12, the
#      same commit built in the main tree and in a worktree gave different UUIDs, so it
#      identifies a (commit, path, toolchain) triple and cannot name a commit.
#
#   2. IT MUST BE SIGNED WITH A PINNED IDENTIFIER. macOS's default adhoc identifier is
#      `<name>-<hex of LC_UUID>`, which changes on every link, and macOS binds privacy
#      grants to it -- so an unpinned release silently revokes fleet-wide grants with no
#      prompt and no error.
#
#   3. IT MUST COME FROM A COMMITTED TREE. Otherwise the stamped revision names a commit
#      whose contents are not what was built, which is worse than `unknown`: it is a
#      confident wrong answer, and the whole point of the stamp is to be trusted during
#      an incident.
#
# Refuses rather than warns on a dirty tree, because a warning at build time is read
# hours later at deploy time, by which point the binary looks like any other.

set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
  echo "REFUSING: the tree has uncommitted changes." >&2
  echo "  A stamped revision must name the source that was actually built." >&2
  git status --short >&2
  exit 1
fi

REV="$(git rev-parse --short=7 HEAD)"
echo "building at ${REV}"

# --locked so the build cannot silently resolve a different dependency set than CI did.
CK_BUILD_REV="$REV" cargo build --locked --release -p credentials-module \
  --bin ck-claustrum --bin ck-auth

for bin in ck-claustrum ck-auth; do
  path="target/release/$bin"
  # Pin the identifier. NEVER re-sign at the destination: a pin is not sticky, and one
  # `codesign --force --sign -` at placement reverts it to the derived form.
  codesign --force --sign - --identifier "$bin" "$path"
  printf '%-14s rev=%s sha=%s\n' \
    "$bin" \
    "$("$path" --version | sed -E 's/.*\((.*)\)/\1/')" \
    "$(shasum -a 256 "$path" | cut -c1-16)"
done

echo
echo "staged in target/release/. Copy into place with a plain cp -- do NOT re-sign."
echo "Then verify AFTER placement: codesign -dv <dest> shows the pinned Identifier,"
echo "and <dest> --version reports ${REV}."
