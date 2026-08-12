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

# COPY OUT OF target/ BEFORE PUBLISHING ANYTHING ABOUT THESE FILES.
#
# target/release/ belongs to cargo, and any later `--release` command silently
# overwrites what is in it. Measured the hard way: an e2e run with `--release` REBUILT
# ck-claustrum on top of a staged, signed artifact, so a sha published from that path
# stopped describing the file within one command. A hash is a promise about a specific
# byte sequence; publishing one for a path a build tool owns is a promise nobody can
# keep.
#
# The staging dir is keyed by revision, so two builds of one commit land in the same
# place and a different commit cannot quietly replace the first.
STAGE="target/staged/${REV}"
mkdir -p "$STAGE"

for bin in ck-claustrum ck-auth; do
  cp "target/release/$bin" "$STAGE/$bin"
  # Pin the identifier. NEVER re-sign at the destination: a pin is not sticky, and one
  # `codesign --force --sign -` at placement reverts it to the derived form.
  codesign --force --sign - --identifier "$bin" "$STAGE/$bin"
  printf '%-14s rev=%s sha256=%s\n' \
    "$bin" \
    "$("$STAGE/$bin" --version | sed -E 's/.*\((.*)\)/\1/')" \
    "$(shasum -a 256 "$STAGE/$bin" | cut -d' ' -f1)"
done

echo
echo "staged in ${STAGE}/ -- outside cargo's reach, so these hashes stay true."
echo "Copy into place with a plain cp -- do NOT re-sign."
echo "Then verify AFTER placement: codesign -dv <dest> shows the pinned Identifier,"
echo "and <dest> --version reports ${REV}."
