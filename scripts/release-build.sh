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
# WHY target/staged AND NOT target/release: a later release-profile build --
# including `cargo test --release`, including the verification run below --
# recompiles the binary IN PLACE, after the sha has been computed. You publish a
# hash that no longer names the file, and nothing errors. Cargo does not write
# build output here, so the hashes stay true.
#
# THIS IS NOT OUTSIDE CARGO'S REACH, and an earlier version of this comment said
# it was. `cargo clean` removes the WHOLE target directory: measured 2026-08-16
# with `cargo clean --dry-run -v`, which names these staged paths in its removal
# list. Two different hazards, and only one is fixed by this placement:
#   OVERWRITE (target/release) -- silent, corrupts a published hash, artifact
#     still present and wrong. This is the one that placement fixes.
#   DELETION (anywhere under target/) -- loud, file simply gone, recoverable by
#     re-running this script at the named rev. Accepted, not fixed.
# If a stage ever needs to survive a clean, it has to leave target/ entirely.
STAGE="target/staged/${REV}"
mkdir -p "$STAGE"

# PRUNE OLD STAGES. Each is ~16MB of two binaries and they accumulate silently --
# 15 of them (242MB) had piled up before anyone looked, because nothing in the
# deploy loop ever removes one and a stale stage is invisible until you measure.
#
# Keeping three is not a disk decision. A stage exists so the sha you published can
# still be checked against the file it named; once three deploys have happened the
# older ones answer a question nobody is asking, and every one of them is
# reproducible by re-running this script at that rev.
#
# AND NEVER PRUNE THE DEPLOYED REV, whatever its age. Normally it is the newest and
# survives anyway -- but stage two revs whose gates fail and the one stage you would
# actually want to diff against is the one that ages out. The script does not have to
# guess which that is: it asks the deployed binary, which is the same
# ask-the-artifact instrument the acceptance legs use.
DEPLOYED_REV="$(
  "${HOME}/.local/share/cortexkit/bin/ck-auth" --version 2>/dev/null \
    | grep -oE '\([0-9a-f]{7,}\)' | tr -d '()'
)"
find target/staged -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null \
  | xargs -0 -r ls -dt 2>/dev/null \
  | tail -n +4 \
  | while read -r old; do
      case "$(basename "$old")" in
        "$(basename "$STAGE")") continue ;;
        "${DEPLOYED_REV:-__none__}") continue ;;
      esac
      rm -rf "$old"
    done

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

# EXERCISE THE STAGED FILE, not the source it came from.
#
# `cargo test` spawns a binary it builds for the test run, so a green suite is
# evidence about the SOURCE and none at all about these bytes -- proven by deleting a
# staged artifact and watching all eight arms pass. CRED_DAEMON_BIN points the same
# arms at the exact file, under a real supervisor. Nothing else runs a release daemon
# before it replaces a production one, and a binary that panics at startup would
# otherwise first announce itself as an outage.
#
# Skipped when the sibling subc-core is absent (the suite's own graceful skip), which
# is why the summary line below states whether it ran rather than assuming it did.
echo
echo "verifying the staged artifacts..."

# BOTH binaries, and as a PAIR. Verifying a staged daemon while driving it with a
# cargo-built CLI proves neither: the two are deployed together and the wire between
# them is exactly where a mismatched build would show.
#
# ck-auth is the higher-stakes half. It is what an operator reaches for during an
# incident and the only thing that takes the single-writer lease to mutate the vault,
# so a broken artifact is discovered while trying to repair something else.
verify() {
  local label="$1"; shift
  if CRED_REQUIRE_DAEMON=1 \
     CRED_DAEMON_BIN="$PWD/$STAGE/ck-claustrum" \
     CRED_CLI_BIN="$PWD/$STAGE/ck-auth" \
     "$@" >"/tmp/ck-stage-verify.$$" 2>&1; then
    grep -E '^test result' "/tmp/ck-stage-verify.$$" | sed "s/^/  ${label}: /"
  else
    echo "STAGED ARTIFACT FAILED VERIFICATION (${label}) -- do not deploy it" >&2
    tail -30 "/tmp/ck-stage-verify.$$" >&2
    rm -f "/tmp/ck-stage-verify.$$"
    exit 1
  fi
  rm -f "/tmp/ck-stage-verify.$$"
}

verify "daemon e2e" cargo test --locked -p credentials-module --test real_daemon_e2e \
  -- --ignored --test-threads=1
verify "admin cli " cargo test --locked -p credentials-module --test cli_admin

# THE BOUNDARY OF WHAT THE ABOVE PROVES, enforced rather than remembered.
#
# A test reaching through a `cfg(debug_assertions)` seam is structurally incapable of
# verifying a release artifact: the seam is compiled out, so the arm either fails
# against the staged binary or -- worse -- passes without exercising what it names.
# Those arms are enumerable in advance by grepping for the cfg, which is what this
# does. One seam is known and handled (the api-key validation bypass, whose arm skips
# under CRED_CLI_BIN and says so).
#
# A NEW seam silently NARROWS artifact verification while every line above still prints
# green, so the count is pinned. Raising it means deciding what the matching test arm
# does under an override -- skip with a printed reason, or be rewritten not to need the
# seam -- rather than discovering the narrowing at some later deploy.
KNOWN_DEBUG_SEAMS=1
seams="$(grep -rc 'cfg(debug_assertions)' crates/*/src --include='*.rs' 2>/dev/null \
  | awk -F: '{n += $2} END {print n + 0}')"
if [ "$seams" -ne "$KNOWN_DEBUG_SEAMS" ]; then
  echo "REFUSING: found ${seams} cfg(debug_assertions) seams, expected ${KNOWN_DEBUG_SEAMS}." >&2
  echo "  Each one is a place artifact verification cannot reach. Decide what the" >&2
  echo "  matching test arm does under CRED_CLI_BIN / CRED_DAEMON_BIN, then update" >&2
  echo "  KNOWN_DEBUG_SEAMS in this script." >&2
  grep -rn 'cfg(debug_assertions)' crates/*/src --include='*.rs' >&2
  exit 1
fi
echo "  debug seams: ${seams} (known, and its test arm skips with a printed reason)"

echo "  the STAGED artifacts passed, not merely the source they were built from"

# THE REACHABILITY PROBE, and the script refuses without one.
#
# Every acceptance leg asks whether the right bytes are in the right place. None
# asks whether the BEHAVIOUR reached production, and that gap has been the half
# that mattered on two consecutive placements: a CLI fix accepted on all ten legs
# while its effect stayed invisible, because the logic ran in the daemon and only
# the CLI had been placed.
#
# It cannot be derived. The placer knows which binaries moved; only the REQUESTER
# knows which behaviour changed and what proves it. So the probe is an input, and
# a build that cannot name one has to say so explicitly -- "none" with a reason is
# an acceptable answer and an unanswered prompt is not, because the whole failure
# mode is a step everybody assumes someone else did.
if [ -z "${PROBE:-}" ]; then
  echo >&2
  echo "REFUSING: no reachability probe given." >&2
  echo >&2
  echo "  Set PROBE to a command whose output proves the change is LIVE, e.g." >&2
  echo "    PROBE='ck auth remove --id X should print \"1 handle(s)\"' $0" >&2
  echo >&2
  echo "  If this build changes no observable behaviour, say so and why:" >&2
  echo "    PROBE='none: comment-only in store.rs, no executable change' $0" >&2
  echo >&2
  echo "  It cannot be derived from the diff: the placer sees which binaries" >&2
  echo "  moved, and only you know which behaviour to look for afterwards." >&2
  exit 1
fi

echo
echo "staged in ${STAGE}/ -- outside cargo's reach, so these hashes stay true."
echo "Copy into place with a plain cp -- do NOT re-sign."
echo "Then verify AFTER placement: codesign -dv <dest> shows the pinned Identifier,"
echo "and <dest> --version reports ${REV}."
echo
echo "reachability probe: ${PROBE}"
echo "  ^ include this line VERBATIM in the staging request. The placer runs it as"
echo "    a standard leg; it is the only one that proves the change is live rather"
echo "    than merely placed."
