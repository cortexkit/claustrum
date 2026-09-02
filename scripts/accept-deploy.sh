#!/usr/bin/env bash
# Run the deploy acceptance ladder against the LIVE daemon.
#
# WHY A SCRIPT RATHER THAN THE RUNBOOK'S COMMANDS. The runbook carries every guard
# these legs need, and the guards are correct. They still failed, because a leg
# typed from memory runs the form you learned BEFORE the lesson, while a script
# runs the form that was written after it. Measured this week: the inode leg
# retyped by hand took the wrong lsof field and printed a pid where an inode
# belonged -- a plausible number, next to a real inode, that reads as a mismatch.
# The fleet's written form already said "second-to-last field", from someone
# else's identical slip weeks earlier.
#
# So: prose teaches, scripts enforce. Every guard below is load-bearing and
# annotated with what breaks without it.
#
# WHICH LEGS HAVE BEEN PROVEN ABLE TO FAIL, stated because "ten green legs" is
# also what a ladder checking nothing prints:
#   (a) rev      proven -- run with a wrong rev, both binaries refuse
#   (b) digest   proven -- run against a different staged dir, both refuse
#   (c) identity proven -- a copy re-signed without --identifier reads as
#                          ck-auth-55554944<LC_UUID>, which the equality rejects
#   (d) inode    NOT proven live. THE RECORDED REASON BELOW WAS WRONG AND IS
#                CORRECTED HERE: I wrote that these need production in the state
#                they detect, which reads as unmanufacturable. What actually blocks
#                (d) is narrower and was found by trying it 2026-09-02 -- a
#                throwaway subject binary is needed, and a COPY OF A PLATFORM
#                BINARY CANNOT BE THE SUBJECT: macOS SIGKILLs it on exec. Measured,
#                with the control that disproved my first explanation:
#                  replace the running image, then TERM -> "Killed: 9"
#                  no replace at all,        then TERM -> "Killed: 9"
#                Both arms die identically, so the death is code-signature
#                enforcement on the copied binary and has NOTHING to do with the
#                unlink. My first reading -- "mv over a running image gets it
#                killed" -- was a mechanism invented to fit one observation, and
#                the control killed it. Proving (d) needs a long-running subject
#                that is ad-hoc signed by us rather than copied from /bin, or a
#                fixture from a seat that has observed the state in the wild.
#                Until then this leg's failure mode is unobserved, which is exactly
#                what the note above it must keep saying.
#   (e) store    NOT proven live: needs a daemon holding the wrong vault
#   (f) serving  NOT proven live: needs a degraded vault
#   (g) write    NOT proven live: needs a fenced-out daemon
# The last four are only reachable by putting production into the state they
# detect. Their guards are argued at each site instead; if a rig ever exists that
# can fake those states, prove them there and update this list.
#
# Usage:
#   scripts/accept-deploy.sh <expected-rev> [staged-dir]
#
# Exits non-zero on the first failed leg, and prints what it observed either way:
# a leg that cannot show its working cannot be audited.

set -euo pipefail

EXPECTED_REV="${1:-}"
STAGED_DIR="${2:-}"
BIN_DIR="$HOME/.local/share/cortexkit/bin"
FAILED=0

if [ -z "$EXPECTED_REV" ]; then
    echo "usage: $0 <expected-rev> [staged-dir]" >&2
    echo "  the rev is REQUIRED: a ladder with nothing to compare against passes" >&2
    echo "  trivially, which is the failure mode it exists to prevent." >&2
    exit 2
fi

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }
note() { printf '        %s\n' "$1"; }

echo "acceptance ladder for $EXPECTED_REV"
echo

# ---- leg (a): ask the binary what it is -------------------------------------
# The only leg that interrogates the ARTIFACT rather than inferring identity from
# a path, a timestamp, or a hash you must already hold. It is also the only one
# that works during an incident, when all you have is the running binary.
for name in ck-claustrum ck-auth; do
    got="$("$BIN_DIR/$name" --version 2>&1 | sed -n 's/.*(\(.*\))/\1/p')"
    if [ "$got" = "$EXPECTED_REV" ]; then
        pass "$name reports $got"
    else
        fail "$name reports '${got:-<none>}', expected '$EXPECTED_REV'"
    fi
done

# ---- leg (b): per-binary digest, never pair-against-pair --------------------
# Each binary is compared against ITS OWN staged digest. Comparing the two
# binaries to each other asserts same-rev, which is a DIFFERENT property from
# deployed-together and does not always hold: a CLI-only fix ships a CLI ahead of
# the daemon, and a ladder asserting parity manufactures a failed-flip finding
# out of correct state.
if [ -n "$STAGED_DIR" ]; then
    for name in ck-claustrum ck-auth; do
        if [ ! -f "$STAGED_DIR/$name" ]; then
            fail "$name absent from $STAGED_DIR"
            continue
        fi
        a="$(shasum -a 256 "$STAGED_DIR/$name" | cut -d' ' -f1)"
        b="$(shasum -a 256 "$BIN_DIR/$name" | cut -d' ' -f1)"
        if [ "$a" = "$b" ]; then
            pass "$name digest matches its staged artifact"
        else
            fail "$name digest differs from staged"
            note "staged   ${a:0:16}"
            note "deployed ${b:0:16}"
        fi
    done
else
    note "SKIP  digest leg: no staged dir given"
fi

# ---- leg (c): the pinned code identity --------------------------------------
# Checked AFTER placement, because a pin is not sticky: one `codesign --force
# --sign -` at the destination silently reverts it to the derived form, which
# embeds the link-time UUID and revokes every macOS privacy grant bound to it.
for name in ck-claustrum ck-auth; do
    ident="$(codesign -dv "$BIN_DIR/$name" 2>&1 | sed -n 's/^Identifier=//p')"
    if [ "$ident" = "$name" ]; then
        pass "$name identifier pinned"
    else
        fail "$name identifier is '${ident:-<unsigned>}', expected '$name'"
    fi
done

# ---- leg (d): the running image is the deployed file ------------------------
# `pgrep -x`, NEVER `-f`: `-f` matches the whole command line, so it also matches
# any shell whose script text contains the name -- including THIS script. It
# would return two pids here, and `head -1` would hand lsof the wrong one, which
# reports no store.db and reads as "the daemon has no vault open".
pid="$(pgrep -x ck-claustrum || true)"
if [ -z "$pid" ]; then
    fail "no ck-claustrum process"
else
    # lsof's txt rows: the inode is the SECOND-TO-LAST field and the path is the
    # LAST. Taking $2 yields the pid -- a plausible integer next to a real inode,
    # which is why this guard is spelled out rather than left to memory.
    run_inode="$(lsof -p "$pid" | awk '$4=="txt" && /ck-claustrum/{print $(NF-1); exit}')"
    dep_inode="$(stat -f %i "$BIN_DIR/ck-claustrum")"
    if [ -n "$run_inode" ] && [ "$run_inode" = "$dep_inode" ]; then
        pass "running image is the deployed file (inode $run_inode)"
    else
        fail "running inode '${run_inode:-<none>}' != deploy inode '$dep_inode'"
        note "the process may still be executing an unlinked predecessor"
    fi

    # ---- leg (e): the open store is the expected vault ----------------------
    # Asks the KERNEL what the daemon has open rather than what it believes it
    # opened, so a stale config cannot make it agree with the wrong answer. Every
    # other leg answers "is it healthy" or "is it the right binary"; only this one
    # answers "is it the right vault".
    store="$(lsof -p "$pid" | awk '$NF ~ /store\.db$/ {print $NF; exit}')"
    expected_store="$HOME/.local/share/cortexkit/claustrum/store.db"
    if [ "$store" = "$expected_store" ]; then
        pass "open store is $store"
    else
        fail "open store is '${store:-<none>}', expected '$expected_store'"
    fi
fi

# ---- leg (f): serving, not merely alive -------------------------------------
# A daemon whose master key was unavailable at boot is up, answering, and serving
# nothing. The assertion is N/N serving, never "the process is up".
status="$("$BIN_DIR/ck-auth" status 2>&1 | head -1)"
if printf '%s' "$status" | grep -q "^vault: ok"; then
    pass "$status"
else
    fail "$status"
    note "degraded is not automatically a deploy failure -- check WHICH credential"
fi

# ---- leg (g): a fenced WRITE commits ----------------------------------------
# Reads are unfenced, so a fenced-out daemon serves normally while refusing every
# write. Only a round trip through the write path proves write authority, and the
# mint/revoke pair also exercises the atomic audit append.
probe="apikey:exa"
if handle="$("$BIN_DIR/ck-auth" mint-handle --id "$probe" 2>&1 | head -1)" \
    && [ -n "$handle" ] \
    && "$BIN_DIR/ck-auth" revoke-handle --handle "$handle" >/dev/null 2>&1; then
    pass "fenced write path commits (mint + revoke on $probe)"
else
    fail "could not complete a mint/revoke round trip on $probe"
fi

echo
if [ "$FAILED" -eq 0 ]; then
    echo "ACCEPTED $EXPECTED_REV"
    echo
    echo "NOT covered by this ladder: whether a BEHAVIOUR you shipped is reachable."
    echo "Every leg above asks whether the right bytes are in the right place. A"
    echo "change whose logic lives behind the route plane stays invisible until the"
    echo "daemon half is placed, and a deployed CLI is not a deployed behaviour."
    echo "Exercise the specific change end to end; the ladder cannot do it for you."
else
    echo "REFUSED: at least one leg failed"
    exit 1
fi
