#!/usr/bin/env bash
# Audit the retained signed-payload store against the audit chain, in BOTH directions
# and on BOTH properties.
#
# WHY THIS EXISTS AS A SCRIPT RATHER THAN A REMEMBERED QUERY: the store is the only
# thing that can replay what a signature covered. `payload_hash` in the chain is a
# COMMITMENT to bytes, not a copy, so the chain answers "what was approved" forever and
# cannot answer "what did it say". Manifest v7 (approval seq 4700) is already
# unrecoverable for exactly that reason -- signed, never retained here, and the consumer
# overwrote its own copy in place, so neither side could produce bytes both had
# committed to.
#
# TWO DIRECTIONS, because they answer different questions and only one can find absence:
#
#   files -> chain   "is every artifact I hold one I approved?"
#                    Structurally BLIND to absence: it iterates what exists, so a
#                    missing artifact is not expressible. This returned a clean 5-of-5
#                    while v7 was gone.
#   chain -> files   "can I replay every approval I made?"
#                    This is the one that found v7.
#
# TWO PROPERTIES, because a hash authenticates CONTENT and says nothing about IDENTITY:
#
#   content   sha256(file) matches an approval row -- these are bytes I vouched for
#   label     manifest_version INSIDE the file matches the version in its filename
#
# The second arm exists because the first cannot see a mislabelled file: v9.json holding
# v12's bytes matches approval seq 7858 and passes the content arm clean. Both a hash and
# a signature answer "are these the bytes someone vouched for"; neither answers "are
# these the bytes you think they are". The identity claim lives in the label, and the
# label is the part nobody verifies because it is the part you are reading FROM.
#
# Exit 0 = every arm clean. Exit 1 = a finding. Exit 2 = the audit could not run, which
# is deliberately NOT the same as clean.
set -uo pipefail

DATA_DIR="${1:-$HOME/.local/share/cortexkit/claustrum}"
STORE="$DATA_DIR/store.db"
PAYLOADS="$DATA_DIR/signed-payloads"
KEY_ID="signing:gh-manifest-root:1"

# Refuse rather than report clean when the inputs are not readable. An audit that cannot
# read its subject must not exit 0 -- that is the "ran 0 tests" defect an external
# contributor filed against this repo's gate, and it reads as a pass.
[ -f "$STORE" ] || { echo "REFUSING: no store at $STORE" >&2; exit 2; }
[ -d "$PAYLOADS" ] || { echo "REFUSING: no payload store at $PAYLOADS" >&2; exit 2; }
command -v sqlite3 >/dev/null || { echo "REFUSING: sqlite3 not on PATH" >&2; exit 2; }
command -v python3 >/dev/null || { echo "REFUSING: python3 not on PATH" >&2; exit 2; }

findings=0

# mode=ro, never immutable=1: immutable skips the -wal and answers from a pre-WAL
# snapshot, so a live store's recent approvals would be invisible and the scan would
# report a gap that does not exist.
sql() { sqlite3 "file:$STORE?mode=ro" "$1"; }

approvals=$(sql "SELECT COUNT(*) FROM audit_log WHERE op='approval' AND credential_id='$KEY_ID';")
files=$(find "$PAYLOADS" -name '*.json' -type f | wc -l | tr -d ' ')
echo "approval rows: $approvals   retained files: $files"

# A population floor: this store has held approvals since 2026-08-27, so zero rows means
# the predicate broke, not that nothing was ever signed.
if [ "$approvals" -eq 0 ]; then
  echo "REFUSING: zero approval rows for $KEY_ID -- the predicate or the id is wrong," >&2
  echo "  not a clean result. This store has held approvals since 2026-08-27." >&2
  exit 2
fi

echo
echo "=== files -> chain (content): is every artifact one I approved? ==="
for f in "$PAYLOADS"/*.json; do
  [ -f "$f" ] || continue
  h=$(shasum -a 256 "$f" | cut -d' ' -f1)
  n=$(sql "SELECT COUNT(*) FROM audit_log WHERE op='approval' AND payload_hash='$h';")
  if [ "$n" -ge 1 ]; then
    printf '  %-34s %s  approved\n' "$(basename "$f")" "${h:0:16}"
  else
    printf '  %-34s %s  *** NO APPROVAL ROW ***\n' "$(basename "$f")" "${h:0:16}"
    findings=$((findings + 1))
  fi
done

echo
echo "=== files -> self (label): does each payload's own version match its filename? ==="
for f in "$PAYLOADS"/*.json; do
  [ -f "$f" ] || continue
  fn=$(basename "$f")
  want=$(printf '%s' "$fn" | grep -oE 'v[0-9]+' | head -1 | tr -d 'v')
  got=$(python3 -c "import json;print(json.load(open('$f')).get('manifest_version',''))" 2>/dev/null)
  if [ -z "$want" ] || [ -z "$got" ]; then
    printf '  %-34s could not read a version from both sides  *** UNCHECKABLE ***\n' "$fn"
    findings=$((findings + 1))
  elif [ "$want" = "$got" ]; then
    printf '  %-34s filename v%-3s == payload v%-3s\n' "$fn" "$want" "$got"
  else
    printf '  %-34s filename v%-3s != payload v%-3s  *** MISLABELLED ***\n' "$fn" "$want" "$got"
    findings=$((findings + 1))
  fi
done

echo
echo "=== chain -> files: can I replay every approval? (the direction that finds absence) ==="
while IFS='|' read -r seq ts hash; do
  [ -n "$hash" ] || continue
  match=""
  for f in "$PAYLOADS"/*.json; do
    [ -f "$f" ] || continue
    if [ "$(shasum -a 256 "$f" | cut -d' ' -f1)" = "$hash" ]; then match=$(basename "$f"); break; fi
  done
  if [ -n "$match" ]; then
    printf '  seq %-6s %s  %s\n' "$seq" "${hash:0:16}" "$match"
  else
    printf '  seq %-6s %s  *** BYTES NOT RETAINED (%s) ***\n' "$seq" "${hash:0:16}" "$ts"
    findings=$((findings + 1))
  fi
done < <(sql "SELECT seq, datetime(ts_ms/1000,'unixepoch'), payload_hash FROM audit_log
              WHERE op='approval' AND credential_id='$KEY_ID' ORDER BY seq;")

echo
if [ "$findings" -eq 0 ]; then
  echo "CLEAN: $approvals approval(s), $files file(s), all three arms."
  exit 0
fi
echo "$findings finding(s). A BYTES NOT RETAINED line is permanent if no copy survives"
echo "anywhere -- the chain still proves what was approved, but the artifact cannot be"
echo "replayed and the signature over it becomes uncheckable rather than repudiated."
exit 1
