#!/usr/bin/env bash
# Compare the wire facts this repo TRANSCRIBES against the documents that own them.
#
# WHY THIS EXISTS
# Three constants in `apns_submit.rs` are not decisions this repo made. They are
# transcriptions of facts owned elsewhere: the APNs payload key and the sealed
# envelope's shape are specified in `subconscious/docs/specs/push-sealed-payload.md`,
# and the payload key is ALSO declared independently by the iOS client. No compiler
# spans those copies, and a mismatch is silent in the worst possible place -- the
# notification is accepted by Apple, delivered to the device, and never opens.
#
# WHY A CHECK RATHER THAN A SHARED DEFINITION
# The obvious alternative is to generate the constants from the spec. That would be
# right for a CONTRACT, where both sides must agree and one definition removes a bug
# class. It is wrong HERE, because agreement is the thing being tested: a consumer
# that derives its expectation from the artifact under test cannot detect a change in
# it. The independent transcription IS the second opinion, and this script is the
# thing that reads both.
#
# WHAT IT DOES NOT DO
# It does not check the iOS client's copy. That repository is not available in this
# repo's CI, so the third copy is out of reach from here and is named in the manifest
# rather than verified -- an omission stated so it is not mistaken for coverage.
set -o errexit
set -o nounset
set -o pipefail

spec="${1:-../subconscious/docs/specs/push-sealed-payload.md}"
source_file="crates/credentials-core/src/apns_submit.rs"

if [[ ! -f "$spec" ]]; then
  echo "REFUSED: spec not found at $spec" >&2
  echo "  This check cannot pass by being unable to read its input." >&2
  exit 1
fi
if [[ ! -f "$source_file" ]]; then
  echo "REFUSED: $source_file not found" >&2
  exit 1
fi

fail=0

# Each check reads BOTH copies and compares them. A check that reads only one side
# and pattern-matches an expectation baked into this script would be a third
# transcription rather than a comparison.
compare() {
  local what="$1" ours="$2" theirs="$3"
  if [[ -z "$ours" ]]; then
    echo "REFUSED: could not read $what from $source_file" >&2
    echo "  An unreadable side is not a match; the anchor has probably moved." >&2
    fail=1
    return
  fi
  if [[ -z "$theirs" ]]; then
    echo "REFUSED: could not read $what from the spec" >&2
    echo "  An unreadable side is not a match; the anchor has probably moved." >&2
    fail=1
    return
  fi
  if [[ "$ours" != "$theirs" ]]; then
    echo "MISMATCH in $what" >&2
    echo "  this repo: $ours" >&2
    echo "  spec:      $theirs" >&2
    fail=1
    return
  fi
  echo "  ok  $what = $ours"
}

echo "checking transcribed wire facts against $spec"

# The payload key holding the sealed blob.
ours_key=$(sed -n 's/^pub const SEALED_BLOB_KEY: &str = "\(.*\)";$/\1/p' "$source_file")
theirs_key=$(sed -n 's/^ "\([a-z]*\)":"<base64 of version.*$/\1/p' "$spec")
compare "sealed blob payload key" "$ours_key" "$theirs_key"

# The `aps` member that causes iOS to run the service extension.
ours_mutable=$(sed -n 's/^pub const MUTABLE_CONTENT_KEY: &str = "\(.*\)";$/\1/p' "$source_file")
theirs_mutable=$(grep -o '"mutable-content":1' "$spec" | head -1 | sed 's/^"\(.*\)":1$/\1/')
compare "mutable-content key" "$ours_mutable" "$theirs_mutable"

# The envelope's minimum length, derived on both sides from the same three parts
# rather than copied as a number: version byte + encapsulated key + AEAD tag.
ours_min=$(sed -n 's/^pub const MIN_SEALED_LEN: usize = \(.*\);$/\1/p' "$source_file" | tr -d ' ')
spec_version=$(sed -n 's/^version : \([0-9]*\) byte.*$/\1/p' "$spec")
spec_enc=$(sed -n 's/^enc     : \([0-9]*\) bytes.*$/\1/p' "$spec")
spec_tag=$(sed -n 's/^ct      : N bytes.*includes the \([0-9]*\)-byte tag.*$/\1/p' "$spec")
theirs_min=""
if [[ -n "$spec_version" && -n "$spec_enc" && -n "$spec_tag" ]]; then
  theirs_min="${spec_version}+${spec_enc}+${spec_tag}"
fi
compare "minimum sealed length" "$ours_min" "$theirs_min"

if (( fail )); then
  echo >&2
  echo "One or more transcribed facts disagree with the document that owns them." >&2
  echo "Do NOT reconcile by editing this repo until you know which side moved:" >&2
  echo "the spec is normative, but a spec edit can also be the mistake." >&2
  exit 1
fi

echo "all transcribed facts agree with the owning document"
