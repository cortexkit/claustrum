#!/usr/bin/env bash
# Fail if git tracks anything under .cortexkit/ outside the shared allowlist.
#
# .cortexkit/ holds internal documents and private scripts that git must never carry.
# Only release notes, skills, rules, the worker guide and top-level project settings
# files (.cortexkit/<module>.jsonc, which the supervisor reads) are tracked on purpose.
#
# Listing tracked files rather than tracked-and-ignored ones is the point: a private
# file that a stray `!` line in some .gitignore un-ignores is tracked but no longer
# ignored, so `git ls-files -ci` would not see it. And a git failure must not read as
# an empty list, so the command's own status is checked before its output is used.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! all="$(git ls-files -- .cortexkit)"; then
  echo "BLIND: git ls-files failed, so the .cortexkit layout was not checked" >&2
  exit 2
fi
bad="$(printf '%s\n' "$all" \
  | grep -vE '^\.cortexkit/(release-notes/|skills/|rules/|WORKER\.md$|[a-z0-9-]+\.jsonc$)' \
  | grep -v '^$' || true)"
if [ -n "$bad" ]; then
  printf 'tracked outside the .cortexkit allowlist:\n%s\n' "$bad" >&2
  exit 1
fi
echo "cortexkit layout: $(printf '%s\n' "$all" | grep -c . || true) tracked path(s), all allowed"
