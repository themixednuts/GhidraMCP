#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_SRC="$REPO_ROOT/.githooks/pre-commit"
HOOK_DST="$REPO_ROOT/.git/hooks/pre-commit"

if [[ ! -f "$HOOK_SRC" ]]; then
  echo "Missing hook source: $HOOK_SRC" >&2
  exit 1
fi

cp "$HOOK_SRC" "$HOOK_DST"
chmod +x "$HOOK_DST"

echo "Installed pre-commit hook to $HOOK_DST"
