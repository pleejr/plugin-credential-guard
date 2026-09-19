#!/bin/sh
# Seats hooks/fallback/prompt-guard.ts as a UserPromptSubmit command hook.
# Kept separate from the TypeScript so settings.json names one stable path and
# the runtime lookup stays in shell, where PATH problems are legible.
#
# Failure is OPEN and loud: with no node, the prompt goes through and stdout
# says it was not scanned. A silent pass here would be the very bug this
# fallback exists to cover.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

NODE=$(command -v node 2>/dev/null || true)
if [ -z "$NODE" ] && [ -s "$HOME/.nvm/nvm.sh" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.nvm/nvm.sh" >/dev/null 2>&1 || true
  NODE=$(command -v node 2>/dev/null || true)
fi
if [ -z "$NODE" ]; then
  echo "credential-guard fallback: no node on PATH — the prompt was NOT scanned."
  exit 0
fi

exec "$NODE" --experimental-strip-types --no-warnings "$HERE/prompt-guard.ts"
