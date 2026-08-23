#!/usr/bin/env bash
# Installs the git hooks as symlinks to bin/hooks/ (single source of truth).
# No Python nor pre-commit required; works offline.
#
#   ./bin/install-git-hooks.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

chmod +x "${root}"/bin/hooks/*.sh
for hook in pre-commit commit-msg; do
  ln -sf "${root}/bin/hooks/${hook}.sh" "${root}/.git/hooks/${hook}"
done

echo "✔ git hooks installed:"
ls -l "${root}/.git/hooks/" | grep -E 'pre-commit|commit-msg'
echo "  instant feedback active: lint + formatting + architecture + tests + message convention"
