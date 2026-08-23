#!/usr/bin/env bash
# Instala los git hooks como symlinks a bin/hooks/ (fuente única).
# No requiere Python ni pre-commit; funciona offline.
#
#   ./bin/install-git-hooks.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

chmod +x "${root}"/bin/hooks/*.sh
for hook in pre-commit commit-msg; do
  ln -sf "${root}/bin/hooks/${hook}.sh" "${root}/.git/hooks/${hook}"
done

echo "✔ git hooks instalados:"
ls -l "${root}/.git/hooks/" | grep -E 'pre-commit|commit-msg'
echo "  feedback instantáneo activo: lint + formato + arquitectura + tests + convención de mensajes"
