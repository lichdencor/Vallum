#!/usr/bin/env bash
# Commit-msg: convención Conventional Commits (matching el historial del repo).
#   feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert[(scope)]!: descripción
set -euo pipefail

file="$1"
head_line="$(head -1 "$file")"

regex='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?(!)?: .{1,72}$'

if ! [[ "$head_line" =~ $regex ]]; then
  cat >&2 <<EOF
✖ mensaje de commit no conforme a la convención:

    ${head_line}

Formato esperado:
  <tipo>[(<scope>)][!]: <descripción (máx 72 chars)>

Tipos: feat fix docs style refactor perf test build ci chore revert
Ejemplos:
  feat(compiler): valida zonas antes de emitir IR
  docs: arquitectura high-level
EOF
  exit 1
fi
