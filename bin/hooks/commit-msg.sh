#!/usr/bin/env bash
# Commit-msg: Conventional Commits convention (matching repo history).
#   feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert[(scope)]!: description
set -euo pipefail

file="$1"
head_line="$(head -1 "$file")"

regex='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?(!)?: .{1,72}$'

if ! [[ "$head_line" =~ $regex ]]; then
  cat >&2 <<EOF
✖ commit message does not follow the convention:

    ${head_line}

Expected format:
  <type>[(<scope>)][!]: <description (max 72 chars)>

Types: feat fix docs style refactor perf test build ci chore revert
Examples:
  feat(compiler): validate zones before emitting IR
  docs: high-level architecture
EOF
  exit 1
fi
