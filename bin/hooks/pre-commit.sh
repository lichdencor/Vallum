#!/usr/bin/env bash
# Pre-commit: instant feedback — lint + formatting + architecture + tests.
# Everything runs via deps.edn (no installed binaries required).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
exec clojure -M:harness fast
