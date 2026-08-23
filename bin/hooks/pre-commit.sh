#!/usr/bin/env bash
# Pre-commit: feedback instantáneo — lint + formato + arquitectura + tests.
# Todo corre vía deps.edn (no requiere binarios instalados).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
exec clojure -M:harness fast
