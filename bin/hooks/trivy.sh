#!/usr/bin/env bash
# Quick Trivy security scan for pre-commit.
# If not installed: warn and continue — hard enforcement lives in
# `clojure -M:harness all` and CI.
command -v trivy >/dev/null 2>&1 || [ -x "${HOME}/.local/bin/trivy" ] || {
  echo "⏭️  trivy not installed — skipping (install: bin/install-trivy.sh)"
  exit 0
}

cd "$(git rev-parse --show-toplevel)" || exit 1
BIN="$(command -v trivy || echo "${HOME}/.local/bin/trivy")"
exec "${BIN}" fs --scanners vuln,misconfig,secret \
                 --severity HIGH,CRITICAL --exit-code 1 --skip-db-update .
