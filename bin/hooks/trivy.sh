#!/usr/bin/env bash
# Escaneo rápido de seguridad con Trivy para pre-commit.
# Si no está instalado: avisa y continúa — la enforcement dura vive en
# `clojure -M:harness all` y en CI.
command -v trivy >/dev/null 2>&1 || [ -x "${HOME}/.local/bin/trivy" ] || {
  echo "⏭️  trivy no instalado — saltando (instalar: bin/install-trivy.sh)"
  exit 0
}

cd "$(git rev-parse --show-toplevel)" || exit 1
BIN="$(command -v trivy || echo "${HOME}/.local/bin/trivy")"
exec "${BIN}" fs --scanners vuln,misconfig,secret \
                 --severity HIGH,CRITICAL --exit-code 1 --skip-db-update .
