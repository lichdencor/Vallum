#!/usr/bin/env bash
# Instala Trivy en ~/.local/bin sin sudo, y precalienta la base de
# vulnerabilidades para que los hooks sean rápidos.
#
#   ./bin/install-trivy.sh
#   TRIVY_VERSION=0.74.0 ./bin/install-trivy.sh   # versión pinneada
set -euo pipefail

VERSION="${TRIVY_VERSION:-0.74.0}"
DEST="${HOME}/.local/bin"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Linux)  OSFAM="Linux" ;;
  Darwin) OSFAM="macOS" ;;
  *) echo "✖ SO no soportado: ${OS}" >&2; exit 1 ;;
esac

case "${ARCH}" in
  x86_64)          ARCHFAM="64bit" ;;
  aarch64|arm64)   ARCHFAM="ARM64" ;;
  *) echo "✖ arquitectura no soportada: ${ARCH}" >&2; exit 1 ;;
esac

URL="https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_${OSFAM}-${ARCHFAM}.tar.gz"

mkdir -p "${DEST}"
echo "▶ descargando ${URL}"
curl -fsSL "${URL}" | tar -xz -C "${DEST}" trivy

echo "▶ precalentando DB de vulnerabilidades (una sola vez)"
"${DEST}/trivy" --download-db-only || echo "⚠ sin red para la DB — se descargará en el primer escaneo"

"${DEST}/trivy" --version
echo "✔ trivy instalado en ${DEST}/trivy"
