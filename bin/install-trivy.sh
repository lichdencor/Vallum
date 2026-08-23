#!/usr/bin/env bash
# Installs Trivy into ~/.local/bin without sudo, and pre-warms the
# vulnerability database so hooks stay fast.
#
#   ./bin/install-trivy.sh
#   TRIVY_VERSION=0.74.0 ./bin/install-trivy.sh   # pinned version
set -euo pipefail

VERSION="${TRIVY_VERSION:-0.74.0}"
DEST="${HOME}/.local/bin"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Linux)  OSFAM="Linux" ;;
  Darwin) OSFAM="macOS" ;;
  *) echo "✖ Unsupported OS: ${OS}" >&2; exit 1 ;;
esac

case "${ARCH}" in
  x86_64)          ARCHFAM="64bit" ;;
  aarch64|arm64)   ARCHFAM="ARM64" ;;
  *) echo "✖ Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
esac

URL="https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_${OSFAM}-${ARCHFAM}.tar.gz"

mkdir -p "${DEST}"
echo "▶ downloading ${URL}"
curl -fsSL "${URL}" | tar -xz -C "${DEST}" trivy

echo "▶ pre-warming vulnerability DB (one time only)"
"${DEST}/trivy" --download-db-only || echo "⚠ no network for the DB — it will download on first scan"

"${DEST}/trivy" --version
echo "✔ trivy installed at ${DEST}/trivy"
