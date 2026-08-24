#!/usr/bin/env bash
set -euo pipefail

APP_NAME="vallum"
VERSION="${1:-$(date +%Y%m%d)}"
OUTPUT_DIR="${2:-.}"

echo "=== Vallum native-image build ==="
echo "Version: $VERSION"
echo "Output:  $OUTPUT_DIR/$APP_NAME"
echo ""

# 1. AOT compile the main namespace
echo "--- AOT compile vallum.cli ---"
mkdir -p target/classes
clojure -M:native \
  -e "(binding [*compile-path \"target/classes\"] (compile 'vallum.cli))"

# 2. Build the native image
echo "--- native-image ---"
CP="$(clojure -Spath):target/classes"

native-image \
  -cp "$CP" \
  -H:Name="$APP_NAME" \
  -H:Path="$OUTPUT_DIR" \
  --no-fallback \
  --initialize-at-build-time \
  --report-unsupported-elements-at-runtime \
  --verbose \
  vallum.cli

echo ""
echo "=== Done ==="
ls -lh "$OUTPUT_DIR/$APP_NAME"