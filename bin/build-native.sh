#!/usr/bin/env bash
set -euo pipefail

APP_NAME="vallum"
VERSION="${1:-$(date +%Y%m%d)}"
OUTPUT_DIR="${2:-.}"

echo "=== Vallum native-image build ==="
echo "Version: $VERSION"
echo "Output:  $OUTPUT_DIR/$APP_NAME"
echo ""

# 1. AOT compile all namespaces reachable from cli
echo "--- AOT compile ---"
mkdir -p target/classes
clojure -M:native \
  -e "(binding [clojure.core/*compile-path* \"target/classes\"]
       (doseq [sym '[vallum.cli
                     vallum.compile
                     vallum.dsl
                     vallum.ir
                     vallum.emit.nft
                     vallum.validate
                     vallum.runtime
                     vallum.manifest
                     vallum.ingest
                     vallum.bridge.protocol
                     vallum.bridge.stub]]
         (compile sym)))"

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