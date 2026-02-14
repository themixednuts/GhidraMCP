#!/usr/bin/env bash
# Build wrapper that auto-bootstraps Ghidra jars if missing, then runs Maven.
# Usage: ./build.sh [maven args...]
#   ./build.sh test
#   ./build.sh clean package
#   ./build.sh test -Dtest="com.themixednuts.models.McpResponseTest"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARKER="$SCRIPT_DIR/lib/.ghidra-bootstrap.properties"

if [ ! -f "$MARKER" ]; then
  echo "Ghidra jars not found — running bootstrap..."
  mvn -f "$SCRIPT_DIR/bootstrap.xml" initialize
  echo ""
fi

exec mvn -f "$SCRIPT_DIR/pom.xml" "$@"
