#!/usr/bin/env bash
# Build wrapper that auto-bootstraps Ghidra jars if missing, then runs Maven.
# Usage: ./build.sh [maven args...]
#   ./build.sh test
#   ./build.sh clean package
#   ./build.sh test -Dtest="com.themixednuts.models.McpResponseTest"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

needs_bootstrap=false
if [ ! -f "$LIB_DIR/.ghidra-bootstrap.properties" ]; then
  needs_bootstrap=true
else
  for jar in Base DB Generic SoftwareModeling Utility; do
    if [ ! -f "$LIB_DIR/$jar.jar" ]; then
      needs_bootstrap=true
      break
    fi
  done
fi

if [ "$needs_bootstrap" = true ]; then
  echo "Ghidra jars missing or incomplete — running bootstrap..."
  mvn -f "$SCRIPT_DIR/bootstrap.xml" initialize
  echo ""
fi

exec mvn -f "$SCRIPT_DIR/pom.xml" "$@"
