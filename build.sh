#!/usr/bin/env bash
# Build script. Mirrors the make target chain so tests can call it
# uniformly without worrying about parallel make races.
set -euo pipefail

cd "$(dirname "$0")"
make clean >/dev/null 2>&1 || true
mkdir -p build/gluethread
make all
