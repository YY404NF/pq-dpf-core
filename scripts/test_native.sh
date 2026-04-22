#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
mkdir -p "$BUILD_DIR"

clang++ \
  -std=c++20 \
  -Wall \
  -Wextra \
  -pedantic \
  -pthread \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/src/c_api.cpp" \
  "$ROOT_DIR/tests/core_test.cpp" \
  -o "$BUILD_DIR/core_test"

"$BUILD_DIR/core_test"
