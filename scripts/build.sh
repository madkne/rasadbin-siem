#!/usr/bin/env bash
set -euo pipefail

mkdir -p build

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

CGO_ENABLED=1 go build \
  -ldflags "-X main.commit=${COMMIT}" \
  -o build/rasadbin \
  ./cmd/app