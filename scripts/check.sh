#!/usr/bin/env bash
# Local/CI quality gate: vet, lint, tests, write-isolation check.
set -euo pipefail

cd "$(dirname "$0")/.."

go vet ./...
golangci-lint run
go test ./...
scripts/check-isolation.sh .
