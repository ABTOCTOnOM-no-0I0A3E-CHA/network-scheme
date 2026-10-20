#!/usr/bin/env bash
# Local/CI quality gate: vet, lint, tests, write-isolation check, no-SNMP-SET check, govulncheck.
set -euo pipefail

cd "$(dirname "$0")/.."

go vet ./...
golangci-lint run
go test ./...
scripts/check-isolation.sh .
scripts/check-no-snmp-set.sh
govulncheck ./...
