#!/usr/bin/env bash
# Local/CI quality gate: vet, lint, tests, write-isolation check, no-SNMP-SET check, govulncheck.
set -euo pipefail

cd "$(dirname "$0")/.."

go vet ./...
golangci-lint run
# -p 2: every package starts its own database and simulator containers; fewer at once keeps the timing-sensitive tests steady
go test -p 2 ./...
scripts/check-isolation.sh .
scripts/check-no-snmp-set.sh
govulncheck ./...
