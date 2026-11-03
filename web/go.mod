// Not a Go module of the project: it stops the repository's ./... patterns (go vet, go test, golangci-lint,
// govulncheck, go-licenses) at web/, whose node_modules ship Go sources (flatted).
module github.com/beekamai/network-scheme/web

go 1.27
