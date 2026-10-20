package auth

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

//go:embed data/compromised.txt.gz
var compromisedGz []byte

/* compromisedSet lazily loads the embedded list once; the list is lowercase. */
var compromisedSet = sync.OnceValue(func() map[string]struct{} {
	m := make(map[string]struct{}, 100000)
	zr, err := gzip.NewReader(bytes.NewReader(compromisedGz))
	if err != nil {
		panic("auth: corrupt embedded compromised list: " + err.Error())
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			m[l] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		panic("auth: corrupt embedded compromised list: " + err.Error())
	}
	return m
})

/* isCompromised matches case-insensitively against the embedded list. */
func isCompromised(pw string) bool {
	_, ok := compromisedSet()[strings.ToLower(pw)]
	return ok
}
