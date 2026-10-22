package drivers

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/internal/snmp"
)

const (
	/* MaxRows is the default cap on variables per walked column (large FDBs fit). */
	MaxRows = 200_000
	/* WalkTimeout bounds one column walk; the caller's earlier deadline still wins. */
	WalkTimeout = 2 * time.Minute
)

/* ErrTooManyRows stops a walk that exceeded its row cap; the table is incomplete. */
var ErrTooManyRows = errors.New("drivers: table exceeds the row limit")

/*
WalkColumn walks one table column under a deadline derived from ctx and calls
fn with the index sub-identifiers after the column OID (nil when the suffix is
not a valid index) and the variable. It stops with ErrTooManyRows when more
than limit variables arrive and returns how many variables fn received.
*/
func WalkColumn(ctx context.Context, r snmp.Reader, column string, limit int, fn func(idx []uint32, v snmp.Var)) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, WalkTimeout)
	defer cancel()
	prefix := column + "."
	n := 0
	err := r.Walk(ctx, column, func(v snmp.Var) error {
		if n >= limit {
			return ErrTooManyRows
		}
		n++
		fn(parseIndex(v.OID, prefix), v)
		return nil
	})
	return n, err
}

func parseIndex(oid, prefix string) []uint32 {
	s, ok := strings.CutPrefix(oid, prefix)
	if !ok || s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	idx := make([]uint32, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil
		}
		idx[i] = uint32(v)
	}
	return idx
}
