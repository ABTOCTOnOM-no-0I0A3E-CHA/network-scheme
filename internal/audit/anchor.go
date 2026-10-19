package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

/*
Anchor is a chain hash recorded outside the database (a file on the host,
out of reach of api). It detects truncation of the log even when the
attacker also rewrites audit.chain_head.
*/
type Anchor struct {
	ID   int64
	Hash []byte
	At   time.Time
}

// String formats a as one anchor-file line: "id hex-hash RFC3339".
func (a Anchor) String() string {
	return fmt.Sprintf("%d %x %s", a.ID, a.Hash, a.At.UTC().Format(time.RFC3339))
}

// ParseAnchors reads anchor lines ("id hex-hash RFC3339"); blank lines are skipped.
func ParseAnchors(r io.Reader) ([]Anchor, error) {
	var out []Anchor
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		a, err := parseAnchor(line)
		if err != nil {
			return nil, fmt.Errorf("audit: anchors line %d: %w", n, err)
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read anchors: %w", err)
	}
	return out, nil
}

func parseAnchor(line string) (Anchor, error) {
	f := strings.Fields(line)
	if len(f) != 3 {
		return Anchor{}, errors.New("want 3 fields: id hex-hash RFC3339")
	}
	id, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || id < 1 {
		return Anchor{}, fmt.Errorf("bad id %q", f[0])
	}
	hash, err := hex.DecodeString(f[1])
	if err != nil || len(hash) != HashSize {
		return Anchor{}, errors.New("hash must be 64 hex digits")
	}
	at, err := time.Parse(time.RFC3339, f[2])
	if err != nil {
		return Anchor{}, fmt.Errorf("bad time %q", f[2])
	}
	return Anchor{ID: id, Hash: hash, At: at}, nil
}

/*
CheckAnchors requires that, for every anchor, the event with the same id
still exists and carries the same hash. All failures are reported together.
*/
func CheckAnchors(ctx context.Context, q Querier, anchors []Anchor) error {
	var errs []error
	for _, a := range anchors {
		var hash []byte
		err := q.QueryRow(ctx, `SELECT hash FROM audit.event WHERE id = $1`, a.ID).Scan(&hash)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			errs = append(errs, fmt.Errorf("audit: anchor %d: event missing", a.ID))
		case err != nil:
			return fmt.Errorf("audit: anchor %d: %w", a.ID, err)
		case !bytes.Equal(hash, a.Hash):
			errs = append(errs, fmt.Errorf("audit: anchor %d: hash mismatch", a.ID))
		}
	}
	return errors.Join(errs...)
}
