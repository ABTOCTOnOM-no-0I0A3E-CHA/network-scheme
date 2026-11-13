/*
Package state reads and writes the executor's state file on its own volume
(/var/lib/executor/state): the registry high-water mark, the registry state
hash and the head of the executor's audit chain, for the last committed
change and for the one in flight (pending). The file is MACed with the
state subkey of the sealing key and replaced atomically (temporary file,
fsync, rename, directory fsync).

On disk: the hex HMAC-SHA-256 of the body, a newline, then the JSON body.
*/
package state

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

/* Version is the format version of the body; any other value is refused. */
const Version = 1

/* MaxReason bounds the freeze reason kept in the file. */
const MaxReason = 1024

const (
	macLabel    = "nms/executor/state/v1\x00"
	sealedLabel = "nms/executor/sealed/v1\x00"
	maxSize     = 64 << 10
)

/* ErrInvalid means the file is malformed, of another format or of another key (another install). */
var ErrInvalid = errors.New("state: invalid or foreign state file")

/* AuditHead is the tail of the executor's audit chain (filled in by the audit, task 4a.4). */
type AuditHead struct {
	LastID int64  `json:"last_id"`
	Hash   []byte `json:"hash"`
}

/* Record is the registry as of one counter value: high-water mark, state hash, audit head. */
type Record struct {
	HWM       int64     `json:"hwm"`
	StateHash []byte    `json:"state_hash"`
	AuditHead AuditHead `json:"audit_head"`
}

/*
File is the body of the state file. Pending is the change written before its
COMMIT, with the id of its transaction: only that transaction's fate in the
database (pg_xact_status) ever settles it, never a matching hash. Pending is
nil once settled. Frozen is sticky: it outlives a database that is
put back as it was, so only the host (nmsctl, 4a.4) clears it. AuditBase is
where the verification of the live audit chain starts (nil: its first row):
a registry reset after a break, a rewrite or unanchored rows moves it to the
tail it continues from, since rows can never be repaired (append only), and
keeps the part it could still verify as an AuditSealed segment, which every
later verification checks again.
*/
type File struct {
	V            int        `json:"v"`
	Committed    Record     `json:"committed"`
	Pending      *Record    `json:"pending"`
	PendingXID   uint64     `json:"pending_xid"` /* the database transaction (xid8) of Pending; set iff Pending is */
	Frozen       bool       `json:"frozen"`
	FreezeReason string     `json:"freeze_reason"`
	AuditBase    *AuditHead `json:"audit_base,omitempty"`
	AuditSealed  []Segment  `json:"audit_sealed,omitempty"`
	/*
		KeyVersion is the version of the sealing key this file is MACed with (0: the
		first, 1); PendingKey is set with Pending while a rotation to another key is
		in flight: the ID of that key, so only the rotation itself settles it.
	*/
	KeyVersion int32  `json:"key_version,omitempty"`
	PendingKey []byte `json:"pending_key,omitempty"`
}

/* SealVersion is the version of the sealing key the file is MACed with. */
func (f File) SealVersion() int32 {
	if f.KeyVersion == 0 {
		return 1
	}
	return f.KeyVersion
}

/* MaxSealed bounds the sealed segments (one per registry reset that moved the base). */
const MaxSealed = 256

/* Segment is a part of the audit chain kept verifiable by a reset: the rows after From up to To, chaining from From's hash and ending in To's. */
type Segment struct {
	From AuditHead `json:"from"`
	To   AuditHead `json:"to"`
}

func (s Segment) valid() bool {
	return s.From.LastID >= 0 && s.To.LastID > s.From.LastID && len(s.From.Hash) == sha256.Size && len(s.To.Hash) == sha256.Size
}

/* Chain is what the audit chain is verified against: sealed segments, the live chain's base and the anchor. */
type Chain struct {
	Sealed       []Segment
	Base, Anchor AuditHead
}

/* Base is the start of the live audit chain's verification: AuditBase, or the empty head. */
func (f File) Base() AuditHead {
	if f.AuditBase == nil {
		return AuditHead{Hash: make([]byte, sha256.Size)}
	}
	return *f.AuditBase
}

/* Chain is the audit chain's verification bounds as committed in f. */
func (f File) Chain() Chain {
	return Chain{Sealed: f.AuditSealed, Base: f.Base(), Anchor: f.Committed.AuditHead}
}

/* Equal reports whether two records describe the same registry state. */
func (r Record) Equal(o Record) bool {
	return r.HWM == o.HWM && bytes.Equal(r.StateHash, o.StateHash) &&
		r.AuditHead.LastID == o.AuditHead.LastID && bytes.Equal(r.AuditHead.Hash, o.AuditHead.Hash)
}

func (r Record) valid() bool {
	return r.HWM >= 0 && len(r.StateHash) == sha256.Size &&
		r.AuditHead.LastID >= 0 && len(r.AuditHead.Hash) == sha256.Size
}

/* Reason returns s as valid UTF-8 cut on a character boundary to at most MaxReason bytes. */
func Reason(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= MaxReason {
		return s
	}
	n := MaxReason
	for !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func mac(key *[32]byte, body []byte) []byte {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(macLabel))
	h.Write(body)
	return h.Sum(nil)
}

/*
Load reads and authenticates the state file. A missing file yields an error
matching os.ErrNotExist; anything else that is not a valid file of this key
and format yields ErrInvalid.
*/
func Load(path string, key *[32]byte) (File, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path from the executor configuration
	if err != nil {
		return File{}, err
	}
	sum, body, ok := bytes.Cut(raw, []byte("\n"))
	if !ok || len(raw) > maxSize {
		return File{}, ErrInvalid
	}
	want, err := hex.DecodeString(string(sum))
	if err != nil || !hmac.Equal(want, mac(key, body)) {
		return File{}, ErrInvalid
	}
	var f File
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || dec.More() {
		return File{}, ErrInvalid
	}
	if f.V != Version || !f.Committed.valid() || (f.Pending != nil && !f.Pending.valid()) || (f.Pending == nil) != (f.PendingXID == 0) || len(f.FreezeReason) > MaxReason ||
		f.KeyVersion < 0 || (f.PendingKey != nil && (f.Pending == nil || len(f.PendingKey) != sha256.Size)) ||
		(f.AuditBase != nil && (f.AuditBase.LastID < 0 || len(f.AuditBase.Hash) != sha256.Size)) || !sealedValid(f.AuditSealed, f.Base()) {
		return File{}, ErrInvalid
	}
	return f, nil
}

/* Save writes f atomically and durably: a temporary file in the same directory, fsync, rename, directory fsync. */
func Save(path string, key *[32]byte, f File) error {
	f.V = Version
	f.FreezeReason = Reason(f.FreezeReason)
	body, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return write(path, append([]byte(hex.EncodeToString(mac(key, body))+"\n"), body...))
}

/*
SaveSealed writes body to path as Save writes the state file (MACed with the
state subkey, atomically and durably), under label: a file of another kind
never passes for this one. LoadSealed reads it back, refusing a file over
limit bytes or with another MAC (ErrInvalid); a missing file yields an error
matching os.ErrNotExist.
*/
func SaveSealed(path string, key *[32]byte, label string, body []byte) error {
	return write(path, append([]byte(hex.EncodeToString(sealedMAC(key, label, body))+"\n"), body...))
}

/* LoadSealed reads a file SaveSealed wrote under label, at most limit bytes. */
func LoadSealed(path string, key *[32]byte, label string, limit int) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path inside the executor's state directory
	if err != nil {
		return nil, err
	}
	sum, body, ok := bytes.Cut(raw, []byte("\n"))
	if !ok || len(raw) > limit {
		return nil, ErrInvalid
	}
	want, err := hex.DecodeString(string(sum))
	if err != nil || !hmac.Equal(want, sealedMAC(key, label, body)) {
		return nil, ErrInvalid
	}
	return body, nil
}

func sealedMAC(key *[32]byte, label string, body []byte) []byte {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(sealedLabel + label + "\x00"))
	h.Write(body)
	return h.Sum(nil)
}

/* write replaces path with data: a temporary file in the same directory, fsync, rename, directory fsync. */
func write(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() /* no-op after the rename */
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	return syncDir(dir)
}

/* syncDir makes the rename durable. Windows cannot fsync a directory (development only; the executor runs on Linux). */
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) // #nosec G304 -- directory of the state file
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	return errors.Join(d.Sync(), d.Close())
}

/* sealedValid: well-formed segments in id order, none overlapping another or the live chain's base. */
func sealedValid(segs []Segment, base AuditHead) bool {
	if len(segs) > MaxSealed {
		return false
	}
	last := int64(-1)
	for _, g := range segs {
		if !g.valid() || g.From.LastID < last {
			return false
		}
		last = g.To.LastID
	}
	return last <= base.LastID
}
