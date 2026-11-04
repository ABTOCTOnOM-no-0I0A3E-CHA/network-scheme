/*
Package wcreds accepts the write credentials of registered devices
(security.md 5.1a, 6.1, 9) and opens the stored one for the executor's own
use. The browser seals {v, owner "device:<id>", kind "ssh_write",
created_at, nonce, secret} to the write-domain key of the executor origin's
keys.json; only the executor holds the private key. A write-admin submits it
through confirm(H) (action credential.set). Before the change TOTP the
executor answers only from its registry (grant, device id, address, the
fingerprint of its write key) and does not open the ciphertext; after the
code it opens and checks it inside the registry write, and keeps it sealed
in the registry table write_credential under the registry's MAC. Nothing
returns the secret.

Acceptance (after the confirmation): what was confirmed is unchanged
(changed); the owner inside is the device the request names and the kind is
ssh_write (else mismatch); created_at is strictly newer than the stored one
(stale) and the nonce is not the stored one (replay); the secret's form and
weakness are those of internal/creds (malformed, weak: a password below 12
characters, DSA, RSA below 2048 bits); MES 6.x takes only an RSA user key
(key_type, [R §4]). Every decision is taken on the verified snapshot of
Gate.View or Gate.Write, whose callbacks only declare.

The binding to the device and the kind is inside the ciphertext: Open checks
it again on every use, together with the row's created_at and nonce and the
device's current line. A registry reset removes every write credential.
*/
package wcreds

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	nmsconfig "github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/keys"
)

/* Action is the confirm(H) action that stores a write credential. */
const Action = "credential.set"

/* MaxCiphertext is the bound of a sealed write credential (the CHECK of table write_credential). */
const MaxCiphertext = 8240

/*
Refusal is why a credential is not accepted; its code is what the UI shows
(web answers 422 with it). It never carries secret material.
*/
type Refusal string

func (r Refusal) Error() string { return "wcreds: " + string(r) }

/* RefusalCode is the code web answers with. */
func (r Refusal) RefusalCode() string { return string(r) }

/* Refusals. */
const (
	ErrMalformed     Refusal = "malformed"
	ErrDenied        Refusal = "denied"
	ErrNotRegistered Refusal = "not_registered"
	ErrChanged       Refusal = "changed"
	ErrMismatch      Refusal = "mismatch"
	ErrStale         Refusal = "stale"
	ErrReplay        Refusal = "replay"
	ErrWeak          Refusal = "weak"
	ErrKeyType       Refusal = "key_type"
	ErrNoCredential  Refusal = "no_credential" // #nosec G101 -- a refusal code, not a secret
)

/* outcomeUnknown is a write whose fate could not be read back: 503, the user checks whether it was stored. */
type outcomeUnknown struct{}

func (outcomeUnknown) Error() string       { return "wcreds: outcome unknown" }
func (outcomeUnknown) RefusalCode() string { return "outcome_unknown" }
func (outcomeUnknown) HTTPStatus() int     { return http.StatusServiceUnavailable }

/* ErrOutcomeUnknown is the answer when the credential may or may not be stored. */
var ErrOutcomeUnknown error = outcomeUnknown{}

/* Gate is what the store needs of freeze.Guard: the only decision paths. */
type Gate interface {
	View(ctx context.Context, fn func(*registry.Snapshot) error) error
	Write(ctx context.Context, fn func(ctx context.Context, s *registry.Snapshot, tx *registry.Tx) error) error
}

/* Store accepts and opens write credentials. */
type Store struct {
	Gate Gate
	/* Priv and Pub are the write-domain key pair. */
	Priv, Pub *[32]byte
	/* Record audits a refusal (authz.Authorizer.Record). */
	Record func(context.Context, audit.Event)
	Log    *slog.Logger
	Now    func() time.Time /* nil: time.Now */
}

/* LoadKey reads the write-domain private key file and derives its public key; Wipe the pair when done. */
func LoadKey(path string) (priv, pub *[32]byte, err error) {
	if priv, err = nmsconfig.ReadKeyFile(path); err != nil {
		return nil, nil, err
	}
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		clear(priv[:])
		return nil, nil, fmt.Errorf("wcreds: write key %s: %w", path, err)
	}
	pub = new([32]byte)
	copy(pub[:], p)
	return priv, pub, nil
}

func (st *Store) now() time.Time {
	if st.Now == nil {
		return time.Now()
	}
	return st.Now()
}

/* WriteKey is the fingerprint of the write-domain key the executor opens with (keys.Fingerprint, as in keys.json). */
func (st *Store) WriteKey() string { return keys.Fingerprint(*st.Pub) }

/* accepted is what a verified ciphertext yields: no secret. */
type accepted struct {
	createdAt, replaces time.Time
	username, method    string
	nonce               []byte
}

/* device is what a registered device shows before the confirmation. */
type device struct{ address, driver string }

/*
registered decides, on the verified snapshot s, what may be known before
the change TOTP: the user's write-admin grant (bound to the ticket's name)
and the registered device. Nothing of the ciphertext is looked at.
*/
func registered(s *registry.Snapshot, by authz.Decision, deviceID int64) (device, error) {
	g, ok := s.Get("write_grant", by.UserID, execadmin.KindWriteAdmin, nil)
	if !ok {
		return device{}, ErrDenied
	}
	if snap, _ := g.Get("username_snapshot").(string); snap != by.Username {
		return device{}, ErrDenied
	}
	dev, ok := s.Get("write_device", deviceID)
	if !ok {
		return device{}, ErrNotRegistered
	}
	var d device
	d.driver, _ = dev.Get("write_driver").(string)
	if addr := dev.Get("address"); addr != nil {
		d.address = fmt.Sprint(addr)
	}
	return d, nil
}

/* keyTypeAllowed is the line's key rule: MES 6.x takes only an RSA user key [R §4]. */
func keyTypeAllowed(driver, keyType string) bool {
	return driver != "mes6" || keyType == ssh.KeyAlgoRSA
}

/*
check decides the ciphertext itself on the verified snapshot s, after the
confirmation: binding, the credential it replaces, form, weakness and the
line's key rule.
*/
func (st *Store) check(s *registry.Snapshot, d device, deviceID int64, ct []byte) (accepted, error) {
	var a accepted
	var last []byte
	floor := time.Time{}
	if r, ok := s.Get("write_credential", deviceID); ok {
		a.replaces, _ = r.Get("created_at").(time.Time)
		last, _ = r.Get("nonce").([]byte)
		floor = a.replaces.Add(time.Nanosecond) /* strictly newer: equal is stale */
	}
	c, err := creds.OpenWrite(st.Priv, st.Pub, ct, deviceID, floor, st.now())
	defer c.Wipe()
	switch {
	case errors.Is(err, creds.ErrOwnerMismatch), errors.Is(err, creds.ErrKindMismatch):
		return accepted{}, ErrMismatch
	case errors.Is(err, creds.ErrStale):
		return accepted{}, ErrStale
	case errors.Is(err, creds.ErrWeak):
		return accepted{}, ErrWeak
	case err != nil:
		return accepted{}, ErrMalformed
	}
	if last != nil && bytes.Equal(c.Nonce, last) {
		return accepted{}, ErrReplay
	}
	a.method = "password"
	if c.Password.IsZero() {
		a.method = c.KeyType
		if !keyTypeAllowed(d.driver, c.KeyType) {
			return accepted{}, ErrKeyType
		}
	}
	a.createdAt, a.username, a.nonce = c.CreatedAt, c.Username, c.Nonce
	return a, nil
}

type params struct {
	DeviceID   int64  `json:"device_id"`
	Ciphertext string `json:"ciphertext"`
}

/* parse reads the client's params strictly: a device id above 0 and a bounded standard-base64 ciphertext. */
func parse(raw json.RawMessage) (int64, []byte, error) {
	var p params
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.More() || p.DeviceID <= 0 || p.Ciphertext == "" ||
		len(p.Ciphertext) > base64.StdEncoding.EncodedLen(MaxCiphertext) {
		return 0, nil, ErrMalformed
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(p.Ciphertext)
	if err != nil || len(ct) > MaxCiphertext {
		return 0, nil, ErrMalformed
	}
	return p.DeviceID, ct, nil
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "none"
	}
	return t.UTC().Format(time.RFC3339)
}

/* refuse audits a refusal (Record) at its stage and returns it. */
func (st *Store) refuse(ctx context.Context, by authz.Decision, stage string, id int64, rf Refusal) error {
	if st.Record != nil {
		st.Record(ctx, audit.Event{UserID: &by.UserID, Action: Action, Object: "device:" + strconv.FormatInt(id, 10), Result: audit.Denied,
			Details: map[string]any{"device_id": id, "stage": stage, "reason": string(rf)}})
	}
	return rf
}

/*
Describe answers, before the change TOTP, only what the grant and the
registry say: the device id and its address, plus the fingerprint of the
write key the executor opens with (the browser compares it with keys.json).
The ciphertext is covered by H but not opened yet, so nothing of its content
(binding, account, method, created_at, weakness) is told to someone without
the code. A refusal is audited. The grant is write-admin.
*/
func (st *Store) Describe(ctx context.Context, by authz.Decision, raw json.RawMessage) (authz.Need, confirm.Description, error) {
	id, ct, err := parse(raw)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	var d device
	if err := st.Gate.View(ctx, func(s *registry.Snapshot) error {
		d, err = registered(s, by, id)
		return err
	}); err != nil {
		var rf Refusal
		if errors.As(err, &rf) {
			return authz.Need{}, confirm.Description{}, st.refuse(ctx, by, "describe", id, rf)
		}
		return authz.Need{}, confirm.Description{}, err
	}
	desc := confirm.Description{Action: Action, Fields: []confirm.Field{
		{Key: "address", Value: d.address},
		{Key: "ciphertext", Value: base64.StdEncoding.EncodeToString(ct)},
		{Key: "device_id", Value: strconv.FormatInt(id, 10)},
		{Key: "write_key", Value: st.WriteKey()},
	}}
	return authz.Need{Kind: execadmin.KindWriteAdmin}, desc, nil
}

func field(d confirm.Description, key string) string {
	for _, f := range d.Fields {
		if f.Key == key {
			return f.Value
		}
	}
	return ""
}

/* Result is what Run answers once the code was accepted: no secret. */
type Result struct {
	DeviceID  int64     `json:"device_id"`
	CreatedAt time.Time `json:"created_at"`
	Method    string    `json:"method"`
}

/* rereadTimeout bounds the read that settles an unknown outcome, apart from the client's context. */
var rereadTimeout = 2 * registry.OpTimeout

/*
Run stores the confirmed ciphertext. Inside the registry write it checks
again what was confirmed (grant, device, the address shown and the write
key: any difference is changed) and then the ciphertext itself. A refusal
is audited and returned. Any other error of the write means the outcome is
unknown: the registry is read again, not bound to the client's context;
only a stored copy of exactly this ciphertext counts as success, its absence
as a failure, and a read that fails too as outcome_unknown.
*/
func (st *Store) Run(ctx context.Context, c confirm.Challenge, by authz.Decision) (any, error) {
	id, err := strconv.ParseInt(field(c.Description, "device_id"), 10, 64)
	ct, cerr := base64.StdEncoding.Strict().DecodeString(field(c.Description, "ciphertext"))
	if err != nil || cerr != nil || id <= 0 {
		return nil, ErrMalformed
	}
	var a accepted
	err = st.Gate.Write(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		d, err := registered(s, by, id)
		if err != nil {
			return err
		}
		if d.address != field(c.Description, "address") || st.WriteKey() != field(c.Description, "write_key") {
			return ErrChanged
		}
		if a, err = st.check(s, d, id, ct); err != nil {
			return err
		}
		tx.Audit(audit.Append(audit.Event{UserID: &by.UserID, Action: Action, Object: "device:" + strconv.FormatInt(id, 10), Result: audit.OK,
			Details: map[string]any{"device_id": id, "created_at": stamp(a.createdAt), "method": a.method, "replaces": stamp(a.replaces)}}))
		return tx.Put("write_credential", map[string]any{"device_id": id, "kind": creds.KindSSHWrite, "ciphertext": ct,
			"created_at": a.createdAt, "nonce": a.nonce})
	})
	var rf Refusal
	switch {
	case err == nil:
		return Result{DeviceID: id, CreatedAt: a.createdAt.UTC(), Method: a.method}, nil
	case errors.As(err, &rf):
		return nil, st.refuse(ctx, by, "run", id, rf)
	case errors.Is(err, authz.ErrFrozen):
		return nil, err
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rereadTimeout)
	defer cancel()
	stored := false
	if verr := st.Gate.View(rctx, func(s *registry.Snapshot) error {
		if r, ok := s.Get("write_credential", id); ok {
			got, _ := r.Get("ciphertext").([]byte)
			stored = bytes.Equal(got, ct)
		}
		return nil
	}); verr != nil {
		st.Log.Error("wcreds: outcome unknown", slog.Int64("device_id", id), slog.Any("err", err), slog.Any("reread", verr))
		return nil, ErrOutcomeUnknown
	}
	if !stored {
		return nil, fmt.Errorf("wcreds: not stored: %w", err)
	}
	st.Log.Warn("wcreds: write credential stored after an error", slog.Int64("device_id", id), slog.Any("err", err))
	return Result{DeviceID: id, CreatedAt: a.createdAt.UTC(), Method: a.method}, nil
}

/*
Open returns the stored write credential of deviceID from the verified
snapshot s for the executor's own use: the owner and the kind inside the
ciphertext must be this device and ssh_write, its created_at and nonce
those of the row (a ciphertext of another device or an older one under a
re-MACed row is a mismatch), and a key must still fit the device's current
line (key_type). The caller wipes it.
*/
func (st *Store) Open(s *registry.Snapshot, deviceID int64) (creds.Credential, error) {
	r, ok := s.Get("write_credential", deviceID)
	if !ok {
		return creds.Credential{}, ErrNoCredential
	}
	dev, ok := s.Get("write_device", deviceID)
	if !ok {
		return creds.Credential{}, ErrNotRegistered
	}
	driver, _ := dev.Get("write_driver").(string)
	ct, _ := r.Get("ciphertext").([]byte)
	at, _ := r.Get("created_at").(time.Time)
	nonce, _ := r.Get("nonce").([]byte)
	if kind, _ := r.Get("kind").(string); kind != creds.KindSSHWrite {
		return creds.Credential{}, ErrMismatch
	}
	c, err := creds.OpenWrite(st.Priv, st.Pub, ct, deviceID, at, st.now())
	if err != nil {
		if errors.Is(err, creds.ErrWeak) {
			return creds.Credential{}, ErrWeak
		}
		return creds.Credential{}, ErrMismatch
	}
	if !c.CreatedAt.Equal(at) || !bytes.Equal(c.Nonce, nonce) {
		c.Wipe()
		return creds.Credential{}, ErrMismatch
	}
	if c.Password.IsZero() && !keyTypeAllowed(driver, c.KeyType) {
		c.Wipe()
		return creds.Credential{}, ErrKeyType
	}
	return c, nil
}
