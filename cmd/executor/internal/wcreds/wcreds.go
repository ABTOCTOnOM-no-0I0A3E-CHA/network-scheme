/*
Package wcreds accepts the write credentials of registered devices
(security.md 5.1a, 6.1, 9) and opens the stored one for the executor's own
use. The browser seals {v, owner "device:<id>", kind "ssh_write",
created_at, nonce, secret} to the write-domain key of the executor origin's
keys.json; only the executor holds the private key. A write-admin submits it
through confirm(H) (action credential.set: Describe shows what is about to be
stored, Run stores it after the change TOTP), and it is kept as sealed in
the registry table write_credential under the registry's MAC. Nothing returns the secret:
the description shows the device, the account name and the method only.

Acceptance: the owner inside is the device the request names and the kind is
ssh_write (else mismatch); the device is in write_device (not_registered);
created_at is strictly newer than the stored one (stale) and the nonce is
not the stored one (replay); the secret's form and weakness are those of
internal/creds (malformed, weak: a password below 12 characters, DSA, RSA
below 2048 bits); MES 6.x takes only an RSA user key (key_type, [R §4]).
Every decision is taken on the verified snapshot of Gate.View or Gate.Write,
whose callbacks only declare.

The binding to the device and the kind is inside the ciphertext, so it
survives a registry reset that re-MACs the rows: Open checks it again on
every use, together with the row's created_at and nonce.
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
	ErrMismatch      Refusal = "mismatch"
	ErrStale         Refusal = "stale"
	ErrReplay        Refusal = "replay"
	ErrWeak          Refusal = "weak"
	ErrKeyType       Refusal = "key_type"
	ErrNoCredential  Refusal = "no_credential" // #nosec G101 -- a refusal code, not a secret
)

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
	/* Record audits a refusal after the confirmation (authz.Authorizer.Record). */
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

/* accepted is what a verified submission shows: no secret. */
type accepted struct {
	createdAt, replaces time.Time
	address, driver     string
	username, method    string
	nonce               []byte
}

/*
check decides a submission on the verified snapshot s: the user's
write-admin grant (bound to the ticket's name), the registered device, the
stored credential it replaces and the ciphertext itself.
*/
func (st *Store) check(s *registry.Snapshot, by authz.Decision, deviceID int64, ct []byte) (accepted, error) {
	g, ok := s.Get("write_grant", by.UserID, execadmin.KindWriteAdmin, nil)
	if !ok {
		return accepted{}, ErrDenied
	}
	if snap, _ := g.Get("username_snapshot").(string); snap != by.Username {
		return accepted{}, ErrDenied
	}
	dev, ok := s.Get("write_device", deviceID)
	if !ok {
		return accepted{}, ErrNotRegistered
	}
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
	a.driver, _ = dev.Get("write_driver").(string)
	a.method = "password"
	if c.Password.IsZero() {
		a.method = c.KeyType
		if a.driver == "mes6" && c.KeyType != ssh.KeyAlgoRSA {
			return accepted{}, ErrKeyType
		}
	}
	a.createdAt, a.username, a.nonce = c.CreatedAt, c.Username, c.Nonce
	if addr := dev.Get("address"); addr != nil {
		a.address = fmt.Sprint(addr)
	}
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

/*
Describe verifies the submission on a verified snapshot and describes it:
the ciphertext itself (H covers exactly what Run stores) and what the user
recognises: device, address, driver, account name, method, the credential
it replaces. The grant is write-admin.
*/
func (st *Store) Describe(ctx context.Context, by authz.Decision, raw json.RawMessage) (authz.Need, confirm.Description, error) {
	id, ct, err := parse(raw)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	var a accepted
	if err := st.Gate.View(ctx, func(s *registry.Snapshot) error {
		a, err = st.check(s, by, id, ct)
		return err
	}); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	d := confirm.Description{Action: Action, Fields: []confirm.Field{
		{Key: "address", Value: a.address},
		{Key: "ciphertext", Value: base64.StdEncoding.EncodeToString(ct)},
		{Key: "created_at", Value: stamp(a.createdAt)},
		{Key: "device_id", Value: strconv.FormatInt(id, 10)},
		{Key: "driver", Value: a.driver},
		{Key: "method", Value: a.method},
		{Key: "replaces", Value: stamp(a.replaces)},
		{Key: "username", Value: a.username},
	}}
	if d.Validate() != nil { /* an account name confirm cannot show as is */
		return authz.Need{}, confirm.Description{}, ErrMalformed
	}
	return authz.Need{Kind: execadmin.KindWriteAdmin}, d, nil
}

func field(d confirm.Description, key string) string {
	for _, f := range d.Fields {
		if f.Key == key {
			return f.Value
		}
	}
	return ""
}

/* Result is what Run answers: no secret. */
type Result struct {
	DeviceID  int64     `json:"device_id"`
	CreatedAt time.Time `json:"created_at"`
}

/*
Run stores the confirmed ciphertext, checked again inside the registry
write (the stored credential or the device may have changed since Describe).
A refusal is audited and returned. Any other error of the write means the
outcome is unknown: the registry is read again, and only a stored copy of
exactly this ciphertext counts as success.
*/
func (st *Store) Run(ctx context.Context, c confirm.Challenge, by authz.Decision) (any, error) {
	id, err := strconv.ParseInt(field(c.Description, "device_id"), 10, 64)
	ct, cerr := base64.StdEncoding.Strict().DecodeString(field(c.Description, "ciphertext"))
	if err != nil || cerr != nil || id <= 0 {
		return nil, ErrMalformed
	}
	obj := "device:" + strconv.FormatInt(id, 10)
	var a accepted
	err = st.Gate.Write(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		var err error
		if a, err = st.check(s, by, id, ct); err != nil {
			return err
		}
		tx.Audit(audit.Append(audit.Event{UserID: &by.UserID, Action: Action, Object: obj, Result: audit.OK,
			Details: map[string]any{"device_id": id, "created_at": stamp(a.createdAt), "method": a.method, "replaces": stamp(a.replaces)}}))
		return tx.Put("write_credential", map[string]any{"device_id": id, "kind": creds.KindSSHWrite, "ciphertext": ct,
			"created_at": a.createdAt, "nonce": a.nonce})
	})
	var rf Refusal
	switch {
	case err == nil:
		return Result{DeviceID: id, CreatedAt: a.createdAt.UTC()}, nil
	case errors.As(err, &rf):
		if st.Record != nil {
			st.Record(ctx, audit.Event{UserID: &by.UserID, Action: Action, Object: obj, Result: audit.Denied,
				Details: map[string]any{"device_id": id, "reason": string(rf)}})
		}
		return nil, rf
	case errors.Is(err, authz.ErrFrozen):
		return nil, err
	}
	stored := false
	if verr := st.Gate.View(ctx, func(s *registry.Snapshot) error {
		r, ok := s.Get("write_credential", id)
		got, _ := r.Get("ciphertext").([]byte)
		stored = ok && bytes.Equal(got, ct)
		return nil
	}); verr != nil {
		return nil, fmt.Errorf("wcreds: outcome unknown (%v): the registry cannot be read now: %w", err, verr)
	}
	if !stored {
		return nil, fmt.Errorf("wcreds: not stored: %w", err)
	}
	st.Log.Warn("wcreds: write credential stored after an error", slog.Int64("device_id", id), slog.Any("err", err))
	return Result{DeviceID: id, CreatedAt: a.createdAt.UTC()}, nil
}

/*
Open returns the stored write credential of deviceID from the verified
snapshot s for the executor's own use: the owner and the kind inside the
ciphertext must be this device and ssh_write, and its created_at and nonce
those of the row (a ciphertext of another device or an older one under a
re-MACed row is a mismatch). The caller wipes it.
*/
func (st *Store) Open(s *registry.Snapshot, deviceID int64) (creds.Credential, error) {
	r, ok := s.Get("write_credential", deviceID)
	if !ok {
		return creds.Credential{}, ErrNoCredential
	}
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
	return c, nil
}
