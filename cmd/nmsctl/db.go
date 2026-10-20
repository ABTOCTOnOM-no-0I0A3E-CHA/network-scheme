package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mdp/qrterminal/v3"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/store"
)

/* Locations inside the tools container (see the nmsctl service in compose.yaml). */
const (
	configPath      = "/etc/nms/api.yaml"
	cliUser         = "nms_cli"
	cliPasswordFile = "/run/secrets/db_cli_password" // #nosec G101 -- path of a secret file, not a secret
	defaultAnchors  = "/var/lib/nms/anchors/anchors.log"
)

/* anchorGrace is how old the log may get before verify demands anchors. */
const anchorGrace = time.Hour

/* openDB connects as nms_cli with the settings of api.yaml and loads the data key. */
func openDB(ctx context.Context) (*pgxpool.Pool, *[32]byte, func(), error) {
	cfg, err := config.LoadAPI(configPath)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := config.ReadKeyFile(cfg.DataKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}
	pw, err := config.ReadSecretFile(cliPasswordFile)
	if err != nil {
		return nil, nil, nil, err
	}
	db := cfg.DB
	db.User, db.PasswordFile = cliUser, cliPasswordFile
	pool, err := store.Open(ctx, db, pw)
	if err != nil {
		return nil, nil, nil, err
	}
	return pool, key, pool.Close, nil
}

/* dbCmd runs a database command inside the tools container. */
func dbCmd(ctx context.Context, cmd string, args []string, pool *pgxpool.Pool, key *[32]byte, d deps) error {
	switch cmd {
	case "admin create":
		a, err := parseAdminCreate(args)
		if err != nil {
			return err
		}
		if a.totpOut != "" {
			return errors.New("--totp-secret-out is handled on the host")
		}
		pw, err := readPassword(a.passwordFile, d)
		if err != nil {
			return err
		}
		return adminCreate(ctx, pool, key, a.user, pw, d.out)
	case "user reset":
		a, err := parseUserReset(args)
		if err != nil {
			return err
		}
		var pw *secret.Secret
		if a.password {
			p, err := readPassword(a.passwordFile, d)
			if err != nil {
				return err
			}
			pw = &p
		}
		return userReset(ctx, pool, a.user, pw, a.totp, d.out)
	case "user unlock":
		user, err := parseUserUnlock(args)
		if err != nil {
			return err
		}
		return userUnlock(ctx, pool, user, d.out)
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	anchors := fs.String("anchors", defaultAnchors, "anchors file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New(usage)
	}
	if cmd == "audit verify" {
		return auditVerify(ctx, pool, *anchors, d)
	}
	return auditAnchor(ctx, pool, *anchors, d)
}

func cliEvent(action string, userID int64, details map[string]any) audit.Event {
	return audit.Event{
		UserAgent: "nmsctl", Action: action, ObjectType: "user",
		ObjectID: strconv.FormatInt(userID, 10), Result: "ok", Details: details,
	}
}

/*
adminCreate creates a user with a global admin binding and an enrolled TOTP
secret in one transaction with its audit event, then shows the QR code, the
secret for manual entry and the backup codes once.
*/
func adminCreate(ctx context.Context, pool *pgxpool.Pool, key *[32]byte, user string, pw secret.Secret, out io.Writer) error {
	name, err := auth.NormalizeUsername(user)
	if err != nil {
		return err
	}
	users, roles := auth.NewUserStore(pool), rbac.NewStore(pool)
	var (
		sec   secret.Secret
		uri   string
		codes []string
	)
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		id, err := users.Create(ctx, tx, name, pw.Reveal())
		if err != nil {
			return err
		}
		if err := roles.SetBindings(ctx, tx, id, []rbac.Binding{{Role: rbac.RoleAdmin}}); err != nil {
			return err
		}
		if sec, uri, codes, err = users.EnrollTOTP(ctx, tx, id, key); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, cliEvent("cli.admin_create", id, map[string]any{"username": name}))
		return err
	})
	if err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Administrator %q created with a global admin binding.\nScan the QR code with an authenticator app:\n\n", name)
	qrterminal.GenerateHalfBlock(uri, qrterminal.M, &b)
	fmt.Fprintf(&b, "\n%s%s\n\nBackup codes (shown once, each works once):\n", install.TOTPSecretLinePrefix, sec.Reveal())
	for _, c := range codes {
		b.WriteString("  " + c + "\n")
	}
	_, err = io.WriteString(out, b.String())
	return err
}

/* userID looks up a user by its normalized name. */
func userID(ctx context.Context, tx pgx.Tx, name string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `SELECT id FROM core."user" WHERE username = $1`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: %s", auth.ErrUserNotFound, name)
	}
	return id, err
}

/*
userReset sets a new password and/or removes TOTP (enrolled again at the next
login); both end all sessions and clear an account lock. It neither disables
the user nor changes its bindings, so it cannot remove the last administrator
and needs no rbac.GuardNotLastAdmin.
*/
func userReset(ctx context.Context, pool *pgxpool.Pool, user string, pw *secret.Secret, totp bool, out io.Writer) error {
	name, err := auth.NormalizeUsername(user)
	if err != nil {
		return err
	}
	users := auth.NewUserStore(pool)
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		id, err := userID(ctx, tx, name)
		if err != nil {
			return err
		}
		if err := users.Unlock(ctx, tx, id); err != nil {
			return err
		}
		if pw != nil {
			if err := users.SetPassword(ctx, tx, id, pw.Reveal()); err != nil {
				return err
			}
		}
		if totp {
			if err := users.ResetTOTP(ctx, tx, id); err != nil {
				return err
			}
		}
		_, err = audit.Append(ctx, tx, cliEvent("cli.user_reset", id,
			map[string]any{"username": name, "password": pw != nil, "totp": totp}))
		return err
	})
	if err != nil {
		return err
	}
	if pw != nil {
		printf(out, "%s: password changed.\n", name)
	}
	if totp {
		printf(out, "%s: TOTP removed; it is enrolled again at the next login.\n", name)
	}
	printf(out, "%s: all sessions ended; account lock cleared.\n", name)
	return nil
}

/*
userUnlock clears the failed-login counter and the account lock of a user
(the way out of a lock kept up by repeated failures), audited in the same
transaction. Sessions and per-IP limits are left alone.
*/
func userUnlock(ctx context.Context, pool *pgxpool.Pool, user string, out io.Writer) error {
	name, err := auth.NormalizeUsername(user)
	if err != nil {
		return err
	}
	users := auth.NewUserStore(pool)
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		id, err := userID(ctx, tx, name)
		if err != nil {
			return err
		}
		if err := users.Unlock(ctx, tx, id); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, cliEvent("cli.user_unlock", id, map[string]any{"username": name}))
		return err
	})
	if err != nil {
		return err
	}
	printf(out, "%s: account lock cleared.\n", name)
	return nil
}

/* readAnchors parses the anchors file; a missing file means no anchors. */
func readAnchors(path string) ([]audit.Anchor, error) {
	f, err := os.Open(path) // #nosec G304 G703 -- operator-supplied path inside the tools container
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return audit.ParseAnchors(f)
}

/*
checkChain verifies the hash chain and the anchors; it reports a failure to
out and returns errFailed.
*/
func checkChain(ctx context.Context, pool *pgxpool.Pool, path string, out io.Writer) (audit.VerifyResult, []audit.Anchor, error) {
	res, err := audit.Verify(ctx, pool)
	if err != nil {
		return res, nil, err
	}
	if res.Break != nil {
		printf(out, "FAIL: audit chain broken at event %d: %s\n", res.Break.ID, res.Break.Reason)
		return res, nil, errFailed
	}
	anchors, err := readAnchors(path)
	if err != nil {
		return res, nil, err
	}
	if err := audit.CheckAnchors(ctx, pool, anchors); err != nil {
		printf(out, "FAIL: %v\n", err)
		return res, nil, errFailed
	}
	return res, anchors, nil
}

/*
auditVerify checks the chain and the anchors. With no anchors at all it
also fails when the log has events older than anchorGrace: the hourly
anchor should have recorded them, so their absence may hide a truncation
that a consistent rewrite of the head makes invisible to Verify.
*/
func auditVerify(ctx context.Context, pool *pgxpool.Pool, path string, d deps) error {
	res, anchors, err := checkChain(ctx, pool, path, d.out)
	if err != nil {
		return err
	}
	if len(anchors) == 0 {
		var old bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit.event WHERE ts < $1)`,
			d.now().Add(-anchorGrace)).Scan(&old); err != nil {
			return err
		}
		if old {
			printf(d.out, "FAIL: no anchors in %s, but the log has events older than %s: truncation cannot be ruled out\n", path, anchorGrace)
			return errFailed
		}
	}
	printf(d.out, "OK: %d events, last id %d, %d anchors match\n", res.Count, res.LastID, len(anchors))
	return nil
}

/* auditAnchor appends the verified chain head to the anchors file. */
func auditAnchor(ctx context.Context, pool *pgxpool.Pool, path string, d deps) error {
	res, _, err := checkChain(ctx, pool, path, d.out)
	if err != nil {
		return err
	}
	if res.LastID == 0 {
		printf(d.out, "audit log is empty: nothing to anchor\n")
		return nil
	}
	line := audit.Anchor{ID: res.LastID, Hash: res.LastHash, At: d.now()}.String() + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 G703 -- operator-supplied path inside the tools container
	if err != nil {
		return err
	}
	_, werr := f.WriteString(line)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		return err
	}
	printf(d.out, "anchored event %d\n", res.LastID)
	return nil
}
