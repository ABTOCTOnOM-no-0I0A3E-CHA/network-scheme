/*
Command nmsctl is the host-only administration CLI: installation, the
break-glass admin, user resets and audit chain verification. Database
commands run in the one-shot "nmsctl" tools container of the compose
project; on the host nmsctl only prompts and forwards them.
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/secret"
)

const usage = `usage:
  nmsctl install --public-host HOST --image-tag TAG [--admin-user U] [--admin-password-file F]
                 [--web-cert F --web-key F] [--infra-ntp H,..] [--infra-dns H,..] [--infra-mirror H,..]
                 [--non-interactive] [--totp-secret-out F]
  nmsctl admin create --user U [--password-file F] [--totp-secret-out F]
  nmsctl user reset U [--password [--password-file F]] [--totp]
  nmsctl audit verify [--anchors F]
  nmsctl audit anchor [--anchors F]`

/* printf writes CLI output; a failing stdout or stderr cannot be reported anywhere better. */
func printf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

/* errFailed is returned after the failure has already been reported. */
var errFailed = errors.New("failed")

/* deps are the process boundaries of nmsctl, replaced in tests. */
type deps struct {
	in        io.Reader
	out, errw io.Writer
	sys       install.System
	/* openDB connects as nms_cli and loads the data key (tools container only). */
	openDB func(ctx context.Context) (*pgxpool.Pool, *[32]byte, func(), error)
	now    func() time.Time
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], deps{
		in: os.Stdin, out: os.Stdout, errw: os.Stderr,
		sys: install.OSSystem{}, openDB: openDB, now: time.Now,
	})
	stop()
	os.Exit(code)
}

/* exitStatus is the exit code of a forwarded command that reported its own failure. */
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

/* run executes one command and returns the process exit code. */
func run(ctx context.Context, args []string, d deps) int {
	err := dispatch(ctx, args, d)
	var status exitStatus
	switch {
	case err == nil:
		return 0
	case errors.As(err, &status):
		return int(status)
	case errors.Is(err, errFailed):
		return 1
	default:
		printf(d.errw, "error: %v\n", err)
		return 1
	}
}

func dispatch(ctx context.Context, args []string, d deps) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	if args[0] == "install" {
		if d.sys.InContainer() {
			return errors.New("install runs on the host, not in a container")
		}
		return installCmd(ctx, args[1:], d)
	}
	if len(args) < 2 {
		return errors.New(usage)
	}
	cmd, rest := args[0]+" "+args[1], args[2:]
	if !d.sys.InContainer() {
		err := hostCmd(ctx, cmd, rest, d)
		if exit := (*exec.ExitError)(nil); errors.As(err, &exit) && exit.ExitCode() > 0 {
			return exitStatus(exit.ExitCode()) /* the tools container has reported it */
		}
		return err
	}
	switch cmd {
	case "admin create", "user reset", "audit verify", "audit anchor":
	default:
		return errors.New(usage)
	}
	pool, key, closeDB, err := d.openDB(ctx)
	if err != nil {
		return err
	}
	defer closeDB()
	return dbCmd(ctx, cmd, rest, pool, key, d)
}

/*
hostCmd forwards a database command to the tools container. Passwords are
read on the host (file or no-echo prompt), validated, and passed on stdin.
*/
func hostCmd(ctx context.Context, cmd string, args []string, d deps) error {
	switch cmd {
	case "admin create":
		a, err := parseAdminCreate(args)
		if err != nil {
			return err
		}
		pw, err := newPassword(a.passwordFile, d)
		if err != nil {
			return err
		}
		return install.AdminCreate(ctx, d.sys, install.DefaultEtc, a.user, pw, a.totpOut, d.out, d.errw)
	case "user reset":
		a, err := parseUserReset(args)
		if err != nil {
			return err
		}
		fwd := []string{"user", "reset", a.user}
		var stdin io.Reader = strings.NewReader("")
		if a.password {
			pw, err := newPassword(a.passwordFile, d)
			if err != nil {
				return err
			}
			fwd = append(fwd, "--password", "--password-file", "-")
			stdin = strings.NewReader(pw.Reveal() + "\n")
		}
		if a.totp {
			fwd = append(fwd, "--totp")
		}
		return install.RunInTools(ctx, d.sys, install.DefaultEtc, fwd, stdin, d.out, d.errw)
	case "audit verify", "audit anchor":
		fwd := append(strings.Fields(cmd), args...)
		return install.RunInTools(ctx, d.sys, install.DefaultEtc, fwd, strings.NewReader(""), d.out, d.errw)
	}
	return errors.New(usage)
}

type adminCreateArgs struct{ user, passwordFile, totpOut string }

func parseAdminCreate(args []string) (adminCreateArgs, error) {
	var a adminCreateArgs
	fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&a.user, "user", "", "user name")
	fs.StringVar(&a.passwordFile, "password-file", "", `file with the password ("-": stdin)`)
	fs.StringVar(&a.totpOut, "totp-secret-out", "", "CI only: write the TOTP secret to this file")
	if err := fs.Parse(args); err != nil {
		return a, err
	}
	if a.user == "" || fs.NArg() > 0 {
		return a, errors.New("usage: nmsctl admin create --user U [--password-file F] [--totp-secret-out F]")
	}
	return a, nil
}

type userResetArgs struct {
	user, passwordFile string
	password, totp     bool
}

/* parseUserReset accepts the user name before or after the flags. */
func parseUserReset(args []string) (userResetArgs, error) {
	var a userResetArgs
	fs := flag.NewFlagSet("user reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&a.password, "password", false, "set a new password")
	fs.StringVar(&a.passwordFile, "password-file", "", `file with the new password ("-": stdin)`)
	fs.BoolVar(&a.totp, "totp", false, "remove TOTP: the user enrolls again at the next login")
	bad := errors.New("usage: nmsctl user reset U [--password [--password-file F]] [--totp]")
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		a.user, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return a, err
	}
	if a.user == "" && fs.NArg() == 1 {
		a.user = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return a, bad
	}
	if a.passwordFile != "" {
		a.password = true
	}
	switch {
	case a.user == "":
		return a, bad
	case !a.password && !a.totp:
		return a, errors.New("nothing to reset: give --password and/or --totp")
	}
	return a, nil
}

/* maxPasswordInput bounds a password read from stdin. */
const maxPasswordInput = 4096

/*
readPassword returns the password from file ("-": stdin, one trailing newline
trimmed) or, without a file, from a no-echo prompt on the terminal.
*/
func readPassword(file string, d deps) (secret.Secret, error) {
	switch file {
	case "-":
		raw, err := io.ReadAll(io.LimitReader(d.in, maxPasswordInput))
		if err != nil {
			return secret.Secret{}, err
		}
		pw := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
		if pw == "" {
			return secret.Secret{}, errors.New("empty password on stdin")
		}
		return secret.New(pw), nil
	case "":
	default:
		return config.ReadSecretFile(file)
	}
	f, ok := d.in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) { // #nosec G115 -- a file descriptor fits in int
		return secret.Secret{}, errors.New("no terminal for a password prompt: use --password-file")
	}
	var pws [2]string
	for i, prompt := range []string{"New password: ", "Repeat password: "} {
		if _, err := fmt.Fprint(d.errw, prompt); err != nil {
			return secret.Secret{}, err
		}
		b, err := term.ReadPassword(int(f.Fd())) // #nosec G115 -- a file descriptor fits in int
		printf(d.errw, "\n")
		if err != nil {
			return secret.Secret{}, err
		}
		pws[i] = string(b)
	}
	if pws[0] != pws[1] {
		return secret.Secret{}, errors.New("passwords do not match")
	}
	return secret.New(pws[0]), nil
}

/* newPassword reads a new password and applies the password policy. */
func newPassword(file string, d deps) (secret.Secret, error) {
	pw, err := readPassword(file, d)
	if err != nil {
		return secret.Secret{}, err
	}
	if err := auth.ValidateNewPassword(pw.Reveal()); err != nil {
		return secret.Secret{}, err
	}
	return pw, nil
}

func installCmd(ctx context.Context, args []string, d deps) error {
	var o install.Options
	var ntp, dns, mirror string
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(d.errw)
	fs.StringVar(&o.PublicHost, "public-host", "", "DNS name or IPv4 address of the panel")
	fs.StringVar(&o.ImageTag, "image-tag", "", "tag of the nms/api and nms/gateway images")
	fs.StringVar(&o.WebCertFile, "web-cert", "", "corporate web certificate (PEM); default: self-signed by the internal CA")
	fs.StringVar(&o.WebKeyFile, "web-key", "", "key of --web-cert (PEM)")
	fs.StringVar(&ntp, "infra-ntp", "", "internal NTP servers, comma-separated")
	fs.StringVar(&dns, "infra-dns", "", "internal DNS servers, comma-separated")
	fs.StringVar(&mirror, "infra-mirror", "", "internal OS package mirrors, comma-separated")
	fs.StringVar(&o.AdminUser, "admin-user", install.DefaultAdminUser, "name of the first administrator")
	fs.StringVar(&o.AdminPasswordFile, "admin-password-file", "", "file with the administrator's password")
	fs.StringVar(&o.TOTPSecretOut, "totp-secret-out", "", "CI only: write the administrator's TOTP secret to this file")
	fs.BoolVar(&o.NonInteractive, "non-interactive", false, "never prompt; --admin-password-file is required")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	o.InfraNTP, o.InfraDNS, o.InfraMirror = splitList(ntp), splitList(dns), splitList(mirror)
	o.Out = d.out
	if !o.NonInteractive && o.AdminPasswordFile == "" {
		if err := install.Preflight(o, d.sys); err != nil { /* before asking for anything */
			return err
		}
		pw, err := newPassword("", d)
		if err != nil {
			return err
		}
		o.AdminPassword = pw
	}
	if exe, err := os.Executable(); err == nil && exe != install.HostBinary {
		printf(d.errw, "warning: the audit anchor timer runs %s; install this binary there\n", install.HostBinary)
	}
	return install.Run(ctx, o, d.sys)
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
