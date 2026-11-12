package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mdp/qrterminal/v3"

	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
	"github.com/beekamai/network-scheme/internal/install"
)

const executorUsage = `usage:
  nmsctl executor enable|disable
  nmsctl executor policy show|check|edit [--file F]
  nmsctl executor enroll U [--replace] [--yes] [--totp-secret-out F]
  nmsctl executor grant U write G|write-admin|unmask|audit-read [--yes]
  nmsctl executor revoke U write G|write-admin|unmask|audit-read|--all
  nmsctl executor freeze on [--reason TEXT]
  nmsctl executor freeze off [--reason TEXT] [--drop-panel-request]
  nmsctl executor unlock U|--global
  nmsctl executor model-verify --driver mes6|mes10|esr --model RE --firmware RE [--strategy k=v ...] --note TEXT
      (RE matches the whole model or firmware string: stored as ^(?:RE)$)
  nmsctl executor registry verify | reset [--i-understand] [--drop-panel-request]
  nmsctl executor audit verify
  nmsctl executor key rotate [--yes]
      (stops the executor, re-seals its registry under a new sealing key, starts it again)
` + deviceLines + `(U: a panel user name or #id)`

const deviceLines = `  nmsctl executor device add --device ID --address A --group G --driver mes6|mes10|esr [--port P]
      [--allow-ssh-rsa-sha1] [--backup-via-executor] [--fingerprint SHA256:...]
  nmsctl executor device accept-hostkey --device ID [--address A] [--port P] [--group G] [--driver D]
      [--allow-ssh-rsa-sha1] [--backup-via-executor] [--fingerprint SHA256:...]
      (without --fingerprint the executor shows the host key it read and asks; no TOFU;
       a flag given as --flag=false turns it off)
  nmsctl executor device writes on|off --device ID
  nmsctl executor device list
`

const deviceUsage = "usage:\n" + deviceLines

/* policyFile is the executor's policy on the host; tests point it elsewhere. */
var policyFile = install.DefaultEtc + "/" + install.PolicyFile

var operatorRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

/* hostOperator is the host account running nmsctl (sudo's caller first), recorded in the executor's audit only. */
func hostOperator() string {
	for _, v := range []string{os.Getenv("SUDO_USER"), os.Getenv("USER")} {
		if operatorRe.MatchString(v) {
			return v
		}
	}
	return ""
}

/*
executorCmd runs "nmsctl executor …" on the host. Every command but the
local part of the policy commands is a request to the executor daemon
(execCall); the host-only operations exist nowhere else (security.md 5.1a).
*/
func executorCmd(ctx context.Context, args []string, d deps) error {
	if d.sys.InContainer() {
		return errors.New("nmsctl executor runs on the host, not in a container")
	}
	if len(args) == 0 {
		return errors.New(executorUsage)
	}
	cmd, rest := args[0], args[1:]
	if len(rest) > 0 && (cmd == "policy" || cmd == "freeze" || cmd == "registry" || cmd == "audit" || cmd == "device" || cmd == "key") {
		cmd, rest = cmd+" "+rest[0], rest[1:]
	}
	switch cmd {
	case "enable", "disable":
		if len(rest) > 0 {
			return errors.New(executorUsage)
		}
		return setEnabled(ctx, d, cmd == "enable")
	case "policy show", "policy check":
		if len(rest) > 0 {
			return errors.New(executorUsage)
		}
		return policyCheck(ctx, d, cmd == "policy show")
	case "policy edit":
		return policyEdit(ctx, d, rest)
	case "enroll":
		return enroll(ctx, d, rest)
	case "grant", "revoke":
		return grantRevoke(ctx, d, cmd, rest)
	case "freeze on", "freeze off":
		fs := newFlags(cmd)
		reason := fs.String("reason", "", "why (recorded in the executor audit)")
		drop := fs.Bool("drop-panel-request", false, "off: discard a pending freeze request from the panel (it would freeze again)")
		if err := fs.Parse(rest); err != nil || fs.NArg() > 0 || (cmd == "freeze on" && *drop) {
			return errors.New("usage: nmsctl executor freeze on [--reason TEXT] | off [--reason TEXT] [--drop-panel-request]")
		}
		c := execadmin.CmdFreezeOn
		if cmd == "freeze off" {
			c = execadmin.CmdFreezeOff
		}
		return show(ctx, d, execadmin.Request{Cmd: c, Reason: *reason, DropPanel: *drop})
	case "unlock":
		if len(rest) != 1 {
			return errors.New("usage: nmsctl executor unlock U|--global")
		}
		if rest[0] == "--global" {
			return show(ctx, d, execadmin.Request{Cmd: execadmin.CmdUnlock, Global: true})
		}
		return show(ctx, d, execadmin.Request{Cmd: execadmin.CmdUnlock, User: rest[0]})
	case "model-verify":
		return modelVerify(ctx, d, rest)
	case "registry verify", "registry reset":
		fs := newFlags(cmd)
		sure := fs.Bool("i-understand", false, "reset: revoke every grant, disable writes on every device, clear host keys and model profiles")
		drop := fs.Bool("drop-panel-request", false, "reset: discard a pending freeze request from the panel (it would freeze again)")
		if err := fs.Parse(rest); err != nil || fs.NArg() > 0 || (cmd == "registry verify" && (*sure || *drop)) {
			return errors.New("usage: nmsctl executor registry verify | reset [--i-understand] [--drop-panel-request]")
		}
		if cmd == "registry verify" {
			return show(ctx, d, execadmin.Request{Cmd: execadmin.CmdRegistryVerify})
		}
		return show(ctx, d, execadmin.Request{Cmd: execadmin.CmdRegistryReset, IUnderstand: *sure, DropPanel: *drop})
	case "key rotate":
		return sealingRotate(ctx, d, rest)
	case "audit verify":
		if len(rest) > 0 {
			return errors.New(executorUsage)
		}
		return show(ctx, d, execadmin.Request{Cmd: execadmin.CmdAuditVerify})
	case "device add", "device accept-hostkey", "device writes", "device list":
		return deviceCmd(ctx, d, strings.TrimPrefix(cmd, "device "), rest)
	}
	return errors.New(executorUsage)
}

/*
deviceCmd runs nmsctl executor device. add and accept-hostkey without
--fingerprint are two steps: the executor reads the host key (no
authentication) and shows it with the routing fields, the host confirms
(there is no --yes: accepting a key unseen would be TOFU), and the
confirmation carries the fingerprint, which the executor reads again.
*/
func deviceCmd(ctx context.Context, d deps, action string, args []string) error {
	usage := errors.New(strings.TrimSuffix(deviceUsage, "\n"))
	if action == "writes" {
		if len(args) == 0 || (args[0] != "on" && args[0] != "off") {
			return usage
		}
		action, args = "writes-"+args[0], args[1:]
	}
	req := execadmin.Request{Cmd: execadmin.CmdDevice, Action: action}
	fs := newFlags("device " + action)
	if action != "list" {
		fs.Int64Var(&req.DeviceID, "device", 0, "panel device id")
	}
	if action == "add" || action == "accept-hostkey" {
		fs.StringVar(&req.Address, "address", "", "IPv4 address in a management subnet")
		fs.Int64Var(&req.Port, "port", 0, "SSH port (add: 22)")
		fs.StringVar(&req.Group, "group", "", "write group")
		fs.StringVar(&req.Driver, "driver", "", "write driver line: mes6, mes10 or esr")
		fs.Var(optBool{&req.AllowSHA1}, "allow-ssh-rsa-sha1", "allow the ssh-rsa (SHA-1) host key signature (MES 6.x); =false turns it off")
		fs.Var(optBool{&req.Backup}, "backup-via-executor", "the executor backs the device up; =false turns it off")
		fs.StringVar(&req.Fingerprint, "fingerprint", "", "the host key fingerprint expected (from the device console)")
	}
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || (action != "list" && req.DeviceID <= 0) {
		return usage
	}
	if (action != "add" && action != "accept-hostkey") || req.Fingerprint != "" {
		return show(ctx, d, req)
	}
	resp, err := execCall(ctx, d, req)
	if err != nil {
		return err
	}
	if !resp.OK || resp.Device == nil {
		return printResponse(d, resp)
	}
	v := resp.Device
	printf(d.out, "%s", terminalSafe(fmt.Sprintf("Device %d: %s:%d, group %s, driver %s, ssh-rsa SHA-1 %v, backup via executor %v\nHost key read by the executor: %s %s\n",
		v.ID, v.Address, v.Port, v.Group, v.Driver, v.AllowSHA1, v.Backup, v.Algo, v.Fingerprint)))
	if v.PinnedFP != "" {
		printf(d.out, "Pinned so far: %s (registry row version %d)\n", terminalSafe(v.PinnedFP), v.Version)
	}
	if v.PanelName != "" || v.PanelAddress != "" {
		printf(d.out, "%s", terminalSafe(fmt.Sprintf("The panel calls it %q at %s (shown only; the address above is what is stored).\n", v.PanelName, v.PanelAddress)))
	}
	if err := confirm(d, "Compare the fingerprint with the device console (show crypto key / ssh-keygen -l). Accept this host key and these fields?"); err != nil {
		return err
	}
	/* The confirmation names exactly what was shown: every field, the key, and (accept-hostkey) the row version. */
	req.Address, req.Port, req.Group, req.Driver = v.Address, v.Port, v.Group, v.Driver
	req.AllowSHA1, req.Backup, req.Fingerprint = &v.AllowSHA1, &v.Backup, v.Fingerprint
	if action == "accept-hostkey" {
		req.DeviceVersion = v.Version
	}
	return show(ctx, d, req)
}

/* optBool is a boolean flag that is nil until given: --x is true, --x=false false, absent keeps the registry's value. */
type optBool struct{ p **bool }

func (o optBool) String() string {
	if o.p == nil || *o.p == nil {
		return ""
	}
	return strconv.FormatBool(**o.p)
}

func (o optBool) Set(v string) error {
	b, err := strconv.ParseBool(v)
	if err != nil {
		return err
	}
	*o.p = &b
	return nil
}

func (optBool) IsBoolFlag() bool { return true }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

/* limited collects at most execadmin.MaxResponse bytes and fails beyond. */
type limited struct{ bytes.Buffer }

func (l *limited) Write(p []byte) (int, error) {
	if l.Len()+len(p) > execadmin.MaxResponse+1 {
		return 0, errors.New("executor response too large")
	}
	return l.Buffer.Write(p)
}

/* execCall sends one request to the executor daemon (docker compose exec -T executor /executor admin) and returns its response. */
func execCall(ctx context.Context, d deps, req execadmin.Request) (execadmin.Response, error) {
	var resp execadmin.Response
	req.V, req.Operator = execadmin.Version, hostOperator()
	if err := req.Validate(); err != nil {
		return resp, err
	}
	line, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	var out limited
	if err := install.RunInExecutor(ctx, d.sys, install.DefaultEtc, append(line, '\n'), &out, d.errw); err != nil {
		return resp, fmt.Errorf("executor: %w (is the executor container running?)", err)
	}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		return resp, fmt.Errorf("executor: malformed response: %w", err)
	}
	return resp, nil
}

/* show runs a request and prints its result; a refusal or failure is an error. */
func show(ctx context.Context, d deps, req execadmin.Request) error {
	resp, err := execCall(ctx, d, req)
	if err != nil {
		return err
	}
	return printResponse(d, resp)
}

func printResponse(d deps, resp execadmin.Response) error {
	if resp.Text != "" {
		printf(d.out, "%s\n", terminalSafe(strings.TrimSuffix(resp.Text, "\n")))
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "refused"
		}
		return fmt.Errorf("executor: %s", terminalSafe(resp.Error))
	}
	return nil
}

/*
terminalSafe replaces C0 (but newline and tab), DEL and C1 control
characters, and the bidirectional and invisible format characters, with
"?": the daemon's texts carry database error messages and names the api
controls, which must never reach the operator's terminal as escape
sequences (OSC 52 clipboard writes, cursor tricks) nor reorder what the
operator reads (U+202E). Other text, Cyrillic included, is kept.
*/
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7f && r <= 0x9f):
			return '?'
		case r == 0x061c || r == 0x200b || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) ||
			(r >= 0x2066 && r <= 0x2069) || r == 0xfeff || r == utf8.RuneError:
			return '?'
		}
		return r
	}, s)
}

/* confirm asks a yes/no question on stderr and reads the answer from stdin; only yes goes on. */
func confirm(d deps, question string) error {
	printf(d.errw, "%s [y/N] ", question)
	ans, err := bufio.NewReader(io.LimitReader(d.in, 64)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
		return nil
	}
	return errors.New("not confirmed: nothing changed")
}

/*
bind runs a two-step command that binds a panel user (D10): the daemon
names the user it found (id, name, creation date), the host confirms (or
--yes), and the second request carries that id and name, which the daemon
checks again.
*/
func bind(ctx context.Context, d deps, req execadmin.Request, question string, yes bool) (execadmin.Response, error) {
	resp, err := execCall(ctx, d, req)
	if err != nil {
		return resp, err
	}
	if !resp.OK || resp.Confirm == nil {
		return resp, printResponse(d, resp)
	}
	u := resp.Confirm
	printf(d.out, "Panel user #%d %q, created %s.\n", u.ID, u.Username, u.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	if !yes {
		if err := confirm(d, question); err != nil {
			return resp, err
		}
	}
	req.User, req.UserID, req.UserCreated = u.Username, u.ID, u.CreatedAt
	resp, err = execCall(ctx, d, req)
	if err != nil {
		return resp, err
	}
	return resp, printResponse(d, resp)
}

/* enroll binds a new change TOTP to a panel user and prints it once as a QR code. */
func enroll(ctx context.Context, d deps, args []string) error {
	bad := errors.New("usage: nmsctl executor enroll U [--replace] [--yes] [--totp-secret-out F]")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return bad
	}
	user := args[0]
	fs := newFlags("enroll")
	replace := fs.Bool("replace", false, "overwrite an existing change TOTP")
	yes := fs.Bool("yes", false, "do not ask for confirmation (CI)")
	totpOut := fs.String("totp-secret-out", "", "CI only: write the secret to this new file")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		return bad
	}
	if err := checkNewFile(*totpOut); err != nil {
		return err
	}
	q := "Enroll a change TOTP for this user?"
	if *replace {
		q = "Replace the change TOTP of this user (the old one stops working)?"
	}
	resp, err := bind(ctx, d, execadmin.Request{Cmd: execadmin.CmdEnroll, User: user, Replace: *replace}, q, *yes)
	if err != nil {
		return err
	}
	e := resp.Enrollment
	if e == nil || e.URI == "" || e.Secret == "" {
		return errors.New("executor: no secret in the enrollment response")
	}
	var b strings.Builder
	b.WriteString("Scan the QR code with an authenticator app (shown once; it confirms changes on the executor, not the login):\n\n")
	qrterminal.GenerateHalfBlock(e.URI, qrterminal.M, &b)
	fmt.Fprintf(&b, "\n%s%s\n", install.TOTPSecretLinePrefix, e.Secret)
	printf(d.out, "%s", b.String())
	if *totpOut != "" {
		if err := writeNewFile(*totpOut, []byte(e.Secret+"\n")); err != nil {
			return err
		}
		printf(d.out, "WARNING: the change TOTP secret was written to %s (--totp-secret-out is for CI only); delete it after use.\n", *totpOut)
	}
	return nil
}

/* checkNewFile accepts "" or a path that does not exist yet in an existing directory. */
func checkNewFile(p string) error {
	if p == "" {
		return nil
	}
	if _, err := os.Lstat(p); err == nil {
		return fmt.Errorf("%s: must not exist", p)
	}
	if st, err := os.Stat(filepath.Dir(p)); err != nil || !st.IsDir() {
		return fmt.Errorf("%s: parent directory does not exist", p)
	}
	return nil
}

func writeNewFile(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path given by the operator (CI)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Sync(), f.Close())
}

/* grantRevoke parses "U write G | write-admin | unmask | audit-read" (revoke also "U --all"). */
func grantRevoke(ctx context.Context, d deps, cmd string, args []string) error {
	bad := fmt.Errorf("usage: nmsctl executor %s U write G|write-admin|unmask|audit-read", cmd)
	var yes, all bool
	var words []string
	for _, a := range args {
		switch {
		case a == "--yes" && cmd == "grant":
			yes = true
		case a == "--all" && cmd == "revoke":
			all = true
		case strings.HasPrefix(a, "-"):
			return bad
		default:
			words = append(words, a)
		}
	}
	req := execadmin.Request{Cmd: cmd, All: all}
	switch {
	case all && len(words) == 1:
		req.User = words[0]
	case !all && len(words) == 2:
		req.User, req.Kind = words[0], words[1]
	case !all && len(words) == 3 && words[1] == execadmin.KindWrite:
		req.User, req.Kind, req.Group = words[0], words[1], words[2]
	default:
		return bad
	}
	if cmd == "revoke" {
		return show(ctx, d, req)
	}
	_, err := bind(ctx, d, req, "Grant this user "+strings.TrimSpace(req.Kind+" "+req.Group)+"?", yes)
	return err
}

/* strategies collects repeated --strategy k=v. */
type strategies map[string]string

func (s strategies) String() string { return "" }

func (s strategies) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return errors.New("--strategy wants key=value")
	}
	if _, dup := s[k]; dup {
		return fmt.Errorf("--strategy %s given twice", k)
	}
	s[k] = val
	return nil
}

func modelVerify(ctx context.Context, d deps, args []string) error {
	req := execadmin.Request{Cmd: execadmin.CmdModelVerify, Strategies: strategies{}}
	fs := newFlags("model-verify")
	fs.StringVar(&req.Driver, "driver", "", "write driver line: mes6, mes10 or esr")
	fs.StringVar(&req.Model, "model", "", "regular expression of the model (show version)")
	fs.StringVar(&req.Firmware, "firmware", "", "regular expression of the firmware (show version)")
	fs.StringVar(&req.Note, "note", "", "what was verified on the stand, where and by whom")
	fs.Var(strategies(req.Strategies), "strategy", "strategy override key=value (repeatable)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errors.New("usage: nmsctl executor model-verify --driver mes6|mes10|esr --model RE --firmware RE [--strategy k=v ...] --note TEXT")
	}
	if len(req.Strategies) == 0 {
		req.Strategies = nil
	}
	return show(ctx, d, req)
}

/* readPolicy reads the host's policy file, bounded as the executor reads it. */
func readPolicy() ([]byte, error) {
	f, err := os.Open(policyFile) // #nosec G304 -- the installed policy file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, execpolicy.MaxSize+1))
}

/* setEnabled flips enabled in the host's policy file (atomically, comments kept) and has the executor reread it. */
func setEnabled(ctx context.Context, d deps, on bool) error {
	data, err := readPolicy()
	if err != nil {
		return err
	}
	next, err := execpolicy.SetEnabled(data, on)
	if err != nil {
		return fmt.Errorf("%s: %w (fix it with nmsctl executor policy edit)", policyFile, err)
	}
	if err := install.ReplaceFile(policyFile, next); err != nil {
		return err
	}
	action := "disable"
	if on {
		action = "enable"
	}
	return reloaded(ctx, d, action)
}

/* reloaded has the executor reread the policy nmsctl just replaced; a failure says the file did change. */
func reloaded(ctx context.Context, d deps, action string) error {
	if err := show(ctx, d, execadmin.Request{Cmd: execadmin.CmdPolicyReload, Action: action}); err != nil {
		return fmt.Errorf("%s was replaced, but the executor did not confirm reading it (it rereads it by mtime when running): %w", policyFile, err)
	}
	return nil
}

/* policyCheck validates the host's file here, then asks the executor what it reads (show: and prints it). */
func policyCheck(ctx context.Context, d deps, showIt bool) error {
	data, err := readPolicy()
	if err != nil {
		return err
	}
	_, local := execpolicy.Parse(data)
	if local != nil {
		printf(d.errw, "%s: %v\n", policyFile, local)
	} else {
		printf(d.out, "%s: valid (sha256 %x)\n", policyFile, execpolicy.Sum(data))
	}
	c := execadmin.CmdPolicyCheck
	if showIt {
		c = execadmin.CmdPolicyShow
	}
	if err := show(ctx, d, execadmin.Request{Cmd: c}); err != nil {
		return err
	}
	if local != nil {
		return errFailed
	}
	return nil
}

/*
policyEdit replaces the policy with a validated new version: from --file, or
edited in $VISUAL/$EDITOR (vi) on a temporary copy next to the policy. An
invalid version changes nothing.
*/
func policyEdit(ctx context.Context, d deps, args []string) error {
	fs := newFlags("policy edit")
	from := fs.String("file", "", "new policy file (default: edit the current one)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errors.New("usage: nmsctl executor policy edit [--file F]")
	}
	var next []byte
	var err error
	if *from != "" {
		next, err = os.ReadFile(*from) // #nosec G304 -- file given by the operator
	} else {
		next, err = editCopy(ctx, d)
	}
	if err != nil {
		return err
	}
	if _, err := execpolicy.Parse(next); err != nil {
		return fmt.Errorf("the new policy is invalid, nothing changed: %w", err)
	}
	if err := install.ReplaceFile(policyFile, next); err != nil {
		return err
	}
	return reloaded(ctx, d, "edit")
}

func editCopy(ctx context.Context, d deps) ([]byte, error) {
	cur, err := readPolicy()
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(policyFile), ".executor.yaml.edit.")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, werr := tmp.Write(cur)
	if err := errors.Join(werr, tmp.Close()); err != nil {
		return nil, err
	}
	if err := d.edit(ctx, tmp.Name()); err != nil {
		return nil, fmt.Errorf("editor: %w", err)
	}
	return os.ReadFile(tmp.Name()) // #nosec G304 -- our own temporary file
}

/* runEditor runs the host operator's editor ($VISUAL, $EDITOR, else vi) on path, on the terminal. */
func runEditor(ctx context.Context, path string) error {
	editor := "vi"
	for _, v := range []string{os.Getenv("VISUAL"), os.Getenv("EDITOR")} {
		if v != "" {
			editor = v
			break
		}
	}
	argv := strings.Fields(editor)
	cmd := exec.CommandContext(ctx, argv[0], append(argv[1:], path)...) // #nosec G204 G702 -- the host operator's own editor (host-only command, as visudo)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
