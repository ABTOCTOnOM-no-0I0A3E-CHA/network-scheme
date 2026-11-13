/*
Package execadmin is the wire format of the executor's administration
socket: one JSON request line from nmsctl (through docker compose exec -T
executor /executor admin, on stdin: never in argv) and one JSON response
line back. Both sides import it, so nmsctl links nothing of the executor;
it holds types and syntactic checks only. The daemon re-validates every
request and decides alone (the host is trusted, the request is still
checked: security.md 4, TB6).
*/
package execadmin

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

/* Version of the request format; any other is refused. */
const Version = 1

/* Size bounds of one request and one response line. */
const (
	MaxRequest  = 64 << 10
	MaxResponse = 1 << 20
)

/* Commands of the socket (nmsctl executor …). */
const (
	CmdPolicyShow     = "policy-show"
	CmdPolicyCheck    = "policy-check"
	CmdPolicyReload   = "policy-reload" /* after nmsctl changed the file on the host: Action enable|disable|edit */
	CmdEnroll         = "enroll"
	CmdGrant          = "grant"
	CmdRevoke         = "revoke"
	CmdFreezeOn       = "freeze-on"
	CmdFreezeOff      = "freeze-off"
	CmdUnlock         = "unlock"
	CmdModelVerify    = "model-verify"
	CmdRegistryVerify = "registry-verify"
	CmdRegistryReset  = "registry-reset"
	CmdAuditVerify    = "audit-verify"
	CmdDevice         = "device" /* Action add|accept-hostkey|writes-on|writes-off|list */
)

/* Commands lists every command. */
var Commands = []string{CmdPolicyShow, CmdPolicyCheck, CmdPolicyReload, CmdEnroll, CmdGrant, CmdRevoke, CmdFreezeOn,
	CmdFreezeOff, CmdUnlock, CmdModelVerify, CmdRegistryVerify, CmdRegistryReset, CmdAuditVerify, CmdDevice}

/* Grant kinds (exec.write_grant.kind); only write names a group. */
const (
	KindWrite      = "write"
	KindWriteAdmin = "write-admin"
	KindUnmask     = "unmask"
	KindAuditRead  = "audit-read"
)

/* Kinds lists the grant kinds. */
var Kinds = []string{KindWrite, KindWriteAdmin, KindUnmask, KindAuditRead}

/*
RestoredMarker is the file nmsctl restore puts into the executor's state
directory next to the state file; the executor, at its next start, turns it
into a sticky freeze with RestoredReason (its audit and status show it) and
removes it. It can only ask for a freeze, so it needs no MAC.
*/
const (
	RestoredMarker = "restored-from-backup"
	RestoredReason = "host: restored from backup"
)

/* Drivers are the write driver lines (exec.write_device.write_driver). */
var Drivers = []string{"mes6", "mes10", "esr"}

/*
Request is one command. User names a panel user ("name" or "#id"); a
command that binds a user (enroll, grant) is two steps: without UserID the
daemon only answers with the user it found (Response.Confirm), and nmsctl
sends it again with UserID, User and UserCreated set to the confirmed id,
name and creation date (D10).
*/
type Request struct {
	V           int               `json:"v"`
	Cmd         string            `json:"cmd"`
	Operator    string            `json:"operator,omitempty"` /* host account running nmsctl, for the audit only */
	User        string            `json:"user,omitempty"`
	UserID      int64             `json:"user_id,omitempty"`
	UserCreated time.Time         `json:"user_created_at,omitzero"` /* the confirmed user's creation date (second step) */
	Kind        string            `json:"kind,omitempty"`
	Group       string            `json:"group,omitempty"`
	All         bool              `json:"all,omitempty"`
	Replace     bool              `json:"replace,omitempty"`
	Global      bool              `json:"global,omitempty"`
	IUnderstand bool              `json:"i_understand,omitempty"`
	DropPanel   bool              `json:"drop_panel_request,omitempty"` /* freeze off, registry reset: discard a pending panel freeze request */
	Reason      string            `json:"reason,omitempty"`
	Action      string            `json:"action,omitempty"`
	Driver      string            `json:"driver,omitempty"`
	Model       string            `json:"model,omitempty"`
	Firmware    string            `json:"firmware,omitempty"`
	Note        string            `json:"note,omitempty"`
	Strategies  map[string]string `json:"strategies,omitempty"`
	/*
		The device commands: the device, its routing fields and flags (accept-hostkey: only those
		that change; a nil flag keeps the registry's), Fingerprint, the host key the host confirmed
		(without it: a preview), and DeviceVersion, the registry row version the preview showed
		(accept-hostkey: a row changed since is refused).
	*/
	DeviceID      int64  `json:"device_id,omitempty"`
	Address       string `json:"address,omitempty"`
	Port          int64  `json:"port,omitempty"`
	AllowSHA1     *bool  `json:"allow_ssh_rsa_sha1,omitempty"`
	Backup        *bool  `json:"backup_via_executor,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	DeviceVersion int64  `json:"device_version,omitempty"`
}

var (
	userRe     = regexp.MustCompile(`^[^\x00-\x1f\x7f#\s][^\x00-\x1f\x7f]{0,63}$`)
	groupRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	operatorRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{0,64}$`)
	strategyRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	/* FingerprintRe is a host key's SHA-256 fingerprint as OpenSSH prints it (exec.write_device.hostkey_fp). */
	FingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

/* DeviceActions are the actions of CmdDevice. */
var DeviceActions = []string{"add", "accept-hostkey", "writes-on", "writes-off", "list"}

/* printable reports whether s is valid UTF-8 without control characters. */
func printable(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

/* MaxPattern bounds a model or firmware pattern: stored anchored as ^(?:RE)$, 6 bytes more, within the column's 256. */
const MaxPattern = 250

/* uses lists the optional fields each command takes; any other field set is refused. */
var uses = map[string][]string{
	CmdPolicyReload:  {"action"},
	CmdDevice:        {"action", "device_id", "address", "port", "group", "driver", "allow_ssh_rsa_sha1", "backup_via_executor", "fingerprint", "device_version"},
	CmdEnroll:        {"user", "user_id", "user_created_at", "replace"},
	CmdGrant:         {"user", "user_id", "user_created_at", "kind", "group"},
	CmdRevoke:        {"user", "kind", "group", "all"},
	CmdFreezeOn:      {"reason"},
	CmdFreezeOff:     {"reason", "drop_panel_request"},
	CmdUnlock:        {"user", "global"},
	CmdModelVerify:   {"driver", "model", "firmware", "note", "strategies"},
	CmdRegistryReset: {"i_understand", "drop_panel_request"},
}

/* fields reports which optional fields are set. */
func (r Request) fields() map[string]bool {
	return map[string]bool{
		"user": r.User != "", "user_id": r.UserID != 0, "user_created_at": !r.UserCreated.IsZero(), "kind": r.Kind != "",
		"group": r.Group != "", "all": r.All, "replace": r.Replace, "global": r.Global, "i_understand": r.IUnderstand, "drop_panel_request": r.DropPanel,
		"reason": r.Reason != "", "action": r.Action != "", "driver": r.Driver != "", "model": r.Model != "",
		"firmware": r.Firmware != "", "note": r.Note != "", "strategies": len(r.Strategies) > 0,
		"device_id": r.DeviceID != 0, "address": r.Address != "", "port": r.Port != 0, "allow_ssh_rsa_sha1": r.AllowSHA1 != nil,
		"backup_via_executor": r.Backup != nil, "fingerprint": r.Fingerprint != "", "device_version": r.DeviceVersion != 0,
	}
}

/* UserRef parses User: "#id" gives the id, anything else is a user name. */
func (r Request) UserRef() (id int64, name string, err error) {
	if s, ok := strings.CutPrefix(r.User, "#"); ok {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != s {
			return 0, "", fmt.Errorf("bad user id %q", r.User)
		}
		return id, "", nil
	}
	if !userRe.MatchString(r.User) {
		return 0, "", fmt.Errorf("bad user name %q", r.User)
	}
	return 0, r.User, nil
}

/* Validate checks the request's form for its command (both sides call it; the daemon decides the rest). */
func (r Request) Validate() error {
	if r.V != Version {
		return fmt.Errorf("request version %d, want %d", r.V, Version)
	}
	if !slices.Contains(Commands, r.Cmd) {
		return fmt.Errorf("unknown command %q", r.Cmd)
	}
	if !operatorRe.MatchString(r.Operator) {
		return errors.New("bad operator name")
	}
	if len(r.Reason) > 512 || !printable(r.Reason) {
		return errors.New("reason: at most 512 bytes of printable text")
	}
	for name, set := range r.fields() {
		if set && !slices.Contains(uses[r.Cmd], name) {
			return fmt.Errorf("%s takes no %s", r.Cmd, name)
		}
	}
	needUser := slices.Contains([]string{CmdEnroll, CmdGrant, CmdRevoke}, r.Cmd) || (r.Cmd == CmdUnlock && !r.Global)
	if needUser {
		if _, _, err := r.UserRef(); err != nil {
			return err
		}
	} else if r.User != "" || r.UserID != 0 {
		return fmt.Errorf("%s takes no user", r.Cmd)
	}
	if r.UserID < 0 {
		return errors.New("bad user_id")
	}
	switch r.Cmd {
	case CmdGrant, CmdRevoke:
		if r.Cmd == CmdRevoke && r.All {
			if r.Kind != "" || r.Group != "" {
				return errors.New("revoke --all takes no kind")
			}
			return nil
		}
		if !slices.Contains(Kinds, r.Kind) {
			return fmt.Errorf("kind %q, want one of %s", r.Kind, strings.Join(Kinds, ", "))
		}
		if (r.Kind == KindWrite) != (r.Group != "") || (r.Group != "" && !groupRe.MatchString(r.Group)) {
			return errors.New("write takes one write group (a-z0-9_.-, up to 64); the other kinds none")
		}
	case CmdUnlock:
		if r.Global == (r.User != "") {
			return errors.New("unlock takes a user or --global")
		}
	case CmdPolicyReload:
		if !slices.Contains([]string{"enable", "disable", "edit"}, r.Action) {
			return fmt.Errorf("policy-reload action %q", r.Action)
		}
	case CmdDevice:
		return r.validateDevice()
	case CmdModelVerify:
		return r.validateModel()
	}
	return nil
}

/*
validateDevice checks the form of a device command; whether the device,
address and key are acceptable the daemon decides (and audits).
*/
func (r Request) validateDevice() error {
	switch {
	case !slices.Contains(DeviceActions, r.Action):
		return fmt.Errorf("device action %q", r.Action)
	case r.DeviceID < 0 || r.DeviceVersion < 0:
		return errors.New("bad device id or version")
	case r.DeviceVersion != 0 && (r.Action != "accept-hostkey" || r.Fingerprint == ""):
		return errors.New("device_version binds an accept-hostkey confirmation only")
	case r.Address != "" && len(r.Address) > 64:
		return errors.New("bad address")
	case r.Port < 0 || r.Port > 65535:
		return errors.New("port: 1..65535")
	case r.Group != "" && !groupRe.MatchString(r.Group):
		return errors.New("write group: a-z0-9_.-, up to 64")
	case r.Driver != "" && !slices.Contains(Drivers, r.Driver):
		return fmt.Errorf("driver %q, want one of %s", r.Driver, strings.Join(Drivers, ", "))
	case r.Fingerprint != "" && !FingerprintRe.MatchString(r.Fingerprint):
		return errors.New("fingerprint: SHA256:<43 base64 characters>, as ssh-keygen -l prints it")
	}
	return nil
}

func (r Request) validateModel() error {
	switch {
	case !slices.Contains(Drivers, r.Driver):
		return fmt.Errorf("driver %q, want one of %s", r.Driver, strings.Join(Drivers, ", "))
	case r.Model == "" || len(r.Model) > MaxPattern || !printable(r.Model):
		return fmt.Errorf("model: a regular expression of 1..%d printable bytes", MaxPattern)
	case r.Firmware == "" || len(r.Firmware) > MaxPattern || !printable(r.Firmware):
		return fmt.Errorf("firmware: a regular expression of 1..%d printable bytes", MaxPattern)
	case utf8.RuneCountInString(r.Note) < 1 || utf8.RuneCountInString(r.Note) > 1000 || !printable(r.Note):
		return errors.New("note: 1..1000 characters of printable text (what was verified, where, by whom)")
	case len(r.Strategies) > 64:
		return errors.New("at most 64 strategies")
	}
	for k, v := range r.Strategies {
		if !strategyRe.MatchString(k) || v == "" || len(v) > 256 || !printable(v) {
			return fmt.Errorf("strategy %q: key a-z0-9_. and a printable value of 1..256 bytes", k)
		}
	}
	return nil
}

/* User is a panel user as core.user shows it to the executor (display and refusal only). */
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	Disabled  bool      `json:"disabled"`
}

/*
Enrollment is the new change TOTP secret: the one value that crosses the
socket in clear, once, to the host that prints it as a QR code. It is
serialized as JSON on purpose; String and LogValue mask it.
*/
type Enrollment struct {
	URI    string `json:"uri"`
	Secret string `json:"secret"`
}

/* String masks the secret. */
func (Enrollment) String() string { return "***" }

/* GoString masks the secret. */
func (Enrollment) GoString() string { return "***" }

/* LogValue masks the secret. */
func (Enrollment) LogValue() slog.Value { return slog.StringValue("***") }

/* Response is the answer to one request. */
type Response struct {
	OK         bool        `json:"ok"`
	Error      string      `json:"error,omitempty"`
	Text       string      `json:"text,omitempty"`
	Confirm    *User       `json:"confirm,omitempty"`
	Enrollment *Enrollment `json:"enrollment,omitempty"`
	Device     *Device     `json:"device,omitempty"` /* a device add or accept-hostkey preview: what the host confirms */
}

/* Device is what the host confirms of a device: its routing fields, flags and the host key the executor read, and the panel's view (display only). */
type Device struct {
	ID           int64  `json:"id"`
	Address      string `json:"address"`
	Port         int64  `json:"port"`
	Group        string `json:"write_group"`
	Driver       string `json:"write_driver"`
	AllowSHA1    bool   `json:"allow_ssh_rsa_sha1"`
	Backup       bool   `json:"backup_via_executor"`
	Algo         string `json:"hostkey_algo"`
	Fingerprint  string `json:"hostkey_fp"`
	PinnedFP     string `json:"pinned_fp,omitempty"`
	Version      int64  `json:"version,omitempty"` /* accept-hostkey: the registry row version previewed */
	PanelName    string `json:"panel_name,omitempty"`
	PanelAddress string `json:"panel_address,omitempty"`
}
