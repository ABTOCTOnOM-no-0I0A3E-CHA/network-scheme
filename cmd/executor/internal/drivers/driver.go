/*
Package drivers is the executor's write-driver interface (architecture.md 5):
one driver per firmware line (mes6, mes10, esr), each a grammar for package
core plus the line's masking, GUI forms and Save/Commit/Rollback session
strategies. The line packages register themselves (Register); For returns a
registered driver. Every write driver is unverified (Verified false) until a
run on a stand: the syntax comes from .superpowers/research/eltex-cli.md [R].
*/
package drivers

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	rdrivers "github.com/beekamai/network-scheme/internal/drivers"
)

/* WriteDriver is one firmware line's write driver. */
type WriteDriver interface {
	Line() strategy.Line
	Verified() bool         /* false until a stand run */
	Defaults() strategy.Set /* the transport strategies of the line */
	Strategies() Strategies /* the session strategies of the line */
	Grammar() *core.Grammar /* for Mode, Next, Reconcile and NewRules */
	Normalize(line string, m core.Mode) (string, error)
	Classify(line string, m core.Mode, c core.Context) core.Verdict
	Complete(prefix string, m core.Mode) []string
	/* Targets resolves a management interface ("gi1/0/24", any spelling) or VLAN ("10") for core.Context.Mgmt. */
	Targets(kind, name string) ([]core.Target, bool)
	MaskSecrets(text string) string
	/* RenderForm turns a GUI form into lines typed from the privileged prompt; each passes Classify. */
	RenderForm(f Form) ([]string, error)
	Open(ctx context.Context, sh *transport.Shell, o Options) (Session, error)
}

/*
Session is an open driver session on one device. Send takes only a verdict
of the session's own mode and context (Classify again must give the same);
system commands (save, commit, snapshots, rollback) are the driver's.
*/
type Session interface {
	Mode() core.Mode
	Pre() Config /* the snapshot read at Open: the only target Rollback accepts */
	/* Classify classifies a typed line in the session's mode and context: the verdict Send takes. */
	Classify(line string) core.Verdict
	Snapshot(ctx context.Context) (Config, error)
	Send(ctx context.Context, v core.Verdict) (transport.Output, error)
	Save(ctx context.Context) error
	Commit(ctx context.Context, timeout time.Duration) error
	/* Rollback restores to (the pre-session snapshot) and requires sha256(normalize(running)) == to.SHA256 after. */
	Rollback(ctx context.Context, to Config) error
	Close(ctx context.Context) error
}

/* Options of Open. */
type Options struct {
	/* SessionID names the on-device snapshot (nms-pre-<SessionID>): [A-Za-z0-9-]{1,64}. */
	SessionID string
	/* Context is the management targets (from the registry address) and the policy rules of the session. */
	Context core.Context
	/* Strategies: the zero value takes the line's (WriteDriver.Strategies). */
	Strategies Strategies
	/* CommitTimeout is the ESR confirm timer of a rollback after confirm (the policy's esr_commit_timer_s); 0: 600 s. */
	CommitTimeout time.Duration
	/* Alert publishes an alert (as transport.Config.Alert); required. */
	Alert func(ctx context.Context, kind, severity string, deviceID int64, text string) error
}

/* KindRollbackMismatch is the alert when after a rollback the running configuration is not the pre-session one (high). */
const KindRollbackMismatch = "executor_rollback_mismatch"

/* Errors. */
var (
	ErrNotApplicable    = errors.New("drivers: not applicable to the firmware line")
	ErrNotSendable      = errors.New("drivers: not a safe or dangerous verdict of the session's mode")
	ErrSessionID        = errors.New("drivers: bad session id")
	ErrStrategy         = errors.New("drivers: strategy variant not implemented")
	ErrSnapshot         = errors.New("drivers: the rollback target is not the session's pre-session snapshot")
	ErrNoInverse        = errors.New("drivers: the session's commands have no automatic inverse; restore the pre-session backup (boot config + reload)")
	ErrRollbackMismatch = errors.New("drivers: after the rollback the running configuration differs from the pre-session one")
	ErrNothingToConfirm = errors.New("drivers: no commit to confirm")
	ErrTimeout          = errors.New("drivers: commit timeout out of 120..86400 s")
	ErrForm             = errors.New("drivers: bad form")
	ErrSnapshotLeft     = errors.New("drivers: the on-device snapshot file could not be deleted")
)

/* Config is a running configuration as read and its hash over the normalized text. */
type Config struct {
	Text   string
	SHA256 [32]byte
}

/* NewConfig hashes text: sha256(NormalizeText(text)), as the backups do. */
func NewConfig(text string) Config {
	return Config{Text: text, SHA256: sha256.Sum256([]byte(rdrivers.NormalizeText(text)))}
}

/* Valid reports whether the hash is the text's. */
func (c Config) Valid() bool { return c.SHA256 == NewConfig(c.Text).SHA256 }

/*
Strategies are the session's assumptions of the line [R §9], each with its
research section; the first variant is the default. Only the implemented
variants open a session (ErrStrategy otherwise). Profile overrides of these
keys come with the strategy keys of model_profile (follow-up of 4b.5).
*/
type Strategies struct {
	/* MES 6.x apply: immediate; candidate is documented without its entry command, so off. */
	Apply string `key:"apply" variants:"immediate,candidate" research:"§9.1, §2a"`
	/* MES safety net: none, or reload in N minutes armed at Open and cancelled at Save and Close. */
	SafetyNet string `key:"safety_net" variants:"none,reload-in,candidate-timer" research:"§9.2"`
	/* ReloadMinutes is the reload-in timer (MES 6.x: minutes 1..999; MES 10.x: hours minutes). */
	ReloadMinutes int `research:"§9.2, §2"`
	/* Save: MES 6.x write (+Y) or copy running-config startup-config; MES 10.x write startup-config; ESR confirm. */
	Save string `key:"save" variants:"write,copy,write-startup,confirm" research:"§9.4"`
	/* ExtraSave: ESR, a save after confirm (off: commit writes flash [R §1]). */
	ExtraSave bool `research:"§9.4, §1"`
	/* Commit: ESR end + commit confirm-timeout, or do commit from the configuration mode. */
	Commit string `key:"commit" variants:"end,do" research:"§9.8, §1"`
	/* Close: ESR, an unconfirmed commit is restored, or left to the timer. */
	Close string `key:"close" variants:"restore,timer" research:"§1"`
	/* Rollback: ESR restore / snapshot into candidate; MES 10.x replace running-config; MES 6.x inverse journal (Q7) or boot config + reload. */
	Rollback string `key:"rollback" variants:"restore-snapshot,replace,inverse,boot-reload" research:"§9.3, §1, §2"`
	/* Mask: always mask encrypted forms, or only clear text. */
	Mask string `key:"mask" variants:"always,selective" research:"§9.14, §7"`
}

/* implemented are the variants a session can run, per line ("" = the key does not apply). */
var implemented = map[strategy.Line]map[string][]string{
	strategy.MES6:  {"apply": {"immediate"}, "safety_net": {"none", "reload-in"}, "save": {"write", "copy"}, "commit": {""}, "close": {""}, "rollback": {"inverse"}, "mask": {"always"}},
	strategy.MES10: {"apply": {""}, "safety_net": {"none", "reload-in"}, "save": {"write-startup"}, "commit": {""}, "close": {""}, "rollback": {"replace"}, "mask": {"always"}},
	strategy.ESR:   {"apply": {""}, "safety_net": {"none"}, "save": {"confirm"}, "commit": {"end", "do"}, "close": {"restore", "timer"}, "rollback": {"restore-snapshot"}, "mask": {"always"}},
}

/* Check refuses a variant the line does not implement. */
func (s Strategies) Check(l strategy.Line) error {
	impl, ok := implemented[l]
	if !ok {
		return fmt.Errorf("%w: line %q", ErrStrategy, l)
	}
	v := reflect.ValueOf(s)
	for i := range v.NumField() {
		k := v.Type().Field(i).Tag.Get("key")
		if k == "" {
			continue
		}
		if val := v.Field(i).String(); !slices.Contains(impl[k], val) {
			return fmt.Errorf("%w: %s=%q on %s", ErrStrategy, k, val, l)
		}
	}
	if s.SafetyNet == "reload-in" && (s.ReloadMinutes < 1 || s.ReloadMinutes > 999) {
		return fmt.Errorf("%w: reload in %d minutes", ErrStrategy, s.ReloadMinutes)
	}
	return nil
}

var (
	regMu    sync.RWMutex
	registry = map[strategy.Line]WriteDriver{}
)

/* Register adds the driver of a line (from the line package's init); a second one for a line panics. */
func Register(d WriteDriver) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[d.Line()]; dup || !d.Line().Valid() {
		panic(fmt.Sprintf("drivers: bad or repeated write driver %q", d.Line()))
	}
	registry[d.Line()] = d
}

/* For returns the registered driver of line l. */
func For(l strategy.Line) (WriteDriver, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	d, ok := registry[l]
	return d, ok
}

/*
Base is the line-independent part of a driver: the grammar and its argument
types for Targets. The line packages embed it and add RenderForm and Open.
*/
type Base struct {
	L        strategy.Line
	G        *core.Grammar
	S        Strategies
	Ifs      []string /* argument types of glued interface names */
	SaveCopy bool     /* MES: copy to startup-config is the Save flow */
	VLANT    string   /* argument type of one VLAN */
}

/* Line is the firmware line. */
func (b Base) Line() strategy.Line { return b.L }

/* Verified is false for every write driver until a stand run. */
func (Base) Verified() bool { return false }

/* Defaults are the line's transport strategies. */
func (b Base) Defaults() strategy.Set { return strategy.Defaults(b.L) }

/* Strategies are the line's session strategies. */
func (b Base) Strategies() Strategies { return b.S }

/* Grammar is the line's compiled grammar. */
func (b Base) Grammar() *core.Grammar { return b.G }

/* MaskSecrets masks session input and output (Mask). */
func (Base) MaskSecrets(t string) string { return Mask(t) }

/* Normalize is the grammar's. */
func (b Base) Normalize(line string, m core.Mode) (string, error) { return b.G.Normalize(line, m) }

/*
Classify is the grammar's; on MES (SaveCopy) a copy whose destination is
startup-config in any spelling is the Save flow (SaveCopy).
*/
func (b Base) Classify(line string, m core.Mode, c core.Context) core.Verdict {
	v := b.G.Classify(line, m, c)
	if b.SaveCopy && (v.Class == core.Safe || v.Class == core.Dangerous) {
		switch saveCopy(v.Line) {
		case exactSave:
			return core.Verdict{Class: core.Control, Control: core.Save, Line: v.Line, Reason: core.ReasonGrammar}
		case maybeSave:
			return core.Verdict{Class: core.Denied, Line: v.Line, Reason: core.ReasonControl}
		}
	}
	return v
}

const (
	noSave = iota
	exactSave
	maybeSave
)

/*
saveCopy reads a normalized line as the device may: copy (or a prefix of
it, maybe after do) whose destination, lower case, without quotes, flash:,
nvram:, system: and slashes, is startup-config (exactSave when the line is
exactly "copy <src> <dst>") or a prefix of it, or extra words after one
(maybeSave: never sent, use the Save button).
*/
func saveCopy(line string) int {
	ts := strings.Fields(line)
	if len(ts) > 1 && strings.HasPrefix("do", unq(ts[0])) {
		ts = ts[1:]
	}
	if len(ts) < 3 || unq(ts[0]) == "" || !strings.HasPrefix("copy", unq(ts[0])) {
		return noSave
	}
	for i, t := range ts[2:] {
		switch d := saveDst(t); {
		case d == "startup-config" && i == 0 && len(ts) == 3 && ts[0] == "copy":
			return exactSave
		case d != "" && strings.HasPrefix("startup-config", d), maySave(t):
			return maybeSave
		}
	}
	return noSave
}

/* maySave: t, slashes ignored, is a prefix of a startup-config spelling ("sy", "flash:st"): the device may expand it. */
func maySave(t string) bool {
	r := strings.ReplaceAll(unq(t), "/", "")
	if r == "" {
		return unq(t) != "" /* only slashes: the start of "//startup-config" */
	}
	for _, s := range []string{"startup-config", "flash:startup-config", "nvram:startup-config", "system:startup-config"} {
		if r != "" && strings.HasPrefix(s, r) {
			return true
		}
	}
	return false
}

func unq(s string) string { return strings.ToLower(strings.Trim(s, `"'`)) }

/* saveDst strips a copy destination down to the file name the way a startup-config spelling would be. */
func saveDst(t string) string {
	t = unq(t)
	for {
		s := strings.TrimLeft(t, "/")
		for _, p := range []string{"flash:", "nvram:", "system:"} {
			s = strings.TrimPrefix(s, p)
		}
		if s == t {
			return t
		}
		t = s
	}
}

/* Complete is the grammar's. */
func (b Base) Complete(prefix string, m core.Mode) []string { return b.G.Complete(prefix, m) }

/* Targets resolves a management interface or VLAN of the line. */
func (b Base) Targets(kind, name string) ([]core.Target, bool) {
	switch kind {
	case "vlan":
		return b.G.Targets(b.VLANT, name)
	case "interface":
		for _, t := range b.Ifs {
			if ts, ok := b.G.Targets(t, name); ok {
				return ts, true
			}
		}
	}
	return nil, false
}

/* MustGrammar compiles a line's spec; a bad spec is a programming error. */
func MustGrammar(s core.Spec) *core.Grammar {
	g, err := core.NewGrammar(s)
	if err != nil {
		panic(err)
	}
	return g
}

var sidRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

/* Prepare checks the options of Open and fills the defaults. */
func Prepare(l strategy.Line, def Strategies, o Options) (Options, error) {
	if !sidRe.MatchString(o.SessionID) {
		return o, ErrSessionID
	}
	if o.Strategies == (Strategies{}) {
		o.Strategies = def
	}
	if o.CommitTimeout == 0 {
		o.CommitTimeout = 600 * time.Second
	}
	if o.Alert == nil {
		return o, errors.New("drivers: no alert function")
	}
	return o, o.Strategies.Check(l)
}

/* CommitSeconds checks an ESR commit timer [R §1]: 120..86400 s. */
func CommitSeconds(d time.Duration) (int, error) {
	s := int(d / time.Second)
	if d%time.Second != 0 || s < 120 || s > 86400 {
		return 0, ErrTimeout
	}
	return s, nil
}
