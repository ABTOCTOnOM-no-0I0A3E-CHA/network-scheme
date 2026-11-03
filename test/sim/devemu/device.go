package devemu

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

/* User is a local account of the emulated device. */
type User struct {
	Password  string
	Privilege int  /* 15: privileged prompt after login; lower: exec prompt */
	Expired   bool /* the password has expired: the device asks for a new one before the CLI [R §4] */
}

/* Options configure a Device. */
type Options struct {
	Users       map[string]User /* empty: any user, privilege 15 */
	InbandLogin bool            /* ask User Name:/Password: inside the channel [R §4, guess] */
	Start       time.Time       /* the fake clock's start; zero: 2026-01-01 00:00 UTC */
}

/* Entry is one thing a session received. */
type Entry struct {
	Session int
	Mode    string /* the prompt key: login, exec, privileged, config, a context mode, confirm, pager, expired */
	Kind    string /* line, answer, key, user, password, new-password */
	Input   string
}

/*
Device is one emulated device. It is safe for concurrent use: every session
and every API call takes its lock, so sessions share its state (one candidate
configuration on ESR [R §8]).
*/
type Device struct {
	P       *Profile
	fx      *Fixture
	mu      sync.Mutex
	opt     Options
	now     time.Time
	running *node
	cand    *node /* esr: candidate; mes: unused */
	saved   *node /* esr: flash (commit writes it [R §1]); mes: startup-config */
	backup  *node /* esr: the last confirmed running-config while a commit is pending */
	pending time.Time
	reload  time.Time /* mes: scheduled reload; zero: none */
	files   map[string]string
	rejects []reject
	journal []Entry
	sess    map[int]*Session
	nextID  int
	reboots int
	show    func(cmd string) (string, bool)
	onInput func(Entry)
}

type reject struct {
	re  *regexp.Regexp
	msg string
}

/* New returns a device in the state of the fixture: running = startup = config/running.cfg. */
func New(fx *Fixture, opt Options) *Device {
	root, err := parseConfig(fx.Profile, fx.Running)
	if err != nil {
		panic(err) /* Load validated it */
	}
	if opt.Start.IsZero() {
		opt.Start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	d := &Device{P: fx.Profile, fx: fx, opt: opt, now: opt.Start, running: root, files: map[string]string{}, sess: map[int]*Session{}}
	d.cand, d.saved = root.clone(), root.clone()
	return d
}

/* NewLine loads test/fixtures/devices/<line> and returns a device of it; it fails the test on error. */
func NewLine(t testing.TB, line string, opt Options) *Device {
	t.Helper()
	fx, err := LoadLine(line)
	if err != nil {
		t.Fatal(err)
	}
	return New(fx, opt)
}

/* SetShowLookup makes cmd outputs come from fn before the fixture's show/ files (sshemud -dir). */
func (d *Device) SetShowLookup(fn func(cmd string) (string, bool)) {
	d.mu.Lock()
	d.show = fn
	d.mu.Unlock()
}

/* OnInput calls fn (under the device lock) for every entry added to the journal. */
func (d *Device) OnInput(fn func(Entry)) {
	d.mu.Lock()
	d.onInput = fn
	d.mu.Unlock()
}

/* Reject makes every command line matching pattern fail with msg (and change nothing). */
func (d *Device) Reject(pattern, msg string) {
	d.mu.Lock()
	d.rejects = append(d.rejects, reject{regexp.MustCompile(pattern), msg})
	d.mu.Unlock()
}

/* PutFile stores a file the device can copy from or to (e.g. "tftp://192.0.2.1/a.cfg", "flash:backup.conf"). */
func (d *Device) PutFile(name, content string) {
	d.mu.Lock()
	d.files[name] = normalizeNL(content)
	d.mu.Unlock()
}

/* File returns a stored file. */
func (d *Device) File(name string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.files[name]
	return s, ok
}

/* Running returns the running configuration as "show running-config" prints it. */
func (d *Device) Running() string { return d.locked(func() string { return d.P.render(d.running) }) }

/* Candidate returns the ESR candidate configuration. */
func (d *Device) Candidate() string { return d.locked(func() string { return d.P.render(d.cand) }) }

/* Saved returns what survives a reboot: ESR flash, MES startup-config. */
func (d *Device) Saved() string { return d.locked(func() string { return d.P.render(d.saved) }) }

func (d *Device) locked(f func() string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return f()
}

/* Pending returns the ESR commit timer's deadline, or zero when nothing awaits confirm. */
func (d *Device) Pending() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pending
}

/* ReloadAt returns the scheduled MES reload, or zero. */
func (d *Device) ReloadAt() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reload
}

/* Reboots counts reloads so far. */
func (d *Device) Reboots() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reboots
}

/* Now returns the fake clock. */
func (d *Device) Now() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.now
}

/* Advance moves the fake clock and fires the commit timer and a scheduled reload. */
func (d *Device) Advance(dt time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.now = d.now.Add(dt)
	d.fire()
}

/* RunClock advances the fake clock with the wall clock until stop is closed (the standalone sshemud). */
func (d *Device) RunClock(stop <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			d.Advance(time.Second)
		}
	}
}

func (d *Device) fire() {
	if !d.pending.IsZero() && !d.now.Before(d.pending) {
		/* the timer expired: running returns to the confirmed one, the changes stay in candidate [R §1] */
		d.running, d.saved, d.backup, d.pending = d.backup, d.backup.clone(), nil, time.Time{}
	}
	if !d.reload.IsZero() && !d.now.Before(d.reload) {
		d.reboot()
	}
}

/* reboot loads the saved configuration and drops every session. */
func (d *Device) reboot() {
	d.reboots++
	d.running, d.cand = d.saved.clone(), d.saved.clone()
	d.backup, d.pending, d.reload = nil, time.Time{}, time.Time{}
	for _, s := range d.sess {
		s.close()
	}
}

/* Syslog prints an async log line, with the profile's time stamp, into every open session [R §5]. */
func (d *Device) Syslog(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.syslog(msg)
}

func (d *Device) syslog(msg string) {
	line := d.now.Format(d.P.Syslog["stamp"].Text) + " " + msg
	for _, id := range d.sessionIDs() {
		d.sess[id].async(line)
	}
}

func (d *Device) sessionIDs() []int {
	ids := make([]int, 0, len(d.sess))
	for id := range d.sess {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

/* Disconnect drops every open session. */
func (d *Device) Disconnect() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.sess {
		s.close()
	}
}

/* Journal returns everything the device received, in order. */
func (d *Device) Journal() []Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Entry(nil), d.journal...)
}

/* Lines returns the non-empty command lines received (Kind "line"), in order. */
func (d *Device) Lines() []string {
	var out []string
	for _, e := range d.Journal() {
		if e.Kind == "line" && strings.TrimSpace(e.Input) != "" {
			out = append(out, e.Input)
		}
	}
	return out
}

/* ExpectLines fails the test unless the device received exactly these command lines, in this order. */
func (d *Device) ExpectLines(t testing.TB, want ...string) {
	t.Helper()
	if got := d.Lines(); !slices.Equal(got, want) {
		t.Fatalf("device received:\n  %s\nwant exactly:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

/* ExpectNone fails the test if the device received an entry of one of these kinds (e.g. "new-password"). */
func (d *Device) ExpectNone(t testing.TB, kinds ...string) {
	t.Helper()
	for _, e := range d.Journal() {
		if slices.Contains(kinds, e.Kind) {
			t.Fatalf("device received %s %q in mode %s", e.Kind, e.Input, e.Mode)
		}
	}
}

func (d *Device) record(e Entry) {
	d.journal = append(d.journal, e)
	if d.onInput != nil {
		d.onInput(e)
	}
}

func (d *Device) rejected(line string) (string, bool) {
	for _, r := range d.rejects {
		if r.re.MatchString(line) {
			return r.msg, true
		}
	}
	return "", false
}

/* hostname is the top-level "hostname X" of the running configuration, or the profile's default. */
func (d *Device) hostname() string {
	for _, c := range d.running.children {
		if f := strings.Fields(c.text); len(f) == 2 && f[0] == "hostname" && c.mode == "" {
			return strings.Trim(f[1], `"`)
		}
	}
	return d.P.Hostname.Text
}

func (d *Device) defaultInt(key string) int {
	n, err := strconv.Atoi(d.P.Defaults[key].Text)
	if err != nil {
		panic(fmt.Sprintf("profile default %s: %v", key, err))
	}
	return n
}

/* Serve runs a CLI session over rw for an SSH-authenticated user until either side closes it (sshemu.Config.Shell). */
func (d *Device) Serve(user string, rw io.ReadWriteCloser) {
	s := d.open(user, rw)
	buf := make([]byte, 4096)
	for {
		n, err := rw.Read(buf)
		if n > 0 && !s.input(buf[:n]) {
			break
		}
		if err != nil {
			break
		}
	}
	d.mu.Lock()
	s.close()
	d.mu.Unlock()
}

func (d *Device) open(user string, w io.WriteCloser) *Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nextID++
	s := &Session{d: d, id: d.nextID, out: w}
	d.sess[s.id] = s
	s.start(user)
	return s
}
