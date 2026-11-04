/*
Package drvtest runs driver sessions against the device emulator in memory:
Term implements drivers.Shell over a devemu.Conn with the line's transport
strategies (prompt, question and error patterns, confirmation table). The
SSH transport itself is tested in package transport; this keeps the driver
tests free of SSH and the registry database.
*/
package drvtest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/test/sim/devemu"
)

/* Term is an emulated device's terminal. */
type Term struct {
	D   *devemu.Device
	c   *devemu.Conn
	set strategy.Set
	/* Deleted are the files "delete <file>" removed: the emulator has no delete on MES 10.x and ESR, Term stands in for it. */
	Deleted []string
	gone    map[string]bool
	line    strategy.Line
}

/* New opens a session on a fresh emulated device of line, after the line's terminal setup. */
func New(t testing.TB, line strategy.Line) *Term {
	t.Helper()
	d := devemu.NewLine(t, string(line), devemu.Options{})
	tm := &Term{D: d, c: d.Dial("admin"), set: strategy.Defaults(line), line: line}
	for _, c := range append(tm.set.TerminalCommands[tm.set.Terminal], tm.set.ConfirmOff...) {
		tm.c.Do(c)
	}
	return tm
}

/* State is the prompt state, read from what the device shows. */
func (tm *Term) State() transport.State {
	w := strings.TrimRight(tm.c.Waiting(), " ")
	if tm.set.Question.MatchString(w) {
		return transport.State{Mode: transport.ModeConfirm, Prompt: w, Question: w}
	}
	m := tm.set.Prompt.FindStringSubmatch(w)
	if m == nil {
		return transport.State{Prompt: w}
	}
	st := transport.State{Prompt: w, Host: m[1], Context: m[2]}
	switch {
	case m[3] == ">":
		st.Mode = transport.ModeExec
	case st.Context == "":
		st.Mode = transport.ModePrivileged
	case st.Context == "config":
		st.Mode = transport.ModeConfig
	default:
		st.Mode = transport.ModeSub
	}
	return st
}

/* DeviceID is a fixed id. */
func (tm *Term) DeviceID() int64 { return 7 }

func (tm *Term) exec(line string) (transport.Output, error) {
	if tm.c.Closed() {
		return transport.Output{}, transport.ErrClosed
	}
	out := transport.Output{}
	for _, l := range strings.Split(tm.c.Do(line), "\n") {
		switch {
		case tm.set.Syslog.MatchString(l):
			out.Async = append(out.Async, l)
		case l != "":
			out.Lines = append(out.Lines, l)
		}
	}
	out.State = tm.State()
	for _, l := range out.Lines {
		if tm.set.ErrorMarkers.MatchString(l) {
			out.Error = l
			return out, fmt.Errorf("%w: %s", transport.ErrDevice, l)
		}
	}
	return out, nil
}

/* Send types a line (refused while a question waits). */
func (tm *Term) Send(_ context.Context, line string) (transport.Output, error) {
	if st := tm.State().Mode; st == transport.ModeConfirm {
		return transport.Output{}, transport.ErrQuestionPending
	}
	if f, ok := strings.CutPrefix(line, "delete "); ok && tm.line != strategy.MES6 {
		if _, have := tm.D.File(f); !have || tm.gone[f] {
			return transport.Output{State: tm.State()}, fmt.Errorf("%w: no such file", transport.ErrDevice)
		}
		if tm.gone == nil {
			tm.gone = map[string]bool{}
		}
		tm.gone[f], tm.Deleted = true, append(tm.Deleted, f)
		return transport.Output{State: tm.State()}, nil
	}
	return tm.exec(line)
}

/* System answers questions from the confirmation table only, as transport.Shell.System does. */
func (tm *Term) System(ctx context.Context, line string) (transport.Output, error) {
	out, err := tm.Send(ctx, line)
	for range 3 {
		if err != nil || out.State.Mode != transport.ModeConfirm {
			return out, err
		}
		reply := ""
		for _, a := range tm.set.Answers {
			if a.Command.MatchString(line) && a.Question.MatchString(out.State.Question) {
				reply = a.Reply
			}
		}
		if reply == "" {
			return out, transport.ErrUnansweredQuestion
		}
		out, err = tm.exec(reply)
	}
	return out, err
}

/* Run runs only the snapshot read. */
func (tm *Term) Run(_ context.Context, cmd ssh.ShowCommand) (transport.Output, error) {
	if cmd.Name != "show running-config" || len(cmd.Args) != 0 {
		return transport.Output{}, transport.ErrNotAllowed
	}
	if tm.State().Mode != transport.ModePrivileged {
		return transport.Output{}, transport.ErrUnexpectedPrompt
	}
	return tm.exec(cmd.Name)
}

/* Lines are what the device received after the setup. */
func (tm *Term) Lines() []string {
	ls := tm.D.Lines()
	n := len(tm.set.TerminalCommands[tm.set.Terminal]) + len(tm.set.ConfirmOff)
	return ls[min(n, len(ls)):]
}

/* Alerts records alerts. */
type Alerts struct {
	mu    sync.Mutex
	Kinds []string
}

/* Add records an alert as kind/severity. */
func (a *Alerts) Add(_ context.Context, kind, severity string, _ int64, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Kinds = append(a.Kinds, kind+"/"+severity)
	return nil
}

/* List returns the alerts so far. */
func (a *Alerts) List() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.Kinds...)
}
