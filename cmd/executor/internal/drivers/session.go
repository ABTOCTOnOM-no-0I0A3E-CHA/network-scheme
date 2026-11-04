package drivers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
Shell is the part of transport.Shell a driver session uses: typed lines
(Send), the driver's system commands with the confirmation table (System),
the read allowlist (Run) and the prompt state.
*/
type Shell interface {
	Send(ctx context.Context, line string) (transport.Output, error)
	System(ctx context.Context, line string) (transport.Output, error)
	Run(ctx context.Context, cmd ssh.ShowCommand) (transport.Output, error)
	State() transport.State
	DeviceID() int64
}

var runningConfig = ssh.ShowCommand{Name: "show running-config", LongOutput: true}

/*
Core is the line-independent part of a session: the mode as the device
accepted lines (core.Next, then core.Reconcile with the prompt), the
pre-session snapshot and the hash check after a rollback.
*/
type Core struct {
	Sh   Shell
	G    *core.Grammar
	D    Classifier
	Opt  Options
	Pre  Config
	mode core.Mode
	/* Sent is called after the device accepted a typed line, with the mode it was typed in. */
	Sent func(line string, before core.Mode)
	/* Failed is called when sending a typed line failed: the device may or may not have applied it. */
	Failed func(line string)
}

/* Classifier is the driver's classification (WriteDriver.Classify). */
type Classifier interface {
	Classify(line string, m core.Mode, c core.Context) core.Verdict
}

/* ReasonSnapshot is why a line is denied when it names an executor snapshot file (nms-pre-*), which only the driver touches. */
const ReasonSnapshot core.Reason = "snapshot"

/* NewCore reads the pre-session snapshot from the privileged prompt. */
func NewCore(ctx context.Context, sh Shell, d Classifier, g *core.Grammar, o Options) (*Core, error) {
	c := &Core{Sh: sh, G: g, D: d, Opt: o, mode: g.Root()}
	c.reconcile()
	if err := c.ToRoot(ctx); err != nil {
		return nil, err
	}
	pre, err := c.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	c.Pre = pre
	return c, nil
}

/* Mode is the session's mode. */
func (c *Core) Mode() core.Mode { return c.mode }

/* promptMode names the grammar mode of the prompt: the root is "exec", sub-modes are the prompt's context. */
func promptMode(st transport.State) string {
	switch st.Mode {
	case transport.ModePrivileged:
		return "exec"
	case transport.ModeConfig:
		return "config"
	case transport.ModeSub:
		return st.Context
	}
	return ""
}

func (c *Core) reconcile() { c.mode = c.G.Reconcile(c.mode, promptMode(c.Sh.State())) }

/* System sends a driver command and reconciles the mode with the prompt after it. */
func (c *Core) System(ctx context.Context, line string) (transport.Output, error) {
	out, err := c.Sh.System(ctx, line)
	c.reconcile()
	return out, err
}

/* ToRoot leaves the configuration modes ("end"). */
func (c *Core) ToRoot(ctx context.Context) error {
	switch c.Sh.State().Mode {
	case transport.ModeConfig, transport.ModeSub:
		_, err := c.Sh.Send(ctx, "end")
		c.reconcile()
		if err != nil {
			return err
		}
	}
	if c.Sh.State().Mode != transport.ModePrivileged {
		return fmt.Errorf("%w: %q", transport.ErrUnexpectedPrompt, c.Sh.State().Prompt)
	}
	return nil
}

/* Snapshot reads the running configuration (read allowlist, from the privileged prompt). */
func (c *Core) Snapshot(ctx context.Context) (Config, error) {
	if err := c.ToRoot(ctx); err != nil {
		return Config{}, err
	}
	out, err := c.Sh.Run(ctx, runningConfig)
	c.reconcile()
	if err != nil {
		return Config{}, err
	}
	return NewConfig(out.Text()), nil
}

/*
Classify classifies a typed line in the session's mode and context with the
driver; a line naming an executor snapshot (nms-pre-*: copy over it, delete
it) is Denied.
*/
func (c *Core) Classify(line string) core.Verdict {
	v := c.D.Classify(line, c.mode, c.Opt.Context)
	if (v.Class == core.Safe || v.Class == core.Dangerous) && strings.Contains(strings.ToLower(v.Line), "nms-pre-") {
		return core.Verdict{Class: core.Denied, Line: v.Line, Reason: ReasonSnapshot}
	}
	return v
}

/*
Send sends a typed line: only the verdict Classify gives for it in the
session's mode and context (so a verdict of another mode, an edited line or
a Control or Denied one is refused). A line the device accepted advances the
mode (core.Next); the prompt reconciles it.
*/
func (c *Core) Send(ctx context.Context, v core.Verdict) (transport.Output, error) {
	again := c.Classify(v.Line)
	if v.Line == "" || v.Class != core.Safe && v.Class != core.Dangerous || again.Class != v.Class || again.Line != v.Line {
		return transport.Output{}, ErrNotSendable
	}
	before := c.mode
	out, err := c.Sh.Send(ctx, v.Line)
	switch {
	case err == nil:
		c.mode = c.G.Next(v.Line, c.mode)
		if c.Sent != nil {
			c.Sent(v.Line, before)
		}
	case c.Failed != nil:
		c.Failed(v.Line)
	}
	c.reconcile()
	return out, err
}

/* Fail publishes the high alert of a failed rollback and returns err wrapped in ErrRollbackMismatch. */
func (c *Core) Fail(ctx context.Context, err error) error {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	text := fmt.Sprintf("device %d: rollback did not restore the pre-session configuration", c.Sh.DeviceID())
	_ = c.Opt.Alert(actx, KindRollbackMismatch, "high", c.Sh.DeviceID(), text)
	if err == nil || errors.Is(err, ErrRollbackMismatch) {
		return ErrRollbackMismatch
	}
	return fmt.Errorf("%w: %w", ErrRollbackMismatch, err)
}

/* Verify re-reads the running configuration after a rollback: its hash must be to's, else Fail. */
func (c *Core) Verify(ctx context.Context, to Config) error {
	now, err := c.Snapshot(ctx)
	if err != nil || now.SHA256 != to.SHA256 {
		return c.Fail(ctx, err)
	}
	return nil
}

/* CheckTarget refuses a rollback target that is not this session's pre-session snapshot. */
func (c *Core) CheckTarget(to Config) error {
	if !to.Valid() || to.SHA256 != c.Pre.SHA256 {
		return ErrSnapshot
	}
	return nil
}

/* SnapshotFile is the on-device copy of the pre-session configuration. */
func (c *Core) SnapshotFile(prefix string) string { return prefix + "nms-pre-" + c.Opt.SessionID }

/*
DropSnapshot deletes the on-device snapshot file at Close ("delete <file>":
documented for ESR [R §6], a guess for MES 10.x). A failure leaves the file:
ErrSnapshotLeft, for the caller's alert.
*/
func (c *Core) DropSnapshot(ctx context.Context, file string) error {
	if err := c.ToRoot(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshotLeft, err)
	}
	if _, err := c.System(ctx, "delete "+file); err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshotLeft, err)
	}
	return nil
}
