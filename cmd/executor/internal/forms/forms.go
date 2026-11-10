/*
Package forms is the GUI forms of a change session (security.md 5.3, Task
4c.4): a form is rendered by the device's write driver (RenderForm) into the
"equivalent commands" the user is shown, and applied only when the user
confirms exactly those lines. Applying sends them from the privileged
prompt one by one, each only as the driver session's own Classify verdict
(Session.Classify, never the grammar's: the session's mode, management
context, policy rules and snapshot protection count) and only when it is
Safe: a dangerous line belongs to the terminal's confirmation, and the first
line that is not Safe stops the form before it is sent.
*/
package forms

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/* Errors. */
var (
	ErrForm     = errors.New("forms: bad form")
	ErrChanged  = errors.New("forms: the lines are not the ones the form renders")
	ErrNotSafe  = errors.New("forms: a line is not safe in the session: type it in the terminal")
	ErrNoPrompt = errors.New("forms: the session cannot reach its privileged prompt")
)

/* Params is a form as the executor UI sends it. */
type Params struct {
	Kind        string `json:"kind"`
	Interface   string `json:"interface"`
	Description string `json:"description"`
	Up          bool   `json:"up"`
	VLAN        int    `json:"vlan"`
	Name        string `json:"name"`
}

func (p Params) form() drivers.Form {
	return drivers.Form{Kind: drivers.FormKind(p.Kind), Interface: p.Interface, Description: p.Description, Up: p.Up, VLAN: p.VLAN, Name: p.Name}
}

/* Render is the equivalent commands of p on the driver's line. */
func Render(d drivers.WriteDriver, p Params) ([]string, error) {
	lines, err := d.RenderForm(p.form())
	if err != nil || len(lines) == 0 {
		return nil, ErrForm
	}
	return lines, nil
}

/* rooter is the privileged prompt of a driver session (drivers.Core, embedded by every line's session). */
type rooter interface {
	ToRoot(ctx context.Context) error
}

/*
Apply renders p again and sends its lines when they are exactly shown (the
user's confirmation), see the package comment. sent is how many lines the
device got; on any stop the session goes back to its privileged prompt.
*/
func Apply(ctx context.Context, d drivers.WriteDriver, s drivers.Session, p Params, shown []string) (sent int, err error) {
	lines, err := Render(d, p)
	if err != nil {
		return 0, err
	}
	if !slices.Equal(lines, shown) {
		return 0, ErrChanged
	}
	r, ok := s.(rooter)
	if !ok {
		return 0, ErrNoPrompt
	}
	if err := r.ToRoot(ctx); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNoPrompt, err)
	}
	for i, l := range lines {
		v := s.Classify(l)
		if v.Class != core.Safe {
			return sent, errors.Join(fmt.Errorf("%w: line %d %q is %s", ErrNotSafe, i+1, v.Line, v.Class), r.ToRoot(ctx))
		}
		if _, err := s.Send(ctx, v); err != nil {
			return sent, errors.Join(err, r.ToRoot(ctx))
		}
		sent++
	}
	return sent, nil
}
