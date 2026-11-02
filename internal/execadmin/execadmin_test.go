package execadmin

import (
	"strings"
	"testing"
	"time"
)

/* Review minor 5: a field the command does not use is refused, so a request means exactly what it says. */
func TestValidateRefusesUnusedFields(t *testing.T) {
	ok := []Request{
		{Cmd: CmdFreezeOn, Reason: "drill"},
		{Cmd: CmdEnroll, User: "alice", UserID: 3, UserCreated: time.Now(), Replace: true},
		{Cmd: CmdGrant, User: "alice", Kind: KindWrite, Group: "core"},
		{Cmd: CmdRevoke, User: "#3", All: true},
		{Cmd: CmdUnlock, Global: true},
		{Cmd: CmdRegistryReset, IUnderstand: true},
		{Cmd: CmdRegistryReset, IUnderstand: true, DropPanel: true},
		{Cmd: CmdFreezeOff, Reason: "fixed", DropPanel: true},
		{Cmd: CmdModelVerify, Driver: "esr", Model: "x", Firmware: "y", Note: "n", Strategies: map[string]string{"a": "b"}},
		{Cmd: CmdPolicyReload, Action: "enable"},
	}
	for _, r := range ok {
		r.V = Version
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []Request{
		{Cmd: CmdFreezeOn, Action: "enable"},
		{Cmd: CmdFreezeOff, IUnderstand: true},
		{Cmd: CmdFreezeOn, DropPanel: true},
		{Cmd: CmdRegistryVerify, DropPanel: true},
		{Cmd: CmdRegistryVerify, Reason: "x"},
		{Cmd: CmdAuditVerify, Global: true},
		{Cmd: CmdPolicyShow, Action: "edit"},
		{Cmd: CmdRegistryReset, IUnderstand: true, Replace: true},
		{Cmd: CmdRevoke, User: "alice", Kind: KindUnmask, Replace: true},
		{Cmd: CmdEnroll, User: "alice", Kind: KindUnmask},
		{Cmd: CmdUnlock, Global: true, Reason: "x"},
		{Cmd: CmdModelVerify, Driver: "esr", Model: "x", Firmware: "y", Note: "n", Group: "core"},
		{Cmd: CmdModelVerify, Driver: "esr", Model: strings.Repeat("x", MaxPattern+1), Firmware: "y", Note: "n"},
	}
	for _, r := range bad {
		r.V = Version
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}
