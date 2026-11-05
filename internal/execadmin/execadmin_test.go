package execadmin

import (
	"strings"
	"testing"
	"time"
)

/* Review minor 5: a field the command does not use is refused, so a request means exactly what it says. */
func TestValidateRefusesUnusedFields(t *testing.T) {
	yes, no := true, false
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
		{Cmd: CmdDevice, Action: "add", DeviceID: 7, Address: "10.0.0.7", Port: 22, Group: "core", Driver: "mes6", AllowSHA1: &yes,
			Backup: &no, Fingerprint: "SHA256:" + strings.Repeat("A", 43)},
		{Cmd: CmdDevice, Action: "accept-hostkey", DeviceID: 7, Fingerprint: "SHA256:" + strings.Repeat("A", 43), DeviceVersion: 4},
		{Cmd: CmdDevice, Action: "list"},
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
		{Cmd: CmdDevice, Action: "add", DeviceID: 7, Note: "n"},
		{Cmd: CmdDevice, Action: "remove", DeviceID: 7},
		{Cmd: CmdDevice, Action: "add", DeviceID: 7, Driver: "ios"},
		{Cmd: CmdDevice, Action: "add", DeviceID: 7, Group: "Core"},
		{Cmd: CmdDevice, Action: "add", DeviceID: 7, Port: 65536},
		{Cmd: CmdDevice, Action: "add", DeviceID: 7, Fingerprint: "MD5:aa"},
		{Cmd: CmdGrant, User: "alice", Kind: KindUnmask, DeviceID: 7},
		{Cmd: CmdDevice, Action: "accept-hostkey", DeviceID: 7, DeviceVersion: 4},
		{Cmd: CmdDevice, Action: "add", DeviceID: 7, Fingerprint: "SHA256:" + strings.Repeat("A", 43), DeviceVersion: 4},
		{Cmd: CmdGrant, User: "alice", Kind: KindUnmask, AllowSHA1: &no},
	}
	for _, r := range bad {
		r.V = Version
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}
