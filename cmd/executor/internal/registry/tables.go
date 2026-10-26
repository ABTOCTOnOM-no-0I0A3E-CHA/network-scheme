package registry

import (
	"strings"
)

/* How a column is read as canonical text, independent of session settings (DateStyle, TimeZone, bytea_output). */
type kind int

const (
	kText  kind = iota /* text as stored */
	kCast              /* bigint, int, boolean, inet, jsonb: their text output is canonical */
	kBytea             /* lower-case hex */
	kTime              /* microseconds since the epoch */
)

type column struct {
	name string
	kind kind
}

func (c column) expr() string {
	q := `"` + c.name + `"`
	switch c.kind {
	case kCast:
		return q + "::text"
	case kBytea:
		return "encode(" + q + ", 'hex')"
	case kTime:
		return "(extract(epoch FROM " + q + ") * 1000000)::bigint::text"
	default:
		return q
	}
}

/* table is one registry table: its key, the MACed content and the version column. */
type table struct {
	name    string
	pk      []column
	content []column
	version string
}

const counterTable = "registry_counter"

/*
tables is the whole registry. Every column of each table except mac is
either key, content or version (TestTablesCoverEveryColumn), so nothing can
change outside the MAC. The append-only tables (sessions, recordings, audit)
are not registry: they are never updated and carry their own MACs (4c).
*/
var tables = []table{
	{name: counterTable, pk: []column{{"singleton", kCast}}, version: "seq"},
	{name: "write_device", pk: []column{{"device_id", kCast}}, content: []column{
		{"address", kCast}, {"port", kCast}, {"protocol", kText}, {"write_group", kText}, {"write_driver", kText},
		{"hostkey_algo", kText}, {"hostkey_fp", kText}, {"allow_ssh_rsa_sha1", kCast}, {"writes_enabled", kCast},
		{"backup_via_executor", kCast},
	}, version: "version"},
	{name: "write_grant", pk: []column{{"user_id", kCast}, {"kind", kText}, {"write_group", kText}},
		content: []column{{"username_snapshot", kText}}, version: "version"},
	{name: "change_totp", pk: []column{{"user_id", kCast}}, content: []column{
		{"username_snapshot", kText}, {"ciphertext", kBytea}, {"key_version", kCast}, {"last_step", kCast},
		{"failures", kCast}, {"lock_until", kTime}, {"lock_count", kCast},
	}, version: "version"},
	{name: "exec_state", pk: []column{{"singleton", kCast}}, content: []column{
		{"freeze", kCast}, {"freeze_reason", kText}, {"global_fail_window", kCast},
	}, version: "version"},
	{name: "model_profile", pk: []column{{"id", kCast}}, content: []column{
		{"write_driver", kText}, {"model_re", kText}, {"firmware_re", kText}, {"strategies", kCast}, {"note", kText},
	}, version: "version"},
	{name: "write_credential", pk: []column{{"device_id", kCast}}, content: []column{
		{"kind", kText}, {"ciphertext", kBytea}, {"created_at", kTime}, {"nonce", kBytea},
	}, version: "version"},
}

/* selectSQL reads ctid, key, content, version and mac of every row. */
func (t table) selectSQL() string {
	exprs := []string{"ctid::text"}
	for _, c := range append(append([]column(nil), t.pk...), t.content...) {
		exprs = append(exprs, c.expr())
	}
	exprs = append(exprs, `"`+t.version+`"`, "mac")
	return "SELECT " + strings.Join(exprs, ", ") + ` FROM exec."` + t.name + `"`
}
