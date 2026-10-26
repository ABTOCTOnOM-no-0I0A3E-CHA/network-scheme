package registry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

/* domain opens every MACed message; a new layout gets a new label. */
const domain = "exec/v1"

/* Field tags: a NULL is distinct from an empty value. */
const (
	tagNull  = 0
	tagValue = 1
)

func appendField(b []byte, f *string) []byte {
	if f == nil {
		return append(b, tagNull)
	}
	b = append(b, tagValue)
	b = binary.BigEndian.AppendUint32(b, uint32(len(*f))) // #nosec G115 -- values are bounded far below 4 GiB by the table checks
	return append(b, *f...)
}

func appendList(b []byte, fs []*string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(fs))) // #nosec G115 -- a handful of columns
	for _, f := range fs {
		b = appendField(b, f)
	}
	return b
}

/*
Canonical is the MACed encoding of one registry row:
"exec/v1" ‖ field(table) ‖ list(pk) ‖ list(content) ‖ uint64(version), where
field = tag (0 NULL, 1 value) ‖ uint32 length ‖ bytes and list = uint32
count ‖ fields, all big-endian. Every part is self-delimiting, so no two
different rows share an encoding.
*/
func Canonical(table string, pk, content []*string, version int64) []byte {
	b := append([]byte(domain), tagValue)
	b = binary.BigEndian.AppendUint32(b, uint32(len(table))) // #nosec G115 -- table names are constants
	b = append(b, table...)
	b = appendList(b, pk)
	b = appendList(b, content)
	return binary.BigEndian.AppendUint64(b, uint64(version)) // #nosec G115 -- versions are positive
}

/* rowMAC is HMAC-SHA-256 under the mac subkey of the canonical encoding. */
func rowMAC(key *[32]byte, table string, pk, content []*string, version int64) []byte {
	h := hmac.New(sha256.New, key[:])
	h.Write(Canonical(table, pk, content, version))
	return h.Sum(nil)
}

/* entry is what the state hash covers for one row: (table, pk, version, mac). */
func entry(table string, pk []*string, version int64, mac []byte) []byte {
	s := string(mac)
	b := appendField(nil, &table)
	b = appendList(b, pk)
	b = binary.BigEndian.AppendUint64(b, uint64(version)) // #nosec G115 -- versions are positive
	return appendField(b, &s)
}
