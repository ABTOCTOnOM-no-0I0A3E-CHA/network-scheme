package inventory

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/devices"
)

/* SearchLimit is the most results of one type a search returns. */
const SearchLimit = 50

/*
portCandidates bounds the interface rows a port search sorts: a broad
substring ("eth") may match most interfaces, and only the first candidates
found are ordered. More is still exact, since candidates exceed the limit.
*/
const portCandidates = 1000

/*
minPortLen is the shortest query a port search runs for: the trigram indexes
need three characters, and a shorter substring would scan every interface.
*/
const minPortLen = 3

// DeviceHit is a device whose name contains the query or whose address starts with it.
type DeviceHit struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

// IPHit is an ARP entry whose address starts with the query.
type IPHit struct {
	DeviceID   int64  `json:"device_id"`
	DeviceName string `json:"device_name"`
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	IfIndex    int    `json:"if_index"`
	PortName   string `json:"port_name"`
}

// MACHit is a forwarding database (source fdb, with VLAN) or ARP (source arp, with IP) entry whose MAC starts with the query.
type MACHit struct {
	DeviceID   int64   `json:"device_id"`
	DeviceName string  `json:"device_name"`
	MAC        string  `json:"mac"`
	Source     string  `json:"source"`
	VLAN       *int    `json:"vlan"`
	IP         *string `json:"ip"`
	IfIndex    int     `json:"if_index"`
	PortName   string  `json:"port_name"`
}

// PortHit is an interface whose name or alias contains the query.
type PortHit struct {
	DeviceID   int64  `json:"device_id"`
	DeviceName string `json:"device_name"`
	IfIndex    int    `json:"if_index"`
	Name       string `json:"name"`
	Alias      string `json:"alias"`
}

// SearchGroup holds at most SearchLimit results of one type; More tells that there were more.
type SearchGroup[T any] struct {
	Items []T  `json:"items"`
	More  bool `json:"more"`
}

// SearchResults are the results of a global search by type. Device-reported strings must be rendered as text only.
type SearchResults struct {
	Devices SearchGroup[DeviceHit] `json:"devices"`
	IPs     SearchGroup[IPHit]     `json:"ips"`
	MACs    SearchGroup[MACHit]    `json:"macs"`
	Ports   SearchGroup[PortHit]   `json:"ports"`
}

// EmptySearch is a result with every type present and empty.
func EmptySearch() SearchResults {
	return SearchResults{
		Devices: SearchGroup[DeviceHit]{Items: []DeviceHit{}},
		IPs:     SearchGroup[IPHit]{Items: []IPHit{}},
		MACs:    SearchGroup[MACHit]{Items: []MACHit{}},
		Ports:   SearchGroup[PortHit]{Items: []PortHit{}},
	}
}

/* likeEscape escapes the LIKE wildcards and the escape character itself (the default escape is a backslash). */
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

var (
	ipChars = regexp.MustCompile(`^[0-9a-f.:]*[0-9][0-9a-f.:]*$`)
	ipv4ish = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3})*\.?$`)
	macHex  = regexp.MustCompile(`^[0-9a-f]{4,12}$`)
	macSeps = strings.NewReplacer(":", "", "-", "", ".", "")
)

/*
IPPrefix returns the range [lo, hi) of address texts (host(ip), lower case)
that start with q, or ok false when q cannot start an IPv4 or IPv6 address.
The characters allowed are ASCII, so incrementing the last byte gives the
exclusive upper bound.
*/
func IPPrefix(q string) (lo, hi string, ok bool) {
	q = strings.ToLower(q)
	if !ipChars.MatchString(q) {
		return "", "", false
	}
	return q, q[:len(q)-1] + string(q[len(q)-1]+1), true
}

/*
MACRange returns the macaddr bounds of the MACs starting with q, written with
any separators (":", "-", ".", none) and in any case; a partial MAC of at
least four hex digits matches as a prefix. A dotted decimal query (an IPv4
prefix like "10.10") is not taken as a MAC.
*/
func MACRange(q string) (lo, hi string, ok bool) {
	if ipv4ish.MatchString(q) {
		return "", "", false
	}
	h := strings.ToLower(macSeps.Replace(q))
	if !macHex.MatchString(h) {
		return "", "", false
	}
	return h + strings.Repeat("0", 12-len(h)), h + strings.Repeat("f", 12-len(h)), true
}

/* scopeSQL selects the devices d of the filter ($1 all, $2 group ids). */
const scopeSQL = `($1::bool OR d.group_id = ANY($2::bigint[]))`

/*
Search finds, among the devices f selects and at most SearchLimit of each
type: devices whose name contains q or whose address starts with it, ARP
entries by address prefix (IPPrefix), FDB and ARP entries by MAC prefix
(MACRange) and ports whose name or alias contains q (from minPortLen
characters). Substrings match case-insensitively and LIKE wildcards in q
literally. q is trimmed and bounded by the caller. Every query is
parameterized and bounded by an index range or by a LIMIT.
*/
func (s *Store) Search(ctx context.Context, f devices.Filter, q string) (SearchResults, error) {
	out := EmptySearch()
	if !f.All && len(f.GroupIDs) == 0 {
		return out, nil
	}
	var err error
	sub := "%" + likeEscape(q) + "%"
	prefix := likeEscape(strings.ToLower(q)) + "%"
	if out.Devices, err = search[DeviceHit](ctx, s, `
		SELECT d.id, d.name, host(d.address) FROM core.device d
		WHERE `+scopeSQL+` AND (d.name ILIKE $3 OR host(d.address) LIKE $4)
		ORDER BY d.name, d.id LIMIT $5`, f, sub, prefix); err != nil {
		return out, err
	}
	if utf8.RuneCountInString(q) >= minPortLen {
		if out.Ports, err = search[PortHit](ctx, s, `
			SELECT device_id, device_name, if_index, name, alias FROM (
				SELECT i.device_id, d.name AS device_name, i.if_index, i.name, i.alias
				FROM inventory.interface i JOIN core.device d ON d.id = i.device_id
				WHERE `+scopeSQL+` AND (i.name ILIKE $3 OR i.alias ILIKE $3)
				LIMIT `+fmt.Sprint(portCandidates)+`) c
			ORDER BY device_name, device_id, if_index LIMIT $4`, f, sub); err != nil {
			return out, err
		}
	}
	if lo, hi, ok := IPPrefix(q); ok {
		if out.IPs, err = search[IPHit](ctx, s, `
			SELECT a.device_id, d.name, host(a.ip), a.mac::text, a.if_index, coalesce(i.name, '')
			FROM inventory.arp_entry a JOIN core.device d ON d.id = a.device_id
			LEFT JOIN inventory.interface i ON i.device_id = a.device_id AND i.if_index = a.if_index
			WHERE `+scopeSQL+` AND host(a.ip) COLLATE "C" >= $3 AND host(a.ip) COLLATE "C" < $4
			ORDER BY host(a.ip) COLLATE "C", a.device_id, a.if_index LIMIT $5`, f, lo, hi); err != nil {
			return out, err
		}
	}
	if lo, hi, ok := MACRange(q); ok {
		if out.MACs, err = search[MACHit](ctx, s, `
			SELECT * FROM (
				(SELECT e.device_id, d.name, e.mac::text AS mac, 'fdb' AS source, e.vlan, NULL::text AS ip, e.if_index, coalesce(i.name, '')
				 FROM inventory.mac_entry e JOIN core.device d ON d.id = e.device_id
				 LEFT JOIN inventory.interface i ON i.device_id = e.device_id AND i.if_index = e.if_index
				 WHERE `+scopeSQL+` AND e.mac BETWEEN $3::macaddr AND $4::macaddr
				 ORDER BY e.mac, e.device_id, e.vlan LIMIT $5)
				UNION ALL
				(SELECT a.device_id, d.name, a.mac::text, 'arp', NULL::int, host(a.ip), a.if_index, coalesce(i.name, '')
				 FROM inventory.arp_entry a JOIN core.device d ON d.id = a.device_id
				 LEFT JOIN inventory.interface i ON i.device_id = a.device_id AND i.if_index = a.if_index
				 WHERE `+scopeSQL+` AND a.mac BETWEEN $3::macaddr AND $4::macaddr
				 ORDER BY a.mac, a.device_id, a.ip LIMIT $5)
			) m ORDER BY mac, source, device_id, vlan, ip LIMIT $5`, f, lo, hi); err != nil {
			return out, err
		}
	}
	return out, nil
}

/* search runs q with the filter as $1, $2, then args, and the limit (one extra row tells More) as the last parameter. */
func search[T any](ctx context.Context, s *Store, q string, f devices.Filter, args ...any) (SearchGroup[T], error) {
	params := append([]any{f.All, f.GroupIDs}, args...)
	rows, err := s.pool.Query(ctx, q, append(params, SearchLimit+1)...)
	if err != nil {
		return SearchGroup[T]{}, fmt.Errorf("inventory: search: %w", err)
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[T])
	if err != nil {
		return SearchGroup[T]{}, fmt.Errorf("inventory: search: %w", err)
	}
	g := SearchGroup[T]{Items: items, More: len(items) > SearchLimit}
	if g.More {
		g.Items = items[:SearchLimit]
	}
	if g.Items == nil {
		g.Items = []T{}
	}
	return g, nil
}
