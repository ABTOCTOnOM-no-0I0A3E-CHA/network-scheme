package eventd

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"

	"github.com/gosnmp/gosnmp"

	"github.com/beekamai/network-scheme/internal/events/trap"
)

/* maxVarbindsJSON bounds the serialized varbinds; the table allows 300000 bytes of jsonb text, which renders a little wider than compact JSON. */
const maxVarbindsJSON = 290_000

/* snmpVersion reads the version from the BER header of an SNMP message without decoding anything else. */
func snmpVersion(b []byte) (gosnmp.SnmpVersion, bool) {
	if len(b) < 5 || b[0] != 0x30 {
		return 0, false
	}
	i := 2
	if b[1]&0x80 != 0 {
		n := int(b[1] & 0x7f)
		if n == 0 || n > 4 {
			return 0, false
		}
		i = 2 + n
	}
	if len(b) < i+3 || b[i] != 0x02 || b[i+1] != 1 {
		return 0, false
	}
	switch v := b[i+2]; v {
	case 0:
		return gosnmp.Version1, true
	case 1:
		return gosnmp.Version2c, true
	case 3:
		return gosnmp.Version3, true
	}
	return 0, false
}

/*
authTrap decodes and authenticates a trap datagram from device d (read-locked
by the caller). It returns the decoded packet only when the packet proves the
credentials of d: the community of the snmp2c profile for v1/v2c, an authPriv
message of the USM user of the snmp3 profile for v3 (see v3.go for the cost
model: messages with an engine ID other than the pinned one are budgeted). Every failure is
auth_failed; nothing of an unauthenticated packet is used.
*/
func (s *server) authTrap(d *device, data []byte) (*gosnmp.SnmpPacket, bool) {
	ver, ok := snmpVersion(data)
	if !ok {
		return nil, false
	}
	if ver != gosnmp.Version3 {
		g := &gosnmp.GoSNMP{Version: ver, Logger: quiet}
		p, err := unmarshal(g, data)
		if err != nil || !d.matchCommunity(p.Community) {
			return nil, false
		}
		return p, true
	}
	if d.v3 == nil {
		return nil, false
	}
	return d.v3.decode(data, func() bool {
		/* both budgets or none: a refusal of the global one must not cost the device its token */
		if allowBoth(s.slowDev, d.id, s.slowAll, 0, s.now()) {
			return true
		}
		s.st.slowDropped.Add(1)
		return false
	}, func() { s.st.replayed.Add(1) })
}

/*
handleTrap processes one trap or inform datagram from the peer address ip.
reply sends a datagram back to the peer (nil when it cannot); it is used only
to acknowledge an authenticated INFORM.
*/
func (s *server) handleTrap(ip netip.Addr, data []byte, reply func([]byte)) {
	d, release, ok := s.src.acquire(ip)
	if !ok {
		s.st.unknownSource.Add(1)
		return
	}
	defer release()
	pkt, ok := s.authTrap(d, data)
	if !ok {
		s.st.authFailed.Add(1)
		return
	}
	if pkt.Version == gosnmp.Version3 && pkt.PDUType != gosnmp.SNMPv2Trap {
		if pkt.PDUType == gosnmp.InformRequest {
			/* v3 INFORM needs the engine discovery exchange, whose replies would reflect traffic: not offered */
			s.st.v3Inform.Add(1)
		}
		s.st.malformed.Add(1)
		return
	}
	tr, err := trap.Normalize(pkt)
	if err != nil {
		s.st.malformed.Add(1)
		return
	}
	mapped, identified := trap.Map(d.drv, tr, s.rules.Load().m)
	vb, _ := encodeVarbinds(tr.Varbinds)
	e := event{
		kind: kindTrap, ts: s.now().UTC(), dev: d.id, version: int16(tr.Version), trapOID: tr.OID,
		name: mapped.Name, sev: mapped.Severity, varbinds: vb, identified: identified,
	}
	if !s.admit(d, kindTrap, e) {
		return /* queue full: no acknowledgement, the sender retries an INFORM */
	}
	if pkt.PDUType == gosnmp.InformRequest && reply != nil {
		if out, err := informResponse(pkt); err == nil {
			reply(out)
		}
	}
	if mapped.AffectsState {
		s.polls.request(d.id)
	}
}

/* informResponse builds the v1/v2c acknowledgement: a GetResponse with the request id and variables of the INFORM. */
func informResponse(p *gosnmp.SnmpPacket) ([]byte, error) {
	g := &gosnmp.GoSNMP{Version: p.Version, Community: p.Community, Logger: quiet}
	g.SetRequestID(p.RequestID - 1) /* the encoder takes the next id */
	return g.SnmpEncodePacket(gosnmp.GetResponse, p.Variables, 0, 0)
}

type varbindJSON struct {
	OID       string `json:"oid"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Truncated bool   `json:"truncated,omitempty"`
}

/*
encodeVarbinds serializes the varbinds as a JSON array of at most
maxVarbindsJSON bytes. When they do not fit, the trailing ones are dropped and
a last element {"oid": first dropped, "truncated_varbinds": n} says how many.
*/
func encodeVarbinds(vbs []trap.Varbind) (out []byte, dropped int) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, v := range vbs {
		item, err := json.Marshal(varbindJSON{OID: v.OID, Type: v.Type, Value: v.Value, Truncated: v.Truncated})
		if err != nil || buf.Len()+len(item)+1+markerRoom > maxVarbindsJSON {
			dropped = len(vbs) - i
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`{"oid":` + strconv.Quote(vbs[i].OID) + `,"truncated_varbinds":` + strconv.Itoa(dropped) + `}`)
			break
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(item)
	}
	buf.WriteByte(']')
	return buf.Bytes(), dropped
}

/* markerRoom is the space kept for the truncation marker: an OID of at most 128 sub-identifiers plus the field names. */
const markerRoom = 1600
