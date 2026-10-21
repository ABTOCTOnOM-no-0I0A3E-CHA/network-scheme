/*
Package snmpgo is a minimal in-process SNMPv2c agent for tests that need many
simulated devices (the load test): it serves a static .snmprec file under one
community on one UDP socket. The Python snmpsim does the same, but one process
answers only a few hundred requests a second and starves on a small CI runner.

Supported: GET, GETNEXT and GETBULK of SNMPv2c with noSuchObject, noSuchInstance
and endOfMibView. A request in another version, with another community or of
another type (SET included: the agent is read-only) is dropped without a reply.

Snmprec lines are "oid|type|value" with the types 2 (Integer32), 4 (OctetString),
4x (hex OctetString), 5 (Null), 6 (OID), 64 (IpAddress), 65 (Counter32), 66
(Gauge32), 67 (TimeTicks), 68 (Opaque), 68x (hex Opaque) and 70 (Counter64).
Values are static: a tag with a variation module (type:module) is an error. The
fixtures use none, so counters do not move, exactly as in snmpsim without
variation modules.
*/
package snmpgo

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"
)

/* maxVarbinds bounds one GETBULK reply so that it fits an UDP datagram. */
const maxVarbinds = 100

type entry struct {
	oid []uint32
	pdu gosnmp.SnmpPDU
}

/* MIB is an immutable set of objects sorted by OID; it is safe to share between agents. */
type MIB struct{ entries []entry }

/* Len is the number of objects. */
func (m *MIB) Len() int { return len(m.entries) }

func parseOID(s string) ([]uint32, error) {
	parts := strings.Split(strings.TrimPrefix(s, "."), ".")
	oid := make([]uint32, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("oid %q: %w", s, err)
		}
		oid[i] = uint32(n)
	}
	return oid, nil
}

func parseValue(tag, value string) (gosnmp.SnmpPDU, error) {
	var pdu gosnmp.SnmpPDU
	base, isHex := strings.CutSuffix(tag, "x")
	text := func() (any, error) {
		if isHex {
			return hex.DecodeString(value)
		}
		return []byte(value), nil
	}
	var err error
	switch base {
	case "2":
		var n int
		if n, err = strconv.Atoi(value); err == nil {
			pdu.Type, pdu.Value = gosnmp.Integer, n
		}
	case "4":
		pdu.Type = gosnmp.OctetString
		pdu.Value, err = text()
	case "5":
		pdu.Type = gosnmp.Null
	case "6":
		if _, err = parseOID(value); err == nil {
			pdu.Type, pdu.Value = gosnmp.ObjectIdentifier, value
		}
	case "64":
		pdu.Type = gosnmp.IPAddress
		if isHex {
			pdu.Value, err = text()
		} else if ip := net.ParseIP(value).To4(); ip != nil {
			pdu.Value = []byte(ip)
		} else {
			err = fmt.Errorf("address %q", value)
		}
	case "65", "66", "67":
		var n uint64
		if n, err = strconv.ParseUint(value, 10, 32); err == nil {
			pdu.Type = map[string]gosnmp.Asn1BER{"65": gosnmp.Counter32, "66": gosnmp.Gauge32, "67": gosnmp.TimeTicks}[base]
			pdu.Value = uint32(n)
		}
	case "68":
		pdu.Type = gosnmp.Opaque
		pdu.Value, err = text()
	case "70":
		var n uint64
		if n, err = strconv.ParseUint(value, 10, 64); err == nil {
			pdu.Type, pdu.Value = gosnmp.Counter64, n
		}
	default:
		err = fmt.Errorf("unsupported type %q (variation modules are not emulated)", tag)
	}
	return pdu, err
}

/* ParseSnmprec reads an .snmprec file; blank lines and lines starting with # are skipped. */
func ParseSnmprec(r io.Reader) (*MIB, error) {
	var m MIB
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		p := strings.SplitN(line, "|", 3)
		if len(p) != 3 {
			return nil, fmt.Errorf("line %d: want oid|type|value", n)
		}
		oid, err := parseOID(p[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		pdu, err := parseValue(p[1], p[2])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		pdu.Name = "." + strings.TrimPrefix(p[0], ".")
		m.entries = append(m.entries, entry{oid: oid, pdu: pdu})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(m.entries, func(a, b entry) int { return slices.Compare(a.oid, b.oid) })
	return &m, nil
}

/* LoadSnmprec parses the .snmprec file at path. */
func LoadSnmprec(path string) (*MIB, error) {
	f, err := os.Open(path) // #nosec G304 -- test fixture chosen by the caller
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	m, err := ParseSnmprec(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

/* search is the index of the first object with an OID >= oid and whether it equals oid. */
func (m *MIB) search(oid []uint32) (int, bool) {
	return slices.BinarySearchFunc(m.entries, oid, func(e entry, t []uint32) int { return slices.Compare(e.oid, t) })
}

/* get answers one GET varbind: the value, noSuchInstance if a sibling instance exists, else noSuchObject. */
func (m *MIB) get(name string, oid []uint32) gosnmp.SnmpPDU {
	if i, ok := m.search(oid); ok {
		return m.entries[i].pdu
	}
	kind := gosnmp.NoSuchObject
	if len(oid) > 1 {
		parent := oid[:len(oid)-1]
		if i, _ := m.search(parent); i < len(m.entries) && slices.Equal(m.entries[i].oid[:min(len(parent), len(m.entries[i].oid))], parent) {
			kind = gosnmp.NoSuchInstance
		}
	}
	return gosnmp.SnmpPDU{Name: name, Type: kind}
}

/* next answers one GETNEXT varbind: the first object after oid, or endOfMibView. */
func (m *MIB) next(name string, oid []uint32) gosnmp.SnmpPDU {
	i, ok := m.search(oid)
	if ok {
		i++
	}
	if i >= len(m.entries) {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.EndOfMibView}
	}
	return m.entries[i].pdu
}

/* Agent is one listening SNMPv2c agent. */
type Agent struct {
	conn *net.UDPConn
	wg   sync.WaitGroup
}

/* Listen starts an agent that answers on addr to the given community with mib. */
func Listen(addr netip.AddrPort, community string, mib *MIB) (*Agent, error) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(1 << 20) /* a burst of requests must not be lost between two reads */
	a := &Agent{conn: conn}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.serve(community, mib)
	}()
	return a, nil
}

/* Addr is the address the agent listens on. */
func (a *Agent) Addr() netip.AddrPort { return a.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

/* Close stops the agent and waits for its goroutine. */
func (a *Agent) Close() error {
	err := a.conn.Close()
	a.wg.Wait()
	return err
}

func (a *Agent) serve(community string, mib *MIB) {
	/* One codec per agent, used only by this goroutine; its Target is never dialed. */
	codec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: community, Target: "127.0.0.1"}
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if out := reply(codec, mib, buf[:n]); out != nil {
			_, _ = a.conn.WriteToUDPAddrPort(out, from)
		}
	}
}

/* reply answers one datagram, or returns nil when it is not to be answered. */
func reply(codec *gosnmp.GoSNMP, mib *MIB, datagram []byte) []byte {
	req, err := codec.SnmpDecodePacket(datagram)
	if err != nil || req.Version != gosnmp.Version2c || req.Community != codec.Community {
		return nil
	}
	var vars []gosnmp.SnmpPDU
	switch req.PDUType {
	case gosnmp.GetRequest, gosnmp.GetNextRequest:
		vars = make([]gosnmp.SnmpPDU, 0, len(req.Variables))
		for _, v := range req.Variables {
			oid, err := parseOID(v.Name)
			if err != nil {
				return nil
			}
			if req.PDUType == gosnmp.GetRequest {
				vars = append(vars, mib.get(v.Name, oid))
			} else {
				vars = append(vars, mib.next(v.Name, oid))
			}
		}
	case gosnmp.GetBulkRequest:
		if vars = bulk(mib, req); vars == nil {
			return nil
		}
	default:
		return nil
	}
	/* The codec numbers requests itself (pre-increment): seed it so the reply carries the request id. */
	codec.SetRequestID(req.RequestID - 1)
	out, err := codec.SnmpEncodePacket(gosnmp.GetResponse, vars, 0, 0)
	if err != nil {
		return nil
	}
	return out
}

/*
bulk answers a GETBULK: the first NonRepeaters varbinds as GETNEXT, the others
MaxRepetitions times in turn, each step continuing from the previous one; it
stops early once every repeater has reached endOfMibView.
*/
func bulk(mib *MIB, req *gosnmp.SnmpPacket) []gosnmp.SnmpPDU {
	oids := make([][]uint32, len(req.Variables))
	for i, v := range req.Variables {
		oid, err := parseOID(v.Name)
		if err != nil {
			return nil
		}
		oids[i] = oid
	}
	nonRep := min(int(req.NonRepeaters), len(oids))
	vars := make([]gosnmp.SnmpPDU, 0, len(oids))
	for i := range nonRep {
		vars = append(vars, mib.next(req.Variables[i].Name, oids[i]))
	}
	cur := oids[nonRep:]
	names := make([]string, len(cur))
	for i := range cur {
		names[i] = req.Variables[nonRep+i].Name
	}
	for range req.MaxRepetitions {
		if len(cur) == 0 || len(vars)+len(cur) > maxVarbinds {
			break
		}
		ended := true
		for i := range cur {
			pdu := mib.next(names[i], cur[i])
			if pdu.Type != gosnmp.EndOfMibView {
				ended = false
				names[i] = pdu.Name
				cur[i], _ = parseOID(pdu.Name)
			}
			vars = append(vars, pdu)
		}
		if ended {
			break
		}
	}
	return vars
}
