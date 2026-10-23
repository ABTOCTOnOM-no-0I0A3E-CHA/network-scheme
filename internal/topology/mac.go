package topology

/*
inferMAC links port pairs the LLDP data says nothing about. A port counts when
no LLDP row was reported on it and the MACs learned on it belong to exactly one
known device (a device MAC is one that ARP tables map from the device's
address, see load). Devices A and B are linked at confidence 0.4 when A has
exactly one such port that sees only B and B has exactly one that sees only A.
Hosts (MACs of no known device) are ignored; a port that sees two known devices
(an uplink to a network) infers nothing.
*/
func inferMAC(in *inputs) []link {
	type pair struct{ from, to int64 }
	ports := map[pair][]int32{}
	for k, owners := range in.stations {
		if in.lldpPort[k] {
			continue
		}
		first := owners[0]
		single := true
		for _, o := range owners[1:] {
			if o != first {
				single = false
				break
			}
		}
		if single {
			ports[pair{k.dev, first}] = append(ports[pair{k.dev, first}], k.ifx)
		}
	}
	var out []link
	for p, pa := range ports {
		if p.from > p.to || len(pa) != 1 {
			continue
		}
		if pb := ports[pair{p.to, p.from}]; len(pb) == 1 {
			out = append(out, link{a: p.from, ai: pa[0], b: p.to, bi: pb[0], source: sourceMAC, conf: confMAC})
		}
	}
	return out
}
