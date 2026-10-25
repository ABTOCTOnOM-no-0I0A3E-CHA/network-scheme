/** Section keys, in display order (the same keys as drivers.SplitSections on the server). */
export const SECTIONS = ["general", "interfaces", "vlan", "routing", "snmp", "syslog", "aaa", "other"] as const;
export type SectionKey = (typeof SECTIONS)[number];
export type Section = { name: SectionKey; lines: string[] };

/* checked in order against the lower-cased top-level line; mirrors internal/drivers/config.go */
const PREFIXES: [SectionKey, string[]][] = [
  ["interfaces", ["interface", "port-channel"]],
  ["vlan", ["vlan", "bridge"]],
  ["routing", ["ip route", "ipv6 route", "router", "route-map", "ip prefix", "ipv6 prefix", "ip routing", "ip default-gateway", "ip vrf", "vrf", "route", "ip policy"]],
  ["snmp", ["snmp"]],
  ["syslog", ["logging", "syslog"]],
  ["aaa", ["aaa", "radius", "tacacs", "username", "enable", "privilege"]],
  ["general", ["hostname", "clock", "ntp", "sntp", "ip domain", "ip name-server", "banner", "service", "system", "version", "config-file-header", "boot"]],
];

/* a prefix matches when it is not followed by a letter, so "ip route" does not match "ip routing" */
function classify(line: string): SectionKey {
  const l = line.toLowerCase();
  for (const [section, prefixes] of PREFIXES) {
    for (const p of prefixes) {
      if (!l.startsWith(p)) continue;
      const next = l.charAt(p.length);
      if (next === "" || next < "a" || next > "z") return section;
    }
  }
  return "other";
}

/**
 * Groups masked configuration lines by their top-level command, like the
 * server's drivers.SplitSections: an unindented line starts a block that
 * continues over indented lines and the closing "exit"/"end"/comment lines;
 * lines before the first command are general. Empty sections are omitted.
 */
export function splitSections(text: string): Section[] {
  const by = new Map<SectionKey, string[]>();
  let cur: SectionKey = "general";
  for (const l of text.replace(/\n+$/, "").split("\n")) {
    const t = l.trim();
    if (t === "") continue;
    const top = l[0] !== " " && l[0] !== "\t";
    if (top && t !== "exit" && t !== "end" && t[0] !== "!" && t[0] !== "#") cur = classify(t);
    const lines = by.get(cur);
    if (lines) lines.push(l);
    else by.set(cur, [l]);
  }
  return SECTIONS.filter((s) => by.has(s)).map((name) => ({ name, lines: by.get(name) ?? [] }));
}
