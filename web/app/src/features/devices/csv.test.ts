import { describe, expect, it } from "vitest";
import { csvCell, toCsv } from "./csv";
import { splitSections } from "./sections";

describe("csv", () => {
  it.each([
    ["=HYPERLINK(\"http://x\")", `"'=HYPERLINK(""http://x"")"`],
    ["+1+1", `"'+1+1"`],
    ["-2+3", `"'-2+3"`],
    ["@SUM(A1)", `"'@SUM(A1)"`],
    ["\tcmd", `"'\tcmd"`],
    ["gi1/0/1", `"gi1/0/1"`],
    ["a,b\nc", `"a,b\nc"`],
  ])("neutralizes and quotes %j", (input, want) => {
    expect(csvCell(input)).toBe(want);
  });

  it("writes numbers, booleans and empty values as they are", () => {
    expect(csvCell(-5)).toBe(`"-5"`);
    expect(csvCell(true)).toBe(`"true"`);
    expect(csvCell(null)).toBe(`""`);
    expect(csvCell(undefined)).toBe(`""`);
  });

  it("builds a header and CRLF rows", () => {
    const rows = [
      { name: "=cmd|' /C calc'!A0", vlan: 10 },
      { name: 'say "hi"', vlan: 0 },
    ];
    expect(toCsv(["name", "vlan"], rows)).toBe(`"name","vlan"\r\n"'=cmd|' /C calc'!A0","10"\r\n"say ""hi""","0"\r\n`);
  });
});

describe("splitSections", () => {
  it("groups blocks by their top-level command and keeps every line", () => {
    const text = "! header\nhostname sw\ninterface gi1/0/1\n description x\nexit\nip routing\nip route 0.0.0.0/0 192.0.2.1\nsnmp-server community *** ro\nusername admin password ***\nfoo bar\n";
    const s = splitSections(text);
    expect(s.map((x) => x.name)).toEqual(["general", "interfaces", "routing", "snmp", "aaa", "other"]);
    expect(s.find((x) => x.name === "interfaces")?.lines).toEqual(["interface gi1/0/1", " description x", "exit"]);
    expect(s.flatMap((x) => x.lines)).toHaveLength(text.trim().split("\n").length);
  });
});
