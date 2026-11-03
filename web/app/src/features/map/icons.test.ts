import { describe, expect, it } from "vitest";
import { AREA_ICON, BLANK, haloIcon, lampIcon, PIN_ICON, roleIcon, ROLES, type DeviceRole } from "./icons";

const svgOf = (uri: string) => decodeURIComponent(uri.slice(uri.indexOf(",") + 1));

describe("device pictograms", () => {
  it("has one distinct picture per role", () => {
    expect(ROLES).toHaveLength(11);
    expect(new Set(ROLES.map(roleIcon)).size).toBe(ROLES.length);
  });

  it("falls back to the generic picture for no role or an unknown one", () => {
    expect(roleIcon(null)).toBe(roleIcon("other"));
    expect(roleIcon(undefined)).toBe(roleIcon("other"));
    expect(roleIcon("mainframe" as DeviceRole)).toBe(roleIcon("other"));
  });

  it("is self-contained SVG: data URIs with no script, link or outside reference", () => {
    const all = [...ROLES.map(roleIcon), AREA_ICON, PIN_ICON, BLANK, ...(["up", "partial", "down", "unknown"] as const).map(lampIcon), haloIcon("high")];
    for (const u of all) {
      expect(u.startsWith("data:image/svg+xml;utf8,")).toBe(true);
      const svg = svgOf(u);
      expect(svg).toMatch(/^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
      expect(svg).not.toMatch(/<script|<foreignObject|href=|url\((?!#)|on\w+=/i);
      /* well-formed: the decoder would show nothing on a duplicate attribute */
      for (const tag of svg.match(/<[a-zA-Z][^>]*>/g) ?? []) {
        const names = [...tag.matchAll(/\s([\w:-]+)=/g)].map((m) => m[1]);
        expect(new Set(names).size, tag).toBe(names.length);
      }
    }
  });

  it("colors the status lamp by state", () => {
    expect(svgOf(lampIcon("up"))).toContain("#22c55e");
    expect(svgOf(lampIcon("down"))).toContain("#ef4444");
    expect(new Set((["up", "partial", "down", "unknown"] as const).map(lampIcon)).size).toBe(4);
  });
});
