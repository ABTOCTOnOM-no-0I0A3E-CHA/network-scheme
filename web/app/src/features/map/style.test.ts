import { describe, expect, it } from "vitest";
import { buildStylesheet, iconKey, linkStyle, linkWidth, LINK_COLOR, worseState } from "./style";

describe("linkWidth", () => {
  it("grows with the speed", () => {
    const w = [10e6, 100e6, 1e9, 10e9, 40e9, 100e9].map(linkWidth);
    expect(w.slice(0, 5)).toEqual([...w.slice(0, 5)].sort((a, b) => a - b));
    expect(new Set(w.slice(0, 5)).size).toBe(5);
    expect(w[5]).toBe(w[4]);
  });
  it("has a visible default for an unknown speed", () => {
    expect(linkWidth(null)).toBeGreaterThan(0);
    expect(linkWidth(0)).toBe(linkWidth(null));
  });
});

describe("linkStyle", () => {
  const base = { speed_bps: 1e9, confidence: 1, manual: false };
  it("colors by the worse end", () => {
    expect(linkStyle(base, "up", "up").color).toBe(LINK_COLOR.ok);
    expect(linkStyle(base, "up", "unknown").color).toBe(LINK_COLOR.ok);
    expect(linkStyle(base, "up", "partial").color).toBe(LINK_COLOR.partial);
    expect(linkStyle(base, "partial", "down").color).toBe(LINK_COLOR.down);
  });
  it("dashes links below 0.8 confidence", () => {
    expect(linkStyle({ ...base, confidence: 0.79 }, "up", "up").dashed).toBe(true);
    expect(linkStyle({ ...base, confidence: 0.8 }, "up", "up").dashed).toBe(false);
    expect(linkStyle({ ...base, confidence: 0.4 }, "up", "up").dashed).toBe(true);
  });
  it("draws manual links in their own color, never dashed, whatever the state", () => {
    const s = linkStyle({ ...base, manual: true, confidence: 0.1 }, "down", "down");
    expect(s).toMatchObject({ color: LINK_COLOR.manual, dashed: false });
  });
});

describe("misc", () => {
  it("orders states", () => {
    expect(worseState("up", "down")).toBe("down");
    expect(worseState("partial", "unknown")).toBe("partial");
    expect(worseState("unknown", "up")).toBe("unknown");
  });
  it("picks icons by driver", () => {
    expect(iconKey("eltex-mes")).toBe("switch");
    expect(iconKey("eltex-esr")).toBe("router");
    expect(iconKey("whatever")).toBe("device");
  });
  it("switches to cheap edges for large maps", () => {
    const sheet = (large: boolean) => JSON.stringify(buildStylesheet({ dark: false, large }));
    expect(sheet(true)).toContain("haystack");
    expect(sheet(false)).not.toContain("haystack");
  });
});
