import { describe, expect, it } from "vitest";
import type { IfPoint } from "@/features/devices/api";
import { ERROR_KEYS, MAX_POINTS, TRAFFIC_KEYS, coarserStep, formatBps, isEmpty, pickStep, presetRange, shapeData } from "./series";

const now = new Date("2026-10-21T12:00:00Z");
const UNITS = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
const pt = (ts: string, over: Partial<IfPoint> = {}): IfPoint => ({
  ts,
  in_bps: 1,
  in_bps_max: 1,
  out_bps: 2,
  out_bps_max: 2,
  in_err_ps: 0,
  out_err_ps: 0,
  in_disc_ps: 0,
  out_disc_ps: 0,
  oper_up: true,
  speed_bps: 1000,
  ...over,
});

describe("pickStep", () => {
  it("keeps every preset within the point limit and the source resolution", () => {
    for (const p of ["1h", "6h", "24h", "7d", "30d"] as const) {
      const { from, to } = presetRange(p, now);
      const step = pickStep(from, to, now);
      const width = (to.getTime() - from.getTime()) / 1000;
      const age = (now.getTime() - from.getTime()) / 1000;
      const res = width <= 48 * 3600 && age <= 14 * 86400 ? 10 : width <= 60 * 86400 && age <= 90 * 86400 ? 300 : 3600;
      expect(step).toBeGreaterThanOrEqual(res);
      expect(width / step).toBeLessThanOrEqual(MAX_POINTS);
    }
  });

  it("uses the hourly resolution for old and for very wide ranges", () => {
    const to = new Date(now.getTime() - 200 * 86400 * 1000);
    const from = new Date(to.getTime() - 86400 * 1000);
    expect(pickStep(from, to, now)).toBe(3600);
    const wide = new Date(now.getTime() - 700 * 86400 * 1000);
    expect(pickStep(wide, now, now)).toBeGreaterThanOrEqual(3600);
    expect((now.getTime() - wide.getTime()) / 1000 / pickStep(wide, now, now)).toBeLessThanOrEqual(MAX_POINTS);
  });

  it("coarserStep grows the step", () => {
    expect(coarserStep(60)).toBeGreaterThan(60);
  });
});

describe("shapeData", () => {
  it("converts to epoch seconds and keeps NULL as null, never 0", () => {
    const cols = shapeData([pt("2026-10-21T10:00:00Z"), pt("2026-10-21T10:01:00Z", { in_err_ps: null, out_err_ps: 0 })], ERROR_KEYS, 60);
    expect(cols[0]).toEqual([Date.parse("2026-10-21T10:00:00Z") / 1000, Date.parse("2026-10-21T10:01:00Z") / 1000]);
    expect(cols[1]).toEqual([0, null]);
    expect(cols[2]).toEqual([0, 0]);
  });

  it("breaks the line over a hole instead of bridging it", () => {
    const cols = shapeData([pt("2026-10-21T10:00:00Z"), pt("2026-10-21T10:01:00Z"), pt("2026-10-21T10:30:00Z")], TRAFFIC_KEYS, 60);
    expect(cols[0]).toHaveLength(4);
    expect(cols[1][2]).toBeNull();
    expect(cols[2][2]).toBeNull();
    expect(cols[0][2]).toBe((cols[0][1] as number) + 60);
  });

  it("infers the spacing of raw points (step 0) from the median", () => {
    const cols = shapeData([pt("2026-10-21T10:00:00Z"), pt("2026-10-21T10:00:10Z"), pt("2026-10-21T10:00:20Z"), pt("2026-10-21T10:05:00Z")], TRAFFIC_KEYS, 0);
    expect(cols[1].filter((v) => v === null)).toHaveLength(1);
  });

  it("handles empty input", () => {
    const cols = shapeData([], TRAFFIC_KEYS, 0);
    expect(cols).toEqual([[], [], []]);
    expect(isEmpty(cols)).toBe(true);
  });

  it("isEmpty is true when every error value is NULL and false with a zero", () => {
    expect(isEmpty(shapeData([pt("2026-10-21T10:00:00Z", { in_err_ps: null, out_err_ps: null, in_disc_ps: null, out_disc_ps: null })], ERROR_KEYS, 60))).toBe(true);
    expect(isEmpty(shapeData([pt("2026-10-21T10:00:00Z")], ERROR_KEYS, 60))).toBe(false);
  });
});

describe("formatBps", () => {
  it("applies decimal bit prefixes", () => {
    expect(formatBps(0, UNITS, "en")).toBe("0 bit/s");
    expect(formatBps(999, UNITS, "en")).toBe("999 bit/s");
    expect(formatBps(1000, UNITS, "en")).toBe("1 kbit/s");
    expect(formatBps(1_500_000, UNITS, "en")).toBe("1.5 Mbit/s");
    expect(formatBps(2.5e9, UNITS, "en")).toBe("2.5 Gbit/s");
    expect(formatBps(3e15, UNITS, "en")).toBe("3,000 Tbit/s");
  });
});
