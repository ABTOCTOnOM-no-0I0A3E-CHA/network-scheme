import { describe, expect, it } from "vitest";
import ru from "../i18n/ru.json";
import { parsePreset, REFUSALS, refusalKey, sessionGone, sessionMessage } from "./api";
import { noticeKey } from "./DeviceTerminal";
import { parseDevices } from "./SessionApp";

const get = (key: string) => key.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], ru);

describe("session texts", () => {
  it("every refusal code and terminal code has a Russian text", () => {
    for (const c of REFUSALS) expect(get(refusalKey(c)!), c).toEqual(expect.any(String));
    for (const c of ["line_limit", "device_error", "send_failed", "rest_dropped", "nothing_pending", "device_name", "rate_limited", "changed",
      "no_device_name", "denied", "frozen", "disabled", "locked", "unavailable", "too_many_challenges", "control", "writes_disabled", "recording_full", "zzz"]) {
      expect(get(noticeKey({ code: c })), c).toEqual(expect.any(String));
    }
  });

  it("maps refusals, ended sessions and the common failures", () => {
    expect(sessionMessage({ kind: "http", status: 422, code: "superseded" })).toEqual({ key: "executor.session.refused.superseded" });
    expect(sessionMessage({ kind: "http", status: 422, code: "new_code" })).toEqual({ key: "executor.session.refused.other" });
    expect(sessionMessage({ kind: "http", status: 401, code: "no_token" })).toEqual({ key: "executor.session.refused.no_session" });
    expect(sessionMessage({ kind: "http", status: 503, code: "frozen" })).toEqual({ key: "executor.error.frozen" });
    expect(sessionMessage({ kind: "http", status: 429, code: "rate_limited", retryAfter: 7 })).toEqual({ key: "executor.error.rate_limited", params: { seconds: 7 } });
    expect(sessionGone({ kind: "http", status: 422, code: "no_session" })).toBe(true);
    expect(sessionGone({ kind: "http", status: 422, code: "device_busy" })).toBe(false);
  });
});

describe("what the panel may preselect", () => {
  it("only ids and a session uuid, never anything else", () => {
    expect(parsePreset("#device=12,14")).toEqual({ devices: [12, 14], replay: undefined });
    expect(parsePreset("#device=12,abc,-1,0,99999999999999999999")).toEqual({ devices: [12], replay: undefined });
    expect(parsePreset("#replay=3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c&device=12")).toEqual({
      devices: [12], replay: { session: "3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c", device: 12 } });
    expect(parsePreset("#replay=<script>&device=12").replay).toBeUndefined();
    expect(parsePreset("").devices).toEqual([]);
  });

  it("parses the typed device list", () => {
    expect(parseDevices("12, 14 14;15")).toEqual([12, 14, 15]);
    expect(parseDevices("12, x")).toBeNull();
    expect(parseDevices("")).toBeNull();
    expect(parseDevices("0")).toBeNull();
  });
});
