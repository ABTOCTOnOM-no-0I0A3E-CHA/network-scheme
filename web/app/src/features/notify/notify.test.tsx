import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import type { ProblemSummary } from "@/features/problems/api";
import { backoffMs, DEFAULT_SETTINGS, loadSettings, parseMessage, ProblemSocket, SETTINGS_KEY, shouldNotify, type ProblemMessage } from "./feed";
import { NotificationCenter } from "./NotificationCenter";

class FakeWS {
  static all: FakeWS[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onclose: ((e: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(readonly url: string) {
    FakeWS.all.push(this);
  }
  close() {
    this.closed = true;
  }
  open() {
    this.onopen?.();
  }
  send(data: unknown) {
    this.onmessage?.({ data });
  }
  drop(code = 1006) {
    this.onclose?.({ code });
  }
}

const summary = (over: Partial<ProblemSummary> = {}): ProblemSummary => ({
  id: 1,
  device_id: 1,
  device_name: "core-sw",
  group_id: 1,
  severity: "high",
  state: "problem",
  suppressed: false,
  name: "Link down",
  object: "",
  opened_at: "2026-10-22T10:00:00Z",
  acknowledged_at: null,
  resolved_at: null,
  ...over,
});
const msg = (event: string, over: Partial<ProblemSummary> = {}) => JSON.stringify({ type: "problem", event, problem: summary(over) });
const parsed = (event: string, over: Partial<ProblemSummary> = {}) => parseMessage(msg(event, over)) as ProblemMessage;

beforeEach(() => {
  FakeWS.all = [];
  localStorage.clear();
  vi.stubGlobal("WebSocket", FakeWS);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("parseMessage", () => {
  it("accepts problem messages only", () => {
    expect(parsed("opened").problem.id).toBe(1);
    expect(parseMessage('{"type":"pong"}')).toBeNull();
    expect(parseMessage("not json")).toBeNull();
    expect(parseMessage(new ArrayBuffer(1))).toBeNull();
    expect(parseMessage(JSON.stringify({ type: "problem", event: "weird", problem: summary() }))).toBeNull();
    expect(parseMessage(JSON.stringify({ type: "problem", event: "opened", problem: { id: 1 } }))).toBeNull();
  });
});

describe("shouldNotify", () => {
  const s = { sound: true, severityMin: "high" as const, groups: [] };
  it("announces only opened, unsuppressed problems at or above the severity", () => {
    expect(shouldNotify(parsed("opened"), s)).toBe(true);
    expect(shouldNotify(parsed("opened", { severity: "disaster" }), s)).toBe(true);
    expect(shouldNotify(parsed("opened", { severity: "average" }), s)).toBe(false);
    expect(shouldNotify(parsed("opened", { suppressed: true }), s)).toBe(false);
    expect(shouldNotify(parsed("resolved"), s)).toBe(false);
    expect(shouldNotify(parsed("acknowledged"), s)).toBe(false);
  });
  it("narrows to the chosen groups", () => {
    expect(shouldNotify(parsed("opened", { group_id: 2 }), { ...s, groups: [1] })).toBe(false);
    expect(shouldNotify(parsed("opened", { group_id: 1 }), { ...s, groups: [1] })).toBe(true);
    expect(shouldNotify(parsed("opened", { group_id: null }), { ...s, groups: [1] })).toBe(false);
  });
});

describe("settings storage", () => {
  it("falls back to the defaults for garbage and keeps only valid fields", () => {
    expect(DEFAULT_SETTINGS.severityMin).toBe("average");
    expect(loadSettings()).toEqual(DEFAULT_SETTINGS);
    localStorage.setItem(SETTINGS_KEY, "{bad");
    expect(loadSettings()).toEqual(DEFAULT_SETTINGS);
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ sound: "yes", severityMin: "nope", groups: [3, "x", -1, 4.5, 7], token: "secret" }));
    expect(loadSettings()).toEqual({ sound: false, severityMin: DEFAULT_SETTINGS.severityMin, groups: [3, 7] });
  });
});

describe("reconnect", () => {
  it("backs off from 1 s to 30 s", () => {
    expect([0, 1, 2, 3, 4, 5, 6, 20].map((a) => backoffMs(a, () => 0))).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
    for (let a = 0; a < 8; a++) expect(backoffMs(a, () => 1)).toBeGreaterThanOrEqual(Math.min(30000, 1000 * 2 ** a) * 0.8 - 1);
  });

  it("reconnects with growing delays, resets after an open and stops when stopped", () => {
    vi.useFakeTimers();
    const opens: boolean[] = [];
    const s = new ProblemSocket({ onMessage: () => undefined, onOpen: (r) => opens.push(r) }, () => "ws://x/api/ws", () => 0);
    s.start();
    expect(FakeWS.all).toHaveLength(1);
    FakeWS.all[0].drop();
    vi.advanceTimersByTime(999);
    expect(FakeWS.all).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(FakeWS.all).toHaveLength(2);
    FakeWS.all[1].drop();
    vi.advanceTimersByTime(1999);
    expect(FakeWS.all).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(FakeWS.all).toHaveLength(3);
    FakeWS.all[2].open();
    expect(opens).toEqual([true]);
    FakeWS.all[2].drop(1013);
    vi.advanceTimersByTime(1000);
    expect(FakeWS.all).toHaveLength(4);
    s.stop();
    expect(FakeWS.all[3].closed).toBe(true);
    vi.advanceTimersByTime(60_000);
    expect(FakeWS.all).toHaveLength(4);
  });

  it("uses the same origin and puts nothing in the URL", () => {
    const s = new ProblemSocket({ onMessage: () => undefined });
    s.start();
    expect(FakeWS.all[0].url).toBe(`ws://${location.host}/api/ws`);
    s.stop();
  });
});

const server = setupServer(
  http.get("*/api/groups", () => HttpResponse.json([{ id: 1, parent_id: null, name: "HQ" }])),
  http.get("*/api/auth/me", () => HttpResponse.json({ id: 1, username: "admin", roles: [{ role: "admin", group_id: null }] })),
);

describe("NotificationCenter", () => {
  beforeEach(() => {
    server.listen({ onUnhandledFrame: "bypass" });
    /* listen() patches WebSocket itself: put the fake back on top */
    vi.stubGlobal("WebSocket", FakeWS);
  });
  afterEach(() => server.close());

  function setup(roles = [{ role: "admin", group_id: null as number | null }]) {
    server.use(http.get("*/api/auth/me", () => HttpResponse.json({ id: 1, username: "u", roles })));
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const play = vi.fn();
    render(
      <QueryClientProvider client={qc}>
        <NotificationCenter onOpenProblems={() => undefined} play={play} />
      </QueryClientProvider>,
    );
    return { play, qc };
  }
  const socket = async () => {
    await vi.waitFor(() => expect(FakeWS.all.length).toBeGreaterThan(0));
    const ws = FakeWS.all[0];
    act(() => ws.open());
    return ws;
  };

  it("counts newly opened problems in the badge, refreshes the problem queries and resets on open", async () => {
    const { qc } = setup();
    const inv = vi.spyOn(qc, "invalidateQueries");
    const ws = await socket();
    expect(screen.queryByTestId("notify-badge")).not.toBeInTheDocument();
    act(() => ws.send(msg("opened")));
    act(() => ws.send(msg("opened", { id: 2 })));
    act(() => ws.send(msg("resolved", { id: 3 })));
    expect(screen.getByTestId("notify-badge")).toHaveTextContent("2");
    expect(inv).toHaveBeenCalledWith({ queryKey: ["problems"] });

    await userEvent.click(screen.getByRole("button", { name: /Уведомления/ }));
    expect(screen.queryByTestId("notify-badge")).not.toBeInTheDocument();
    expect(await screen.findAllByText("Link down")).toHaveLength(2);
  });

  it("plays the sound only when enabled and for problems at or above the chosen severity", async () => {
    const { play } = setup();
    const ws = await socket();
    act(() => ws.send(msg("opened")));
    expect(play).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: /Уведомления/ }));
    const panel = await screen.findByRole("group", { name: ru.notify.settings });
    await userEvent.click(within(panel).getByLabelText(ru.notify.sound));
    act(() => ws.send(msg("opened", { id: 2 })));
    expect(play).toHaveBeenCalledTimes(1);
    act(() => ws.send(msg("opened", { id: 3, severity: "warning" })));
    act(() => ws.send(msg("opened", { id: 4, suppressed: true })));
    act(() => ws.send(msg("resolved", { id: 1 })));
    expect(play).toHaveBeenCalledTimes(1);

    await userEvent.selectOptions(within(panel).getByLabelText(ru.notify.severityMin), "warning");
    act(() => ws.send(msg("opened", { id: 5, severity: "warning" })));
    expect(play).toHaveBeenCalledTimes(2);
  });

  it("persists the preferences locally: booleans, severity and group ids only", async () => {
    setup();
    await socket();
    await userEvent.click(screen.getByRole("button", { name: /Уведомления/ }));
    const panel = await screen.findByRole("group", { name: ru.notify.settings });
    await userEvent.click(within(panel).getByLabelText(ru.notify.sound));
    await userEvent.selectOptions(within(panel).getByLabelText(ru.notify.severityMin), "average");
    await userEvent.click(await within(panel).findByLabelText("HQ"));
    expect(JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? "null")).toEqual({ sound: true, severityMin: "average", groups: [1] });
  });

  it("does not connect for an auditor", async () => {
    setup([{ role: "auditor", group_id: null }]);
    await screen.findByRole("button", { name: /Уведомления/ });
    await new Promise((r) => setTimeout(r, 50));
    expect(FakeWS.all).toHaveLength(0);
  });
});
