import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { SystemStatus } from "@/features/system/SystemStatus";
import { EventFeed, eventKeys } from "./EventFeed";
import type { NmsEvent } from "./api";
import { Unidentified } from "./Unidentified";

const err = (status: number, code: string) => HttpResponse.json({ error: { code, message: "RAW SERVER MESSAGE" } }, { status });
const HOSTILE = "<script>alert(1)</script>\u0007‮evil";

const ev = (i: number, over: Record<string, unknown> = {}): NmsEvent => ({
  ts: new Date(Date.UTC(2026, 9, 22, 10, 0, 0) - i * 1000).toISOString(),
  kind: "syslog",
  device_id: 1,
  device_name: "core-sw",
  severity: "info",
  app: "sshd",
  text: `message ${i}`,
  identified: true,
  ...over,
});

let eventsFn: (q: URLSearchParams) => Response;
let eventRequests: URLSearchParams[] = [];
let unidentifiedFn: () => Response;
let ruleBody: unknown;
let ruleFn: () => Response;
let createdOids: string[] = [];
let rulesFn: () => Response;
let deletedId: string | undefined;
let statusFn: () => Response;

const server = setupServer(
  http.get("*/api/events/unidentified", () => unidentifiedFn()),
  http.get("*/api/events", ({ request }) => {
    const q = new URL(request.url).searchParams;
    eventRequests.push(q);
    return eventsFn(q);
  }),
  http.get("*/api/devices", () => HttpResponse.json([{ id: 1, name: "core-sw", address: "192.0.2.10", group_id: 1, driver: "generic-snmp", model: "", firmware: "", insecure_protocols: false, state: "up", state_since: null }])),
  http.get("*/api/trap-rules", () => rulesFn()),
  http.delete("*/api/trap-rules/:id", ({ params }) => {
    deletedId = String(params.id);
    return new HttpResponse(null, { status: 204 });
  }),
  http.post("*/api/trap-rules", async ({ request }) => {
    ruleBody = await request.json();
    const res = ruleFn();
    if (res.ok) createdOids.push((ruleBody as { trap_oid: string }).trap_oid);
    return res;
  }),
  http.get("*/api/system/status", () => statusFn()),
);

beforeAll(() => {
  server.listen({ onUnhandledFrame: "error" });
  /* jsdom has no layout: the scroll area is 440px high, a row 40px */
  Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, get: () => 440 });
  Object.defineProperty(HTMLElement.prototype, "clientWidth", { configurable: true, get: () => 1100 });
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get: () => 40 });
  HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
    const h = this.hasAttribute("data-index") ? 40 : 440;
    return { width: 1100, height: h, top: 0, left: 0, right: 1100, bottom: h, x: 0, y: 0, toJSON() {} };
  };
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  eventRequests = [];
  ruleBody = undefined;
  createdOids = [];
  deletedId = undefined;
});
afterAll(() => server.close());

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const last = () => eventRequests[eventRequests.length - 1];
const dataRows = () => screen.getAllByRole("row").filter((r) => r.hasAttribute("data-index"));

describe("EventFeed", () => {
  it("renders hostile event text as plain text and marks truncated varbinds", async () => {
    eventsFn = () =>
      HttpResponse.json({
        items: [
          ev(0, { kind: "trap", severity: null, name: HOSTILE, text: `1.3.6.1.4.1.9.${HOSTILE}`, identified: false, varbinds: [{ OID: "1.3.6.1.2.1.1.5.0", Type: "OctetString", Value: HOSTILE, Truncated: true }] }),
          ev(1, { app: HOSTILE, text: HOSTILE }),
        ],
        next_cursor: null,
      });
    const { container } = wrap(<EventFeed />);
    await waitFor(() => expect(dataRows()).toHaveLength(2));
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>��evil");
    expect(container.textContent).not.toContain("‮");
    expect(screen.getByText(ru.events.unidentified)).toBeInTheDocument();

    await userEvent.click(screen.getAllByRole("button", { name: ru.events.expand })[0]);
    const details = screen.getByTestId("event-details");
    expect(within(details).getByText(ru.events.truncated)).toBeInTheDocument();
    expect(within(details).getByText("1.3.6.1.2.1.1.5.0")).toBeInTheDocument();
  });

  it("sends the filters and repeats them with the cursor", async () => {
    eventsFn = (q) =>
      q.get("cursor") === "c1"
        ? HttpResponse.json({ items: [ev(100, { text: "second page" })], next_cursor: null })
        : HttpResponse.json({ items: [ev(0, { text: "first page" })], next_cursor: "c1" });
    wrap(<EventFeed />);
    await screen.findByText("first page");
    expect(last().get("kind")).toBeNull();
    expect(last().get("from")).not.toBeNull();

    await userEvent.selectOptions(screen.getByLabelText(ru.events.filter.kind), "trap");
    await userEvent.selectOptions(screen.getByLabelText(ru.events.filter.severity), "high");
    await userEvent.selectOptions(screen.getByLabelText(ru.events.filter.device), "1");
    await userEvent.selectOptions(screen.getByLabelText(ru.events.filter.period), "7d");
    await screen.findByText("first page");
    await waitFor(() => expect(last().get("device_id")).toBe("1"));
    expect(last().get("kind")).toBe("trap");
    expect(last().get("severity_min")).toBe("high");
    const span = Date.now() - Date.parse(last().get("from")!);
    expect(span).toBeGreaterThan(6.9 * 86_400_000);
    expect(span).toBeLessThan(7.1 * 86_400_000);

    /* one short page is within reach of the end, so the next one is requested without a click */
    await screen.findByText("second page");
    expect(last().get("cursor")).toBe("c1");
    expect(last().get("kind")).toBe("trap");
    expect(last().get("severity_min")).toBe("high");
    expect(last().get("device_id")).toBe("1");
    expect(screen.queryByRole("button", { name: ru.events.loadMore })).not.toBeInTheDocument();
  });

  it("offers a load-more button while the end is far", async () => {
    eventsFn = (q) =>
      q.get("cursor") === "c1"
        ? HttpResponse.json({ items: [ev(900, { text: "tail page" })], next_cursor: null })
        : HttpResponse.json({ items: Array.from({ length: 200 }, (_, i) => ev(i)), next_cursor: "c1" });
    wrap(<EventFeed />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.loadMore }));
    await waitFor(() => expect(last().get("cursor")).toBe("c1"));
    expect(screen.getByText(ru.events.count.replace("{{count}}", "201"))).toBeInTheDocument();
  });

  it("debounces the text search", async () => {
    eventsFn = () => HttpResponse.json({ items: [], next_cursor: null });
    wrap(<EventFeed />);
    await screen.findByText(ru.events.empty);
    const before = eventRequests.length;
    await userEvent.type(screen.getByLabelText(ru.events.filter.search), "link down");
    await waitFor(() => expect(last().get("q")).toBe("link down"));
    /* one request for the whole word, not one per keystroke */
    expect(eventRequests.length - before).toBe(1);
  });

  it("rejects a custom period over 31 days without calling the API", async () => {
    eventsFn = () => HttpResponse.json({ items: [], next_cursor: null });
    wrap(<EventFeed />);
    await screen.findByText(ru.events.empty);
    await userEvent.selectOptions(screen.getByLabelText(ru.events.filter.period), "custom");
    const before = eventRequests.length;
    fireEvent.change(screen.getByLabelText(ru.events.period.from), { target: { value: "2026-08-01T00:00" } });
    fireEvent.change(screen.getByLabelText(ru.events.period.to), { target: { value: "2026-10-01T00:00" } });
    expect(await screen.findByText(ru.events.periodError.tooWide)).toBeInTheDocument();
    expect(eventRequests.length).toBe(before);

    fireEvent.change(screen.getByLabelText(ru.events.period.from), { target: { value: "2026-09-20T00:00" } });
    await waitFor(() => expect(screen.queryByText(ru.events.periodError.tooWide)).not.toBeInTheDocument());
    await waitFor(() => expect(last().get("to")).not.toBeNull());
  });

  it("renders only the visible window of a long page", async () => {
    eventsFn = () => HttpResponse.json({ items: Array.from({ length: 500 }, (_, i) => ev(i)), next_cursor: "more" });
    wrap(<EventFeed />);
    await screen.findByText("message 0");
    expect(dataRows().length).toBeLessThan(40);
    expect(screen.getByText(ru.events.count.replace("{{count}}", "500"))).toBeInTheDocument();
  });

  it("fixes the device on a device journal and hides the device filter", async () => {
    eventsFn = () => HttpResponse.json({ items: [ev(0)], next_cursor: null });
    wrap(<EventFeed deviceId={7} />);
    await screen.findByText("message 0");
    expect(last().get("device_id")).toBe("7");
    expect(screen.queryByLabelText(ru.events.filter.device)).not.toBeInTheDocument();
  });

  it("keeps a row expanded across a refresh that adds newer events", async () => {
    let extra = false;
    eventsFn = () => HttpResponse.json({ items: [...(extra ? [ev(-5, { text: "brand new" })] : []), ev(1, { text: "keep me" }), ev(2, { text: "other" })], next_cursor: null });
    wrap(<EventFeed />);
    await screen.findByText("keep me");
    await userEvent.click(screen.getAllByRole("button", { name: ru.events.expand })[0]);
    expect(screen.getAllByTestId("event-details")).toHaveLength(1);
    extra = true;
    await userEvent.click(screen.getByRole("button", { name: ru.events.refresh }));
    await screen.findByText("brand new");
    const details = screen.getByTestId("event-details");
    expect(details).toHaveTextContent("keep me");
  });

  it("says when the varbinds of a trap were too large to list", async () => {
    eventsFn = () => HttpResponse.json({ items: [ev(0, { kind: "trap", name: "big", varbinds_omitted: true })], next_cursor: null });
    wrap(<EventFeed />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.expand }));
    expect(screen.getByText(ru.events.varbindsOmitted)).toBeInTheDocument();
    expect(screen.queryByText(ru.events.noVarbinds)).not.toBeInTheDocument();
  });

  it("shows a storm row with the folded kind, the repeat count and the minute", async () => {
    eventsFn = () => HttpResponse.json({ items: [ev(0, { kind: "storm", severity: null, text: "syslog", count: 500, ts: "2026-01-01T10:07:00Z" })], next_cursor: null });
    wrap(<EventFeed />);
    await waitFor(() => expect(dataRows()).toHaveLength(1));
    const row = dataRows()[0];
    expect(within(row).getByText(ru.events.kind.storm)).toBeInTheDocument();
    expect(row.textContent).toContain("500");
    expect(row.textContent).toContain("Свёрнуто событий (Syslog)");
  });

  it("maps API errors to a localized message", async () => {
    eventsFn = () => err(400, "bad_request");
    wrap(<EventFeed />);
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.bad_request);
    expect(document.body.textContent).not.toContain("RAW SERVER MESSAGE");
  });
});

describe("eventKeys", () => {
  it("depends on content, not position, and tells identical rows apart", () => {
    const a = ev(1, { text: "a" });
    const b = ev(2, { text: "b" });
    const before = eventKeys([a, b]);
    expect(eventKeys([ev(0, { text: "new" }), a, b]).slice(1)).toEqual(before);
    const dup = eventKeys([a, a]);
    expect(dup[0]).not.toBe(dup[1]);
    expect(new Set(before).size).toBe(2);
  });
});

describe("Unidentified", () => {
  const row = { trap_oid: "1.3.6.1.4.1.35265.1.2", count: 12, last_ts: "2026-10-22T10:00:00Z", last_device_id: 1, last_device_name: "core-sw", last_varbinds: [{ OID: "1.3.6.1.2.1.1.3.0", Type: "TimeTicks", Value: "100", Truncated: false }] };

  it("viewer cannot create rules", async () => {
    unidentifiedFn = () => HttpResponse.json({ items: [row], next_cursor: null });
    wrap(<Unidentified canManage={false} />);
    await screen.findByText(row.trap_oid);
    expect(screen.queryByRole("button", { name: ru.events.rule.create })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: ru.events.varbindsOf.replace("{{oid}}", row.trap_oid) }));
    expect(screen.getByText("1.3.6.1.2.1.1.3.0")).toBeInTheDocument();
  });

  it("creates a rule with the OID prefilled and the row disappears after the refresh", async () => {
    unidentifiedFn = () => HttpResponse.json({ items: [row].filter((r) => !createdOids.includes(r.trap_oid)), next_cursor: null });
    ruleFn = () => new HttpResponse(null, { status: 201 });
    wrap(<Unidentified canManage />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.rule.createFor.replace("{{oid}}", row.trap_oid) }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText(ru.events.rule.oid)).toHaveValue(row.trap_oid);
    await userEvent.type(within(dialog).getByLabelText(ru.events.rule.name), "  Link flap ");
    await userEvent.selectOptions(within(dialog).getByLabelText(ru.events.rule.severity), "high");
    await userEvent.click(within(dialog).getByRole("button", { name: ru.events.rule.create }));
    await waitFor(() => expect(ruleBody).toEqual({ trap_oid: row.trap_oid, name: "Link flap", severity: "high" }));
    await waitFor(() => expect(screen.queryByText(row.trap_oid)).not.toBeInTheDocument());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText(ru.events.unidentifiedEmpty)).toBeInTheDocument();
  });

  it("rejects a rule name over 1024 bytes without calling the API", async () => {
    unidentifiedFn = () => HttpResponse.json({ items: [row], next_cursor: null });
    ruleFn = () => new HttpResponse(null, { status: 201 });
    wrap(<Unidentified canManage />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.rule.createFor.replace("{{oid}}", row.trap_oid) }));
    const dialog = await screen.findByRole("dialog");
    /* 600 two-byte characters: 600 chars but 1200 bytes */
    fireEvent.change(within(dialog).getByLabelText(ru.events.rule.name), { target: { value: "я".repeat(600) } });
    await userEvent.click(within(dialog).getByRole("button", { name: ru.events.rule.create }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(ru.events.rule.tooLong.replace("{{max}}", "1024"));
    expect(ruleBody).toBeUndefined();
  });

  it("lists trap rules for managers and deletes one after a confirmation", async () => {
    unidentifiedFn = () => HttpResponse.json({ items: [], next_cursor: null });
    rulesFn = () => HttpResponse.json([{ id: 5, trap_oid: "1.3.6.1.4.1.9.9", name: HOSTILE, severity: "high", created_at: "2026-10-20T10:00:00Z" }]);
    const { container } = wrap(<Unidentified canManage />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.rules.title }));
    expect(await screen.findByText("1.3.6.1.4.1.9.9")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: ru.events.rules.deleteFor.replace("{{oid}}", "1.3.6.1.4.1.9.9") }));
    expect(deletedId).toBeUndefined();
    await userEvent.click(screen.getByRole("button", { name: ru.events.rules.confirm }));
    await waitFor(() => expect(deletedId).toBe("5"));
  });

  it("does not offer the rules list to viewers", async () => {
    unidentifiedFn = () => HttpResponse.json({ items: [], next_cursor: null });
    wrap(<Unidentified canManage={false} />);
    await screen.findByText(ru.events.unidentifiedEmpty);
    expect(screen.queryByRole("button", { name: ru.events.rules.title })).not.toBeInTheDocument();
  });

  it("says when the varbinds are too large to list", async () => {
    unidentifiedFn = () => HttpResponse.json({ items: [{ ...row, last_varbinds: undefined, last_varbinds_omitted: true }], next_cursor: null });
    wrap(<Unidentified canManage={false} />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.varbindsOf.replace("{{oid}}", row.trap_oid) }));
    expect(screen.getByText(ru.events.varbindsOmitted)).toBeInTheDocument();
  });

  it("shows trap_rule_exists and keeps the dialog open", async () => {
    unidentifiedFn = () => HttpResponse.json({ items: [row], next_cursor: null });
    ruleFn = () => err(409, "trap_rule_exists");
    wrap(<Unidentified canManage />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.rule.createFor.replace("{{oid}}", row.trap_oid) }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(ru.events.rule.name), "x");
    await userEvent.click(within(dialog).getByRole("button", { name: ru.events.rule.create }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(ru.errors.trap_rule_exists);
  });
});

describe("SystemStatus", () => {
  it("shows counters and highlights a silent poller and a stale eventd", async () => {
    /* the browser clock is irrelevant: only the server's `now` counts */
    const now = Date.parse("2020-01-01T00:00:00Z");
    statusFn = () =>
      HttpResponse.json({
        now: new Date(now).toISOString(),
        pollers: [
          { id: "poller-a", devices: 10, devices_reporting: 9, heartbeat_at: new Date(now - 10_000).toISOString() },
          { id: "poller-b", devices: 5, devices_reporting: 0, heartbeat_at: null },
          { id: "poller-idle", devices: 0, devices_reporting: 0, heartbeat_at: null },
          { id: "poller-stale", devices: 4, devices_reporting: 4, heartbeat_at: new Date(now - 200_000).toISOString() },
        ],
        eventd: [
          { instance: "eventd-fresh", updated_at: new Date(now - 5_000).toISOString(), received: 100, accepted: 90, unknown_source: 3, auth_failed: 2, rate_limited: 1, dropped: 4, queue_depth: 7 },
          { instance: "eventd-old", updated_at: new Date(now - 120_000).toISOString(), received: 1, accepted: 1, unknown_source: 0, auth_failed: 0, rate_limited: 0, dropped: 0, queue_depth: 0 },
        ],
        db_size_bytes: 52428800,
        queues: [{ name: "default", available: 3, running: 1, retryable: 2 }],
      });
    wrap(<SystemStatus />);
    const rowOf = async (text: string) => (await screen.findByText(text)).closest("tr")!;
    expect(await rowOf("poller-b")).toHaveAttribute("data-alert", "true");
    expect(within(await rowOf("poller-b")).getByText(ru.system.silent)).toBeInTheDocument();
    expect(await rowOf("poller-a")).toHaveAttribute("data-alert", "false");
    expect(await rowOf("poller-idle")).toHaveAttribute("data-alert", "false");
    expect(await rowOf("poller-stale")).toHaveAttribute("data-alert", "true"); /* reports devices, but its heartbeat is old */
    expect(await rowOf("eventd-old")).toHaveAttribute("data-alert", "true");
    expect(within(await rowOf("eventd-old")).getByText(ru.system.stale)).toBeInTheDocument();
    expect(await rowOf("eventd-fresh")).toHaveAttribute("data-alert", "false");
    expect(within(await rowOf("eventd-fresh")).getByText("100")).toBeInTheDocument();
    expect(screen.getByText(ru.system.dbSize.replace("{{size}}", "50"))).toBeInTheDocument();
    expect(within(await rowOf("default")).getByText("3")).toBeInTheDocument();
  });

  it("maps a 403 to a localized message", async () => {
    statusFn = () => err(403, "forbidden");
    wrap(<SystemStatus />);
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.forbidden);
  });
});
