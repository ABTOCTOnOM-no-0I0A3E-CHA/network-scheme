import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { SystemStatus } from "@/features/system/SystemStatus";
import { EventFeed } from "./EventFeed";
import { Unidentified } from "./Unidentified";

const err = (status: number, code: string) => HttpResponse.json({ error: { code, message: "RAW SERVER MESSAGE" } }, { status });
const HOSTILE = "<script>alert(1)</script>\u0007‮evil";

const ev = (i: number, over: Record<string, unknown> = {}) => ({
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
let statusFn: () => Response;

const server = setupServer(
  http.get("*/api/events/unidentified", () => unidentifiedFn()),
  http.get("*/api/events", ({ request }) => {
    const q = new URL(request.url).searchParams;
    eventRequests.push(q);
    return eventsFn(q);
  }),
  http.get("*/api/devices", () => HttpResponse.json([{ id: 1, name: "core-sw", address: "192.0.2.10", group_id: 1, driver: "generic-snmp", model: "", firmware: "", insecure_protocols: false, state: "up", state_since: null }])),
  http.post("*/api/trap-rules", async ({ request }) => {
    ruleBody = await request.json();
    return ruleFn();
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

  it("maps API errors to a localized message", async () => {
    eventsFn = () => err(400, "bad_request");
    wrap(<EventFeed />);
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.bad_request);
    expect(document.body.textContent).not.toContain("RAW SERVER MESSAGE");
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
    let created = false;
    unidentifiedFn = () => HttpResponse.json({ items: created ? [] : [row], next_cursor: null });
    ruleFn = () => {
      created = true;
      return new HttpResponse(null, { status: 201 });
    };
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
    const now = Date.now();
    statusFn = () =>
      HttpResponse.json({
        pollers: [
          { id: "poller-a", devices: 10, devices_reporting: 9 },
          { id: "poller-b", devices: 5, devices_reporting: 0 },
          { id: "poller-idle", devices: 0, devices_reporting: 0 },
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
