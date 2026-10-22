import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { x25519 } from "@noble/curves/ed25519.js";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { fingerprint } from "@/lib/keys";
import { toBase64 } from "@/lib/seal";
import { safeText } from "@/lib/text";
import { DeviceCard } from "./DeviceCard";

const err = (status: number, code: string) => HttpResponse.json({ error: { code, message: "RAW SERVER MESSAGE" } }, { status });
const detail = (over: Record<string, unknown> = {}) => ({
  id: 7,
  name: "core-sw",
  address: "192.0.2.10",
  group_id: 1,
  driver: "eltex-mes",
  model: "MES2324",
  firmware: "4.0.1",
  insecure_protocols: false,
  state: "up",
  state_since: "2026-10-01T10:00:00Z",
  snmp_port: 161,
  interval_avail_s: null,
  interval_metrics_s: 60,
  interval_inventory_s: null,
  ...over,
});

const LONG = "A".repeat(1024);
const HOSTILE = "<script>alert(1)</script>\u0007‮evil";
const kp = x25519.keygen();
let deviceFn: () => Response;
let polled = 0;
let patched: unknown;
let metricsQuery: Record<string, string | null> | undefined;
const seen = "2026-10-02T10:00:00Z";
const server = setupServer(
  http.get("*/api/devices/7", () => deviceFn()),
  http.get("*/api/devices/7/interfaces", ({ request }) => {
    const offset = Number(new URL(request.url).searchParams.get("offset") ?? 0);
    if (offset === 0) {
      return HttpResponse.json({
        items: [
          { if_index: 1, name: HOSTILE, alias: LONG, speed_bps: 1000000000, oper_up: true, seen_at: seen },
          { if_index: 2, name: "ge0/2", alias: "", speed_bps: 0, oper_up: false, seen_at: seen },
        ],
        next_offset: 50,
      });
    }
    return HttpResponse.json({ items: [{ if_index: 99, name: "page-two", alias: "", speed_bps: 10, oper_up: true, seen_at: seen }], next_offset: null });
  }),
  http.get("*/api/devices/7/lldp", () =>
    HttpResponse.json({ items: [{ local_if_index: 1, chassis_id: "aa:bb", port_id: "\u0001p", sys_name: "<img src=x onerror=alert(1)>", mgmt_addr: null, seen_at: seen }], next_offset: null }),
  ),
  http.get("*/api/devices/7/metrics/if", ({ request }) => {
    const q = new URL(request.url).searchParams;
    metricsQuery = { if_index: q.get("if_index"), step: q.get("step") };
    return HttpResponse.json({ step_s: 10, points: [] });
  }),
  http.get("*/api/devices/7/profiles", () => HttpResponse.json([{ kind: "snmp3", status: "weak", updated_at: seen }])),
  http.get("*/api/groups", () => err(403, "forbidden")),
  http.post("*/api/devices/7/poll", () => {
    polled++;
    return new HttpResponse(null, { status: 202 });
  }),
  http.patch("*/api/devices/7", async ({ request }) => {
    patched = await request.json();
    return err(400, "bad_request");
  }),
  http.get("*/keys.json", () => HttpResponse.json({ version: 1, domains: { read: { key_version: 1, public_key: toBase64(kp.publicKey), fingerprint: fingerprint(kp.publicKey) } } })),
);

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  polled = 0;
  patched = undefined;
  metricsQuery = undefined;
});
afterAll(() => server.close());

function setup(canPoll: boolean, canManage = false) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DeviceCard id={7} canPoll={canPoll} canManage={canManage} />
    </QueryClientProvider>,
  );
}

describe("DeviceCard", () => {
  it("starts fresh when the device id changes: closed edit form, no values of the previous device", async () => {
    deviceFn = () => HttpResponse.json(detail());
    let patched8 = 0;
    server.use(
      http.get("*/api/devices/8", () => HttpResponse.json(detail({ id: 8, name: "edge-sw", address: "192.0.2.20" }))),
      http.get("*/api/devices/8/interfaces", () => HttpResponse.json({ items: [], next_offset: null })),
      http.get("*/api/groups", () => HttpResponse.json([{ id: 1, parent_id: null, name: "Core" }])),
      http.patch("*/api/devices/8", () => {
        patched8++;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const ui = (id: number) => (
      <QueryClientProvider client={qc}>
        <DeviceCard id={id} canPoll canManage />
      </QueryClientProvider>
    );
    const { rerender } = render(ui(7));
    await userEvent.click(await screen.findByRole("button", { name: ru.card.edit.open }));
    expect(within(screen.getByRole("form", { name: ru.card.edit.title })).getByLabelText(ru.devices.addDialog.address)).toHaveValue("192.0.2.10");
    await userEvent.click(screen.getByRole("tab", { name: ru.card.tab.lldp }));

    rerender(ui(8));
    expect(await screen.findByRole("heading", { name: "edge-sw" })).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: ru.card.edit.title })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: ru.card.tab.interfaces })).toHaveAttribute("aria-selected", "true");
    /* opening the form again shows the new device's values; saving unchanged values sends nothing */
    await userEvent.click(screen.getByRole("button", { name: ru.card.edit.open }));
    const form = screen.getByRole("form", { name: ru.card.edit.title });
    expect(within(form).getByLabelText(ru.devices.addDialog.address)).toHaveValue("192.0.2.20");
    await userEvent.click(within(form).getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(screen.queryByRole("form", { name: ru.card.edit.title })).not.toBeInTheDocument());
    expect(patched8).toBe(0);
    expect(patched).toBeUndefined();
  });

  it("shows the header facts", async () => {
    deviceFn = () => HttpResponse.json(detail());
    setup(false);
    expect(await screen.findByRole("heading", { name: "core-sw" })).toBeInTheDocument();
    expect(screen.getByText("MES2324")).toBeInTheDocument();
    expect(screen.getByText("4.0.1")).toBeInTheDocument();
    expect(screen.getByText("eltex-mes")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.10:161")).toBeInTheDocument();
    expect(screen.getByText("#1")).toBeInTheDocument();
    expect(screen.getByText(ru.state.up)).toBeInTheDocument();
  });

  it("404 shows not found, without retries or data", async () => {
    let calls = 0;
    deviceFn = () => {
      calls++;
      return err(404, "not_found");
    };
    setup(true, true);
    expect(await screen.findByText(ru.card.notFound)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: ru.card.pollNow })).not.toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 100));
    expect(calls).toBe(1);
  });

  it("renders hostile device strings as text and keeps long ones wrappable", async () => {
    deviceFn = () => HttpResponse.json(detail({ model: LONG, firmware: HOSTILE, name: HOSTILE }));
    setup(false);
    const safe = safeText(HOSTILE);
    expect(safe).toBe("<script>alert(1)</script>��evil");
    expect(await screen.findByRole("heading", { name: safe })).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getByText(LONG, { selector: "dd" })).toHaveClass("break-words");

    /* inventory cells */
    expect((await screen.findAllByText(safe, { selector: "td span" })).length).toBe(1);
    const alias = screen.getByText(LONG, { selector: "td span" });
    expect(alias).toHaveClass("break-words");
    expect(alias).toHaveAttribute("title", LONG);
    await userEvent.click(screen.getByRole("tab", { name: ru.card.tab.lldp }));
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("�p")).toBeInTheDocument();
  });

  it("the chart button of an interface opens the graphs tab for it", async () => {
    deviceFn = () => HttpResponse.json(detail());
    setup(false);
    await userEvent.click(await screen.findByRole("button", { name: ru.card.chartBtn.replace("{{name}}", "ge0/2") }));
    expect(screen.getByRole("tab", { name: ru.card.tab.graphs })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText(ru.chart.empty)).toBeInTheDocument();
    expect(metricsQuery).toMatchObject({ if_index: "2" });
    expect(Number(metricsQuery?.step)).toBeGreaterThanOrEqual(10);
  });

  it("operator sees poll-now and queues a poll, viewer does not", async () => {
    deviceFn = () => HttpResponse.json(detail());
    setup(true);
    await userEvent.click(await screen.findByRole("button", { name: ru.card.pollNow }));
    expect(await screen.findByText(ru.card.pollQueued)).toBeInTheDocument();
    expect(polled).toBe(1);
    cleanup();
    setup(false);
    await screen.findByRole("heading", { name: "core-sw" });
    expect(screen.queryByRole("button", { name: ru.card.pollNow })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: ru.card.edit.open })).not.toBeInTheDocument();
  });

  it("pages with next_offset", async () => {
    deviceFn = () => HttpResponse.json(detail());
    setup(false);
    await screen.findByText("ge0/2");
    expect(screen.getByRole("button", { name: ru.card.prev })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: ru.card.next }));
    expect(await screen.findByText("page-two")).toBeInTheDocument();
    expect(screen.queryByText("ge0/2")).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: ru.card.next })).toBeDisabled());
    await userEvent.click(screen.getByRole("button", { name: ru.card.prev }));
    expect(await screen.findByText("ge0/2")).toBeInTheDocument();
  });

  it("profiles tab shows status and date for a viewer, never content", async () => {
    deviceFn = () => HttpResponse.json(detail());
    setup(false, false);
    await userEvent.click(await screen.findByRole("tab", { name: ru.card.tab.profiles }));
    expect(await screen.findByText(new RegExp(ru.profile.status.weak))).toBeInTheDocument();
    expect(screen.getAllByText(new RegExp(ru.profile.status.none))).toHaveLength(2);
    expect(document.querySelector("input")).toBeNull();
  });

  it("manager gets the credential forms and the charts slot tab", async () => {
    deviceFn = () => HttpResponse.json(detail());
    setup(false, true);
    await userEvent.click(await screen.findByRole("tab", { name: ru.card.tab.profiles }));
    expect(await screen.findAllByRole("button", { name: ru.profile.save })).toHaveLength(3);
    expect(screen.getByRole("tab", { name: ru.card.tab.graphs })).toBeInTheDocument();
  });

  it("edit validates interval minimums before calling the API and maps server errors", async () => {
    deviceFn = () => HttpResponse.json(detail());
    setup(false, true);
    await userEvent.click(await screen.findByRole("button", { name: ru.card.edit.open }));
    const form = screen.getByRole("form", { name: ru.card.edit.title });
    const avail = within(form).getByLabelText(ru.card.edit.intervalAvail);
    await userEvent.type(avail, "9");
    await userEvent.click(within(form).getByRole("button", { name: ru.profile.save }));
    expect(await within(form).findByRole("alert")).toHaveTextContent("от 10 до 86400");
    expect(patched).toBeUndefined();

    await userEvent.clear(avail);
    await userEvent.type(avail, "30");
    await userEvent.click(within(form).getByRole("button", { name: ru.profile.save }));
    expect(await within(form).findByText(ru.errors.bad_request)).toBeInTheDocument();
    expect(patched).toEqual({ interval_avail_s: 30 });
    expect(screen.queryByText("RAW SERVER MESSAGE")).not.toBeInTheDocument();

    const inv = within(form).getByLabelText(ru.card.edit.intervalInventory);
    await userEvent.type(inv, "59");
    await userEvent.click(within(form).getByRole("button", { name: ru.profile.save }));
    expect(await within(form).findByRole("alert")).toHaveTextContent("от 60 до 86400");
  });
});
