import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { x25519 } from "@noble/curves/ed25519.js";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { canListGroups, canManageDevices } from "@/features/auth/permissions";
import { fingerprint } from "@/lib/keys";
import { toBase64 } from "@/lib/seal";
import { DeviceList } from "./DeviceList";

const err = (status: number, code: string) => HttpResponse.json({ error: { code, message: "RAW SERVER MESSAGE" } }, { status });
const device = (id: number, over: Record<string, unknown> = {}) => ({
  id,
  name: `sw-${String(id).padStart(4, "0")}`,
  address: `10.${id >> 8}.${id & 255}.1`,
  group_id: 1,
  driver: "generic-snmp",
  model: `model-${id}`,
  firmware: "1.0",
  insecure_protocols: false,
  state: "up",
  state_since: null,
  ...over,
});

const kp = x25519.keygen();
let devices: unknown[] = [];
let groupsStatus = 200;
let createFn: () => Response;
const server = setupServer(
  http.get("*/api/devices", () => HttpResponse.json(devices)),
  http.get("*/api/groups", () => (groupsStatus === 200 ? HttpResponse.json([{ id: 1, parent_id: null, name: "Core" }, { id: 2, parent_id: 1, name: "Edge" }]) : err(groupsStatus, "forbidden"))),
  http.post("*/api/devices", () => createFn()),
  http.get("*/keys.json", () => HttpResponse.json({ version: 1, domains: { read: { key_version: 1, public_key: toBase64(kp.publicKey), fingerprint: fingerprint(kp.publicKey) } } })),
);

beforeAll(() => {
  server.listen({ onUnhandledFrame: "error" });
  /* jsdom has no layout: give every element a size so the virtualizer sees a 440px viewport */
  Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, get: () => 440 });
  Object.defineProperty(HTMLElement.prototype, "clientWidth", { configurable: true, get: () => 1100 });
  HTMLElement.prototype.getBoundingClientRect = () => ({ width: 1100, height: 440, top: 0, left: 0, right: 1100, bottom: 440, x: 0, y: 0, toJSON() {} });
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  groupsStatus = 200;
});
afterAll(() => server.close());

function Harness({ canAdd, initial = "", canListGroups = true }: { canAdd: boolean; initial?: string; canListGroups?: boolean }) {
  const [search, setSearch] = useState(initial);
  return <DeviceList canAdd={canAdd} canListGroups={canListGroups} search={search} onSearchChange={setSearch} />;
}

function setup(canAdd: boolean, initial?: string, canListGroups = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <Harness canAdd={canAdd} initial={initial} canListGroups={canListGroups} />
    </QueryClientProvider>,
  );
}

const dataRows = () => screen.getAllByRole("row").filter((r) => within(r).queryAllByRole("cell").length > 0);

describe("DeviceList", () => {
  it("renders only the visible window of 5000 rows and follows scrolling", async () => {
    devices = Array.from({ length: 5000 }, (_, i) => device(i + 1));
    setup(false);
    await screen.findByText("sw-0001");
    const rendered = dataRows().length;
    expect(rendered).toBeGreaterThan(5);
    expect(rendered).toBeLessThan(200);
    expect(screen.queryByText("sw-3000")).not.toBeInTheDocument();
    expect(screen.getByText(ru.devices.count.replace("{{shown}}", "5000").replace("{{total}}", "5000"))).toBeInTheDocument();

    const scroller = screen.getByTestId("device-scroll");
    scroller.scrollTop = 44 * 2999;
    fireEvent.scroll(scroller);
    await screen.findByText("sw-3000");
    expect(screen.queryByText("sw-0001")).not.toBeInTheDocument();
    expect(dataRows().length).toBeLessThan(200);
  });

  it("shows driver, hardware warning, insecure protocol and group name or #id", async () => {
    devices = [device(1, { driver: "eltex-mes", insecure_protocols: true, group_id: 2 }), device(2, { group_id: 99, model: "<b>x</b>" })];
    setup(false);
    expect(await screen.findByText("eltex-mes")).toBeInTheDocument();
    expect(screen.getByText(ru.devices.unverified)).toBeInTheDocument();
    expect(screen.getByText(ru.devices.insecure)).toBeInTheDocument();
    expect(await within(dataRows()[0]).findByText("Edge")).toBeInTheDocument();
    expect(screen.getByText("#99")).toBeInTheDocument();
    /* device-provided strings are text, never markup */
    expect(screen.getByText("<b>x</b>")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
  });

  it("filters by search and by state", async () => {
    devices = [device(1, { name: "alpha" }), device(2, { name: "beta", state: "down" }), device(3, { name: "alphabet", state: "down" })];
    setup(false);
    await screen.findByText("alpha");
    await userEvent.selectOptions(screen.getByLabelText(ru.devices.filter.state), "down");
    await waitFor(() => expect(screen.queryByText("alpha")).not.toBeInTheDocument());
    await userEvent.type(screen.getByLabelText(ru.devices.search), "alph");
    expect(screen.getByText("alphabet")).toBeInTheDocument();
    expect(screen.queryByText("beta")).not.toBeInTheDocument();
  });

  it("does not request groups and hides the group filter without the groups right", async () => {
    let requested = 0;
    server.use(
      http.get("*/api/groups", () => {
        requested++;
        return err(403, "forbidden");
      }),
    );
    devices = [device(1)];
    setup(false, undefined, false);
    await screen.findByText("sw-0001");
    await screen.findByText("#1");
    expect(screen.queryByLabelText(ru.devices.filter.group)).not.toBeInTheDocument();
    expect(requested).toBe(0);
  });

  it("neutralises control and bidi characters in model, firmware and driver", async () => {
    devices = [device(1, { model: "m‮odel", firmware: "fw", driver: "d⁦rv" })];
    setup(false);
    expect(await screen.findByText("m�odel")).toBeInTheDocument();
    expect(screen.getByText("f�w")).toBeInTheDocument();
    expect(screen.getByText("d�rv")).toBeInTheDocument();
  });

  it("offers the add button only to those who may add", async () => {
    devices = [device(1)];
    setup(false);
    await screen.findByText("sw-0001");
    expect(screen.queryByRole("button", { name: ru.devices.add })).not.toBeInTheDocument();
    cleanup();
    setup(true);
    expect(await screen.findByRole("button", { name: ru.devices.add })).toBeInTheDocument();
  });

  it("maps a duplicate address to a clear message and keeps the dialog open", async () => {
    devices = [];
    createFn = () => err(409, "address_exists");
    setup(true);
    await userEvent.click(await screen.findByRole("button", { name: ru.devices.add }));
    await userEvent.type(await screen.findByLabelText(ru.devices.addDialog.name), "core-1");
    await userEvent.type(screen.getByLabelText(ru.devices.addDialog.address), "192.0.2.10");
    await userEvent.click(screen.getByRole("button", { name: ru.devices.addDialog.create }));
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.address_exists);
    expect(screen.queryByText(/RAW SERVER MESSAGE/)).not.toBeInTheDocument();
    expect(screen.getByLabelText(ru.devices.addDialog.name)).toHaveValue("core-1");
  });

  it("rejects an invalid SNMP port before sending", async () => {
    devices = [];
    let posted = 0;
    createFn = () => {
      posted++;
      return HttpResponse.json({ id: 1 }, { status: 201 });
    };
    setup(true);
    await userEvent.click(await screen.findByRole("button", { name: ru.devices.add }));
    await userEvent.type(await screen.findByLabelText(ru.devices.addDialog.name), "core-1");
    await userEvent.type(screen.getByLabelText(ru.devices.addDialog.address), "192.0.2.10");
    const port = screen.getByLabelText(ru.devices.addDialog.port);
    await userEvent.clear(port);
    await userEvent.type(port, "70000");
    await userEvent.click(screen.getByRole("button", { name: ru.devices.addDialog.create }));
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.devices.addDialog.badPort);
    expect(posted).toBe(0);
  });

  it("after creation moves straight to the credential step", async () => {
    devices = [];
    createFn = () => HttpResponse.json({ id: 42 }, { status: 201 });
    setup(true);
    await userEvent.click(await screen.findByRole("button", { name: ru.devices.add }));
    await userEvent.type(await screen.findByLabelText(ru.devices.addDialog.name), "core-1");
    await userEvent.type(screen.getByLabelText(ru.devices.addDialog.address), "192.0.2.10");
    await userEvent.click(screen.getByRole("button", { name: ru.devices.addDialog.create }));
    expect(await screen.findByText(ru.devices.addDialog.credTitle)).toBeInTheDocument();
    expect(screen.getByLabelText(ru.profile.community)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: ru.devices.addDialog.later }));
    await waitFor(() => expect(screen.queryByText(ru.devices.addDialog.credTitle)).not.toBeInTheDocument());
  });
});

describe("canListGroups", () => {
  it("is true only for a global admin binding", () => {
    const s = (role: string, group_id: number | null) => ({ id: 1, username: "u", roles: [{ role, group_id }] });
    expect(canListGroups(s("admin", null))).toBe(true);
    expect(canListGroups(s("admin", 3))).toBe(false);
    for (const r of ["viewer", "operator", "auditor"]) expect(canListGroups(s(r, null))).toBe(false);
    expect(canListGroups(null)).toBe(false);
  });
});

describe("canManageDevices", () => {
  const s = (role: string) => ({ id: 1, username: "u", roles: [{ role, group_id: null }] });
  it("is true for admin only", () => {
    expect(canManageDevices(s("admin"))).toBe(true);
    for (const r of ["viewer", "operator", "auditor"]) expect(canManageDevices(s(r))).toBe(false);
    expect(canManageDevices(null)).toBe(false);
  });
});
