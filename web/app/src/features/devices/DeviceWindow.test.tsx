import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import type { ReactNode } from "react";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { BackupsTab } from "./BackupsTab";
import { CliTab } from "./CliTab";
import { ConfigTab } from "./ConfigTab";
import { DeviceCard } from "./DeviceCard";
import { ESR_INTERFACES, GENERIC_INTERFACES, MES_INTERFACES } from "./fixtures";
import { frontPanel, PhysicalTab } from "./PhysicalTab";
import type { TableRows } from "./api";

const ESC = String.fromCharCode(27);
const RLO = String.fromCharCode(0x202e);
const FFFD = String.fromCharCode(0xfffd);
const HOSTILE = `<img src=x onerror=alert(1)> ${ESC}[31mred${ESC}[0m ${RLO}evil`;
const seen = "2026-10-02T10:00:00Z";
const version = (id: number, over: Record<string, unknown> = {}) => ({ id, taken_at: `2026-10-0${id}T10:00:00Z`, source: "schedule", size: 120, sha256: "abcdef012345", drift: false, ...over });
const stateBody = (over: Record<string, unknown> = {}) => ({ last_ok_at: seen, last_error: null, needs_write: false, last_sha256: "abcdef012345", latest_version: version(2), ...over });

let ifaces: TableRows["interfaces"][] = [];
let stateFn: () => Response;
let showBody: unknown;
const server = setupServer(
  http.get("*/api/devices/7", () => HttpResponse.json({ id: 7, name: "sw", address: "192.0.2.10", group_id: 1, driver: "eltex-mes", model: "MES2324", firmware: "", insecure_protocols: false, state: "up", state_since: seen, snmp_port: 161, interval_avail_s: null, interval_metrics_s: null, interval_inventory_s: null, parent_id: null, last_error: null })),
  http.get("*/api/devices/7/interfaces", () => HttpResponse.json({ items: ifaces, next_offset: null })),
  http.get("*/api/devices/7/mac", () => HttpResponse.json({ items: [{ mac: "00:11:22:33:44:55", vlan: 10, if_index: 49, seen_at: seen }], next_offset: null })),
  http.get("*/api/devices/7/lldp", () => HttpResponse.json({ items: [], next_offset: null })),
  http.get("*/api/devices/7/metrics/if", () => HttpResponse.json({ step_s: 0, points: [] })),
  http.get("*/api/devices/7/backup-state", () => stateFn()),
  http.get("*/api/devices/7/backups", () => HttpResponse.json({ items: [version(2), version(1, { drift: true })], next_cursor: null })),
  http.get("*/api/devices/7/backups/diff", () => HttpResponse.json({ a: { id: 1, taken_at: seen }, b: { id: 2, taken_at: seen }, diff: `--- a\n+++ b\n@@ -1 +1 @@\n-hostname old\n+${HOSTILE}\n` })),
  http.get("*/api/devices/7/backups/:vid", () => HttpResponse.json({ ...version(2), text: `hostname sw\ninterface gi1/0/1\n description ${HOSTILE}\nexit\nsnmp-server community *** ro\n` })),
  http.get("*/api/devices/7/show-commands", () => HttpResponse.json({ commands: [{ key: "interface_status", args: ["interface"] }, { key: "vlan", args: ["vlan"] }] })),
  http.post("*/api/devices/7/show", async ({ request }) => {
    showBody = await request.json();
    return HttpResponse.json({ id: 5 }, { status: 202 });
  }),
  http.get("*/api/show/5", () => HttpResponse.json({ id: 5, device_id: 7, key: "interface_status", args: {}, status: "done", requested_at: seen, finished_at: seen, output: `Port  Status\n${HOSTILE}\n`, truncated: true })),
  http.get("*/api/events", () => HttpResponse.json({ items: [], next_cursor: null })),
);

beforeAll(() => server.listen());
afterEach(() => {
  cleanup();
  server.resetHandlers();
  showBody = undefined;
});
afterAll(() => server.close());

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

/* hostile device text shows up as literal characters: no element is created and controls are replaced */
function expectInert(el: HTMLElement) {
  expect(el.querySelector("img")).toBeNull();
  expect(document.querySelector("img")).toBeNull();
  expect(el.textContent).toContain("<img src=x onerror=alert(1)>");
  expect(el.textContent).not.toContain(ESC);
  expect(el.textContent).not.toContain(RLO);
  expect(el.textContent).toContain(`${FFFD}[31mred`);
}

describe("Физика", () => {
  it.each([
    ["MES", MES_INTERFACES, 24, 4],
    ["ESR", ESR_INTERFACES, 4, 2],
    ["generic", GENERIC_INTERFACES, 3, 0],
  ])("draws the ports of the %s inventory by kind", async (_name, rows, rj45, sfp) => {
    ifaces = rows;
    const { container } = wrap(<PhysicalTab deviceId={7} onShowChart={() => {}} />);
    await screen.findByText(ru.phys.hoverHint);
    const ports = container.querySelectorAll("[data-port-kind]");
    expect(container.querySelectorAll('[data-port-kind="rj45"]')).toHaveLength(rows.filter((r) => r.port_kind === "rj45").length);
    expect(container.querySelectorAll('[data-port-kind="sfp"]')).toHaveLength(rows.filter((r) => r.port_kind === "sfp").length);
    expect(ports).toHaveLength(rj45 + sfp);
    /* status indicators follow oper_up */
    expect(container.querySelectorAll('[data-oper="up"]')).toHaveLength(rows.filter((r) => r.port_kind !== "other" && r.oper_up).length);
  });

  it("orders ports naturally and leaves logical interfaces off the panel", () => {
    const p = frontPanel([...MES_INTERFACES].reverse());
    expect(p.rj45.map((r) => r.name).slice(0, 3)).toEqual(["gi1/0/1", "gi1/0/2", "gi1/0/3"]);
    expect(p.rj45.at(-1)?.name).toBe("gi1/0/24");
    expect([...p.rj45, ...p.sfp].some((r) => r.port_kind === "other")).toBe(false);
  });

  it("hover shows speed and VLAN, a click opens the port card", async () => {
    ifaces = MES_INTERFACES;
    wrap(<PhysicalTab deviceId={7} onShowChart={() => {}} />);
    const port = await screen.findByRole("button", { name: /^Порт gi1\/0\/1:/ });
    await userEvent.hover(port);
    const hint = screen.getByTestId("port-hint");
    expect(hint).toHaveTextContent(ru.phys.speed);
    expect(hint).toHaveTextContent(ru.chart.unit.gbps);
    /* the MAC fixture puts VLAN 10 on if_index 49 (gi1/0/1); gi1/0/2 has none */
    expect(hint).toHaveTextContent(`${ru.phys.vlan}: 10`);
    await userEvent.hover(screen.getByRole("button", { name: /^Порт gi1\/0\/2:/ }));
    expect(hint).toHaveTextContent(`${ru.phys.vlan}: ${ru.phys.unknown}`);
    await userEvent.click(port);
    expect(await screen.findByRole("region", { name: "Карточка порта gi1/0/1" })).toBeInTheDocument();
  });
});

describe("hostile device text", () => {
  it("config sections render the masked text as text only", async () => {
    stateFn = () => HttpResponse.json(stateBody());
    wrap(<ConfigTab deviceId={7} />);
    await userEvent.click(await screen.findByRole("button", { name: new RegExp(ru.config.section.interfaces) }));
    expectInert(screen.getByTestId("config-lines"));
    /* every line lands in a section: general, interfaces, snmp */
    expect(screen.getAllByRole("treeitem")).toHaveLength(3);
  });

  it("CLI output renders as text only; args are typed from the inventory", async () => {
    ifaces = MES_INTERFACES;
    wrap(<CliTab deviceId={7} />);
    await userEvent.selectOptions(await screen.findByLabelText(ru.cli.command), "interface_status");
    await userEvent.selectOptions(screen.getByLabelText(ru.cli.interface), "gi1/0/2");
    await userEvent.click(screen.getByRole("button", { name: ru.cli.run }));
    const out = await screen.findByTestId("cli-output");
    expect(showBody).toEqual({ key: "interface_status", args: { interface: "gi1/0/2" } });
    expectInert(out);
    expect(screen.getByRole("status")).toHaveTextContent(ru.cli.truncated);
  });

  it("CLI refuses a VLAN outside 1..4094 before sending and shows the 429 message", async () => {
    server.use(http.post("*/api/devices/7/show", () => HttpResponse.json({ error: { code: "rate_limited", message: "RAW" } }, { status: 429 })));
    wrap(<CliTab deviceId={7} />);
    await userEvent.selectOptions(await screen.findByLabelText(ru.cli.command), "vlan");
    await userEvent.type(screen.getByLabelText(ru.cli.vlan), "5000");
    await userEvent.click(screen.getByRole("button", { name: ru.cli.run }));
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.cli.badVlan);
    await userEvent.clear(screen.getByLabelText(ru.cli.vlan));
    await userEvent.type(screen.getByLabelText(ru.cli.vlan), "10");
    await userEvent.click(screen.getByRole("button", { name: ru.cli.run }));
    expect(await screen.findByText(ru.errors.rate_limited)).toBeInTheDocument();
    expect(screen.queryByText("RAW")).toBeNull();
  });

  it("backup diff renders as text only", async () => {
    stateFn = () => HttpResponse.json(stateBody());
    wrap(<BackupsTab deviceId={7} canBackup />);
    await userEvent.click((await screen.findAllByRole("radio", { name: /^Сторона A/ }))[0]);
    await userEvent.click(screen.getAllByRole("radio", { name: /^Сторона B/ })[1]);
    await userEvent.click(screen.getByRole("button", { name: ru.backup.compare }));
    expectInert(await screen.findByTestId("backup-diff"));
  });
});

describe("Бэкапы", () => {
  it("needs_write shows the phase 4 message and offers no manual backup", async () => {
    stateFn = () => HttpResponse.json(stateBody({ needs_write: true, last_ok_at: null, latest_version: null }));
    wrap(<BackupsTab deviceId={7} canBackup />);
    expect(await screen.findByText(ru.backup.needsWrite)).toBeInTheDocument();
    expect(ru.backup.needsWrite.toLowerCase()).toContain("бэкап до фазы 4 недоступен для этой модели");
    expect(screen.queryByRole("button", { name: ru.backup.now })).toBeNull();
    cleanup();
    wrap(<ConfigTab deviceId={7} />);
    expect(await screen.findByText(ru.backup.needsWrite)).toBeInTheDocument();
  });

  it("lists versions with drift and a same-origin masked download link", async () => {
    stateFn = () => HttpResponse.json(stateBody());
    wrap(<BackupsTab deviceId={7} canBackup={false} />);
    const table = await screen.findByRole("table", { name: ru.backup.versions });
    expect(within(table).getAllByText(ru.backup.drift)).toHaveLength(1);
    const links = within(table).getAllByRole("link", { name: ru.backup.download });
    expect(links[0]).toHaveAttribute("href", "/api/devices/7/backups/2/download");
    expect(screen.queryByRole("button", { name: ru.backup.now })).toBeNull();
  });
});

describe("device window tabs", () => {
  it("hides the CLI tab without devices.show", async () => {
    ifaces = [];
    stateFn = () => HttpResponse.json(stateBody());
    wrap(<DeviceCard id={7} canPoll={false} canManage={false} />);
    await screen.findByRole("tab", { name: ru.card.tab.physical });
    expect(screen.queryByRole("tab", { name: ru.card.tab.cli })).toBeNull();
    cleanup();
    wrap(<DeviceCard id={7} canPoll canManage={false} canShow />);
    expect(await screen.findByRole("tab", { name: ru.card.tab.cli })).toBeInTheDocument();
  });

  it("Данные: search filters the page and CSV exports the whole table with formulas neutralized", async () => {
    ifaces = [...GENERIC_INTERFACES, { ...GENERIC_INTERFACES[0], if_index: 9, name: "=HYPERLINK(1)", port_kind: "other" }];
    let href = "";
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      href = this.href;
    });
    wrap(<DeviceCard id={7} canPoll={false} canManage={false} />);
    const table = await screen.findByRole("table", { name: ru.card.tab.interfaces });
    await within(table).findByText("Gi1/0/2");
    await userEvent.type(screen.getByLabelText(ru.data.search), "gi1/0/2");
    expect(within(table).queryByText("Gi1/0/1")).toBeNull();
    expect(within(table).getByText("Gi1/0/2")).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText(ru.data.search));
    await userEvent.selectOptions(screen.getByLabelText(ru.data.filter), ru.card.down);
    expect(within(table).queryByText("Gi1/0/1")).toBeNull();
    await userEvent.selectOptions(screen.getByLabelText(ru.data.filter), ru.data.all);
    await userEvent.click(screen.getByRole("button", { name: ru.data.csv }));
    expect(await screen.findByText(ru.data.exported.replace("{{count}}", "4"))).toBeInTheDocument();
    click.mockRestore();
    expect(href.startsWith("data:text/csv;charset=utf-8,")).toBe(true);
    const csv = decodeURIComponent(href.slice(href.indexOf(",") + 1));
    expect(csv).toContain(`"'=HYPERLINK(1)"`);
    expect(csv.split(String.fromCharCode(13, 10))[0]).toContain(`"if_index","name"`);
  });
});
