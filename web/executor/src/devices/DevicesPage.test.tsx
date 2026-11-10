import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import { createPoster } from "../client";
import { DevicesPage } from "./DevicesPage";

/* jsdom has no IntersectionObserver v2: the visibility gate is driven by the test */
const vis = vi.hoisted(() => ({ unobscured: true }));
vi.mock("../useUnobscured", () => ({ useUnobscured: () => ({ ref: () => {}, unobscured: vis.unobscured, supported: true }) }));

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const H = "cd".repeat(32);
const FP = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const EVIL = "<img src=x onerror=alert(1)>";

const row = (o: Record<string, unknown> = {}) => ({
  device_id: 5, address: "10.9.0.1", port: 22, protocol: "ssh", write_group: "core", write_driver: "mes6", hostkey_algo: "ssh-ed25519", hostkey_fp: FP,
  allow_ssh_rsa_sha1: false, writes_enabled: false, backup_via_executor: false, version: 3, status: "writes_off", ...o,
});
const probed = {
  device: "5", address: "10.9.0.1", port: "22", protocol: "ssh", write_group: "core", write_driver: "mes6", allow_ssh_rsa_sha1: "false",
  backup_via_executor: "false", hostkey_algo: "ssh-ed25519", hostkey_fp: FP, address_source: "panel", panel_name: EVIL, panel_address: "10.9.0.1",
};
const challenge = (action: string, f: Record<string, string>) => ({
  challenge_id: "c1", action, h: H, expires: "2026-11-05T10:00:00Z",
  fields: Object.entries(f).sort().map(([key, value]) => ({ key, value })),
});

let fetchMock: ReturnType<typeof vi.fn>;
let tickets: number;
const touched: string[] = [];
beforeEach(() => {
  vis.unobscured = true;
  tickets = 0;
  touched.length = 0;
  fetchMock = vi.fn(() => Promise.reject(new Error("offline"))); /* keys.json of the embedded credential form */
  vi.stubGlobal("fetch", fetchMock);
  for (const m of ["setItem", "getItem", "removeItem", "key", "clear"] as const) {
    vi.spyOn(Storage.prototype, m).mockImplementation(() => {
      touched.push(m);
      return null;
    });
  }
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const poster = () => createPoster({ requestTicket: () => Promise.resolve(`ticket-${++tickets}`) });
const reply = (...r: Response[]) => r.forEach((x) => fetchMock.mockImplementationOnce(() => Promise.resolve(x)));
const calls = () => (fetchMock.mock.calls as [string, RequestInit][]).filter((c) => c[0] !== "/keys.json");
const bodyOf = (i: number) => JSON.parse(calls()[i][1].body as string) as Record<string, unknown>;
const urlOf = (i: number) => calls()[i][0];
type U = ReturnType<typeof userEvent.setup>;
const codeBox = () => screen.getAllByLabelText("Код TOTP изменений").at(-1) as HTMLInputElement;
const typeCode = async (u: U, c: string) => u.type(codeBox(), c);

async function list(u: U, devices: unknown[]) {
  reply(json(200, { result: devices }));
  await typeCode(u, "111111");
  await u.click(screen.getByRole("button", { name: "Показать список" }));
  await screen.findByTestId("device-5").catch(() => undefined);
}

describe("DevicesPage list", () => {
  it("reads the list with one code and a fresh ticket, shows status, gate and writes, and says each read costs a code", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    await screen.findByText(/расходует один код TOTP изменений/);
    await list(u, [row(), row({ device_id: 6, hostkey_algo: undefined, hostkey_fp: undefined, status: "from_reset_unconfirmed" })]);
    expect(urlOf(0)).toBe("/x/devices");
    expect(bodyOf(0)).toEqual({ code: "111111", params: {}, ticket: "ticket-1" });
    expect(screen.getByTestId("device-5")).toHaveTextContent("Запись выключена");
    expect(screen.getByTestId("device-5")).toHaveTextContent(FP);
    expect(screen.getByTestId("device-6")).toHaveTextContent("Ключ хоста не подтверждён");
    expect(screen.getAllByTestId("gate")[0]).toHaveTextContent("nmsctl executor model-verify");
    expect(codeBox().value).toBe("");
    expect(touched).toEqual([]);
  });

  it("renders device strings as text only", async () => {
    const u = userEvent.setup();
    const { container } = render(<DevicesPage poster={poster()} />);
    await list(u, [row({ write_group: EVIL, write_driver: "<i>x</i>", hostkey_algo: EVIL })]);
    expect(screen.getByTestId("device-5")).toHaveTextContent(EVIL);
    expect(container.querySelector("img")).toBeNull();
    expect(container.innerHTML).not.toContain("<img");
  });

  it("never resends a spent code", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    reply(json(429, { error: { code: "rate_limited" } }));
    await typeCode(u, "111111");
    await u.click(screen.getByRole("button", { name: "Показать список" }));
    await screen.findByTestId("failure");
    await typeCode(u, "111111");
    await u.click(screen.getByRole("button", { name: "Показать список" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Этот код уже использован");
    expect(calls()).toHaveLength(1);
  });

  it("has no form and no autofill-able fields", async () => {
    const u = userEvent.setup();
    const { container } = render(<DevicesPage poster={poster()} />);
    const check = () => {
      expect(container.querySelector("form")).toBeNull();
      for (const el of container.querySelectorAll("input:not([type=checkbox]):not([type=radio]), textarea")) expect(el.getAttribute("autocomplete"), el.id).toBe("off");
    };
    check();
    await u.click(screen.getByRole("button", { name: "Зарегистрировать устройство" }));
    check();
  });
});

describe("register flow", () => {
  async function toConfirm(u: U, issued = challenge("device.register", { ...probed })) {
    await u.click(screen.getByRole("button", { name: "Зарегистрировать устройство" }));
    await u.type(screen.getByLabelText("Устройство"), "5");
    await u.type(screen.getByLabelText("Группа записи"), "core");
    reply(json(200, { result: probed }), json(200, issued));
    await typeCode(u, "222222");
    await u.click(screen.getByRole("button", { name: "Прочитать ключ хоста" }));
    return screen.findByTestId("confirm").catch(() => null);
  }

  it("probes, then shows EVERY field with the fingerprint, the panel flag, H and the out-of-band instruction, and confirms with the next code", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    await toConfirm(u);
    expect(urlOf(0)).toBe("/x/devices/probe");
    expect(bodyOf(0)).toMatchObject({ code: "222222", ticket: "ticket-1", params: { kind: "register", device_id: 5, write_group: "core", write_driver: "mes6" } });
    expect(urlOf(1)).toBe("/x/confirm/issue");
    expect(bodyOf(1)).toMatchObject({ ticket: "ticket-2", action: "device.register", params: { hostkey_algo: "ssh-ed25519", hostkey_fp: FP } });
    const panel = screen.getByTestId("confirm");
    for (const [k, v] of Object.entries(probed)) expect(screen.getByTestId(`field-${k}`), k).toHaveTextContent(v);
    expect(screen.getByTestId("field-address_source")).toHaveTextContent("Адрес взят из панели");
    expect(screen.getByTestId("h")).toHaveTextContent(H);
    expect(screen.getByTestId("oob")).toHaveTextContent("Сравните отпечаток");
    expect(panel.querySelector("img")).toBeNull();
    expect(panel).toHaveTextContent(EVIL);

    reply(json(200, { action: "device.register", result: {} }));
    await typeCode(u, "333333");
    await u.click(screen.getByRole("button", { name: "Подтвердить" }));
    expect(await screen.findByTestId("changed")).toBeInTheDocument();
    expect(urlOf(2)).toBe("/x/confirm");
    expect(bodyOf(2)).toEqual({ challenge_id: "c1", h: H, code: "333333", ticket: "ticket-3" });
    expect(touched).toEqual([]);
  });

  it("refuses a description that differs from what the probe read", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    const other = challenge("device.register", { ...probed, hostkey_fp: "SHA256:otherotherotherotherotherotherotherotherothe" });
    expect(await toConfirm(u, other)).toBeNull();
    expect(screen.getByTestId("failure")).toHaveTextContent("не совпало с прочитанным ключом");
    expect(screen.queryByTestId("confirm")).toBeNull();
  });

  it("refuses to confirm while obscured", async () => {
    vis.unobscured = false;
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    await toConfirm(u);
    await typeCode(u, "333333");
    expect(screen.getByRole("button", { name: "Подтвердить" })).toBeDisabled();
    expect(screen.getByText("Окно перекрыто другим содержимым: подтверждение недоступно.")).toBeInTheDocument();
  });

  it("drops the challenge on a refusal and clears the code", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    await toConfirm(u);
    reply(json(422, { error: { code: "device_refused" } }));
    await typeCode(u, "333333");
    await u.click(screen.getByRole("button", { name: "Подтвердить" }));
    await waitFor(() => expect(screen.queryByTestId("confirm")).toBeNull());
    expect(screen.getByTestId("failure")).toHaveTextContent("Executor отклонил действие");
  });
});

describe("accept and writes", () => {
  it("accepts a changed key: pinned fingerprint and status are shown beside the new one", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    await list(u, [row({ status: "writes_on", writes_enabled: true })]);
    await u.click(screen.getByRole("button", { name: "Принять ключ хоста" }));
    const f = { ...probed, address_source: "registry", hostkey_fp: "SHA256:newnewnewnewnewnewnewnewnewnewnewnewnewnewne", pinned_fp: FP, status: "writes_on", version: "3" };
    reply(json(200, { result: f }), json(200, challenge("device.accept_hostkey", f)));
    await typeCode(u, "222222");
    await u.click(screen.getByRole("button", { name: "Прочитать ключ хоста" }));
    await screen.findByTestId("confirm");
    expect(bodyOf(1)).toMatchObject({ params: { kind: "accept_hostkey", device_id: 5 } });
    expect(screen.getByTestId("field-pinned_fp")).toHaveTextContent(FP);
    expect(screen.getByTestId("field-status")).toHaveTextContent("writes_on");
    expect(screen.getByTestId("field-hostkey_fp")).toHaveTextContent("SHA256:newnew");
    expect(screen.getByTestId("field-address_source")).not.toHaveTextContent("из панели");
  });

  it("turns writes on through a confirmation of the device as the registry has it", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    await list(u, [row()]);
    const f = { ...probed, writes_enabled: "true", version: "3" };
    reply(json(200, challenge("device.writes", f)));
    await u.click(screen.getByRole("button", { name: "Включить запись" }));
    await screen.findByTestId("confirm");
    expect(bodyOf(1)).toMatchObject({ action: "device.writes", params: { device_id: 5, enabled: true }, ticket: "ticket-2" });
    expect(screen.getByTestId("field-writes_enabled")).toHaveTextContent("true");
    reply(json(200, { action: "device.writes", result: {} }));
    await typeCode(u, "444444");
    await u.click(screen.getByRole("button", { name: "Подтвердить" }));
    expect(await screen.findByTestId("changed")).toBeInTheDocument();
  });

  it("cannot enable writes on an unconfirmed device, can disable", async () => {
    const u = userEvent.setup();
    render(<DevicesPage poster={poster()} />);
    await list(u, [row({ hostkey_fp: undefined, hostkey_algo: undefined, status: "from_reset_unconfirmed" })]);
    expect(screen.getByRole("button", { name: "Включить запись" })).toBeDisabled();
  });
});
