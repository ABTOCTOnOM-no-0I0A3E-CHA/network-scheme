import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import { createPoster } from "../client";
import { ConfigsPage } from "./ConfigsPage";

/* jsdom has no IntersectionObserver v2: the visibility gate is driven by the test */
const vis = vi.hoisted(() => ({ unobscured: true }));
vi.mock("../useUnobscured", () => ({ useUnobscured: () => ({ ref: () => {}, unobscured: vis.unobscured, supported: true }) }));

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const H = "ab".repeat(32);
const SUM = "cd".repeat(32);
const EVIL = "<img src=x onerror=alert(1)>";
const version = { version_id: 42, device_id: 7, taken_at: "2026-11-10T10:00:00Z", source: "schedule", sha256: SUM, size: 120 };
const challenge = (action: string, versionId = 42) => ({
  challenge_id: "c1", action, h: H, expires: "2026-11-10T10:02:00Z",
  fields: [
    { key: "device_id", value: "7" }, { key: "sha256", value: SUM }, { key: "size", value: "120" },
    { key: "taken_at", value: "2026-11-10T10:00:00Z" }, { key: "version_id", value: String(versionId) }, { key: "write_group", value: "core" },
  ],
});

let fetchMock: ReturnType<typeof vi.fn>;
let tickets: number;
beforeEach(() => {
  vis.unobscured = true;
  tickets = 0;
  fetchMock = vi.fn(() => Promise.reject(new Error("offline")));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const poster = () => createPoster({ requestTicket: () => Promise.resolve(`ticket-${++tickets}`) });
const reply = (...r: Response[]) => r.forEach((x) => fetchMock.mockImplementationOnce(() => Promise.resolve(x)));
const call = (i: number) => fetchMock.mock.calls[i] as [string, RequestInit];
const bodyOf = (i: number) => JSON.parse(call(i)[1].body as string) as Record<string, unknown>;
type U = ReturnType<typeof userEvent.setup>;
const codeBox = () => screen.getAllByLabelText("Код TOTP изменений").at(-1) as HTMLInputElement;

async function listed(u: U, save = vi.fn()) {
  render(<ConfigsPage poster={poster()} save={save} />);
  await u.type(screen.getByLabelText("Устройство (id)"), "7");
  await u.type(codeBox(), "111111");
  reply(json(200, { result: [version] }));
  await u.click(screen.getByRole("button", { name: "Показать версии" }));
  await screen.findByTestId("version-42");
  return save;
}

describe("ConfigsPage", () => {
  it("lists with one code, confirms the view with the next one and shows the configuration as text only", async () => {
    const u = userEvent.setup();
    await listed(u);
    expect(call(0)[0]).toBe("/x/configs");
    expect(bodyOf(0)).toEqual({ code: "111111", params: { device_id: 7 }, ticket: "ticket-1" });
    reply(json(200, challenge("config.view")));
    await u.click(screen.getByRole("button", { name: "Показать" }));
    expect(bodyOf(1)).toEqual({ action: "config.view", params: { device_id: 7, version_id: 42 }, ticket: "ticket-2" });
    /* every field of the description and H, gated */
    for (const k of ["device_id", "sha256", "size", "taken_at", "version_id", "write_group"]) expect(screen.getByTestId(`field-${k}`)).toBeInTheDocument();
    expect(screen.getByTestId("h")).toHaveTextContent(H);
    vis.unobscured = false;
    await u.type(codeBox(), "222222");
    expect(screen.getByRole("button", { name: "Подтвердить" })).toBeDisabled();
    vis.unobscured = true;
    await u.clear(codeBox());
    await u.type(codeBox(), "222222");
    reply(json(200, { result: { device_id: 7, version_id: 42, sha256: SUM, taken_at: "2026-11-10T10:00:00Z", text: `hostname ${EVIL}\nend\n` } }));
    await u.click(screen.getByRole("button", { name: "Подтвердить" }));
    const shown = await screen.findByTestId("config-text");
    expect(call(2)[0]).toBe("/x/configs/7/42");
    expect(bodyOf(2)).toEqual({ challenge_id: "c1", h: H, code: "222222", ticket: "ticket-3" });
    expect(shown.textContent).toContain(EVIL); /* as text */
    expect(shown.querySelector("img")).toBeNull();
  });

  it("exports through a fetch with the code in the body and saves the executor's text", async () => {
    const u = userEvent.setup();
    const save = await listed(u);
    reply(json(200, challenge("config.export")));
    await u.click(screen.getByRole("button", { name: "Выгрузить" }));
    await u.type(codeBox(), "333333");
    reply(new Response("hostname sw1\n", { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } }));
    await u.click(screen.getByRole("button", { name: "Подтвердить" }));
    await screen.findByTestId("saved");
    const [url, init] = call(2);
    expect(url).toBe("/x/download/configs/7/42");
    expect(init.credentials).toBe("omit");
    expect(bodyOf(2)).toEqual({ challenge_id: "c1", h: H, code: "333333", ticket: "ticket-3" });
    expect(save).toHaveBeenCalledWith("config-7-42.txt", "hostname sw1\n");
    expect(screen.queryByTestId("config-text")).toBeNull();
  });

  it("refuses a challenge for another version and names the executor's refusals", async () => {
    const u = userEvent.setup();
    await listed(u);
    reply(json(200, challenge("config.view", 43)));
    await u.click(screen.getByRole("button", { name: "Показать" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("другое действие, устройство или версию");
    expect(screen.queryByTestId("h")).toBeNull();
    reply(json(200, challenge("config.view")));
    await u.click(screen.getByRole("button", { name: "Показать" }));
    await u.type(codeBox(), "444444");
    reply(json(422, { error: { code: "config_tampered" } }));
    await u.click(screen.getByRole("button", { name: "Подтвердить" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("не прошла проверку хеша");
    expect(screen.queryByTestId("config-text")).toBeNull();
  });
});
