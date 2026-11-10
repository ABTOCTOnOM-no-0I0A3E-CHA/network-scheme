import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import { createPoster } from "../client";
import { MAX_SHOWN, RecordingsPage } from "./RecordingsPage";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const SID = "0a1b2c3d-0000-4000-8000-00000000abcd";
const EVIL = "<img src=x onerror=alert(1)>";

let fetchMock: ReturnType<typeof vi.fn>;
let tickets: number;
beforeEach(() => {
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
const bodyOf = (i: number) => JSON.parse((fetchMock.mock.calls[i] as [string, RequestInit])[1].body as string) as Record<string, unknown>;
const urlOf = (i: number) => (fetchMock.mock.calls[i] as [string, RequestInit])[0];
const item = { session_id: SID, device_id: 5, user_id: 3, opened_at: "2026-11-10T10:00:00Z", state: "complete" };
const events = [
  { t: 0, code: "m", data: "session opened by op" },
  { t: 1, code: "i", data: "show running-config\n" },
  { t: 1.5, code: "o", data: `hostname ${EVIL}\nusername admin ***\n` },
  { t: 2, code: "m", data: "session ended: closed" },
];

async function listed(u: ReturnType<typeof userEvent.setup>) {
  render(<RecordingsPage poster={poster()} />);
  await u.type(screen.getByLabelText("Устройство (id)"), "5");
  await u.type(screen.getByLabelText("Код TOTP изменений"), "111111");
  reply(json(200, { result: [item] }));
  await u.click(screen.getByRole("button", { name: "Показать записи" }));
  await screen.findByTestId(`recording-${SID}`);
}

describe("RecordingsPage", () => {
  it("lists with one code, replays with the next one, and shows the recording as text only", async () => {
    const u = userEvent.setup();
    await listed(u);
    expect(urlOf(0)).toBe("/x/recordings");
    expect(bodyOf(0)).toEqual({ code: "111111", params: { device_id: 5 }, ticket: "ticket-1" });
    reply(json(200, { result: { session_id: SID, device_id: 5, timestamp: 1, title: "change session", events } }));
    await u.type(screen.getByLabelText("Код TOTP изменений"), "222222");
    await u.click(screen.getByRole("button", { name: "Воспроизвести" }));
    await screen.findByTestId("player");
    expect(urlOf(1)).toBe("/x/recordings/replay");
    expect(bodyOf(1)).toEqual({ code: "222222", params: { session_id: SID, device_id: 5 }, ticket: "ticket-2" });
    await u.click(screen.getByRole("button", { name: "Показать всё" }));
    const term = screen.getByTestId("terminal");
    await waitFor(() => expect(term.textContent).toContain("session ended: closed"));
    expect(term.textContent).toContain("> show running-config");
    expect(term.textContent).toContain(EVIL); /* as text */
    expect(term.querySelector("img")).toBeNull();
    expect((screen.getByLabelText("Код TOTP изменений") as HTMLInputElement).value).toBe(""); /* a code is sent once */
  });

  it("names the executor's refusal of a tampered recording and shows nothing of it", async () => {
    const u = userEvent.setup();
    await listed(u);
    reply(json(422, { error: { code: "recording_tampered" } }));
    await u.type(screen.getByLabelText("Код TOTP изменений"), "333333");
    await u.click(screen.getByRole("button", { name: "Воспроизвести" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("не прошла проверку целостности");
    expect(screen.queryByTestId("player")).toBeNull();
  });

  it("shows at most the last MAX_SHOWN characters of a large recording, with a notice", async () => {
    const u = userEvent.setup();
    await listed(u);
    const big = "y".repeat(MAX_SHOWN - 10) + "\n";
    const many = [{ t: 0, code: "o", data: big }, { t: 0.1, code: "o", data: "z".repeat(1000) + "\n" }, { t: 0.2, code: "m", data: "session ended: closed" }];
    reply(json(200, { result: { session_id: SID, device_id: 5, timestamp: 1, title: "t", events: many } }));
    await u.type(screen.getByLabelText("Код TOTP изменений"), "555555");
    await u.click(screen.getByRole("button", { name: "Воспроизвести" }));
    await screen.findByTestId("player");
    await u.click(screen.getByRole("button", { name: "Показать всё" }));
    const term = screen.getByTestId("terminal");
    await waitFor(() => expect(term.textContent).toContain("session ended: closed"));
    expect(term.textContent!.length).toBeLessThanOrEqual(MAX_SHOWN);
    expect(screen.getByTestId("cut")).toHaveTextContent("Показан только конец записи");
  });

  it("names a busy executor's refusal of a replay", async () => {
    const u = userEvent.setup();
    await listed(u);
    reply(json(503, { error: { code: "replays_busy" } }));
    await u.type(screen.getByLabelText("Код TOTP изменений"), "666666");
    await u.click(screen.getByRole("button", { name: "Воспроизвести" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("слишком много записей");
  });

  it("refuses a malformed answer instead of rendering it", async () => {
    const u = userEvent.setup();
    await listed(u);
    reply(json(200, { result: { session_id: SID, device_id: 5, timestamp: 1, title: "x", events: [{ t: 0, code: "x", data: "?" }] } }));
    await u.type(screen.getByLabelText("Код TOTP изменений"), "444444");
    await u.click(screen.getByRole("button", { name: "Воспроизвести" }));
    await screen.findByTestId("failure");
    expect(screen.queryByTestId("player")).toBeNull();
  });
});
