import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import { createPoster } from "../client";
import { AuditPage } from "./AuditPage";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const EVIL = "<img src=x onerror=alert(1)>";
const row = (id: number, o: Record<string, unknown> = {}) => ({
  id, ts: "2026-11-10T10:00:00Z", user_id: 3, ip: "192.0.2.7", user_agent: "ua", action: "session.command", object: "session:x",
  result: "ok", details: `{"line":"${EVIL}"}`, ...o,
});

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

describe("AuditPage", () => {
  it("reads a page with the filters and one code, shows it as text only and continues by the cursor", async () => {
    const u = userEvent.setup();
    render(<AuditPage poster={poster()} />);
    await u.type(screen.getByLabelText("Пользователь (id)"), "3");
    await u.type(screen.getByLabelText("Действие (точно или префикс с *)"), "session.*");
    await u.type(screen.getByLabelText("Устройство (id)"), "7");
    await u.selectOptions(screen.getByLabelText("Результат"), "denied");
    await u.type(screen.getByLabelText("Код TOTP изменений"), "111111");
    reply(json(200, { result: { rows: [row(9), row(8, { result: "denied", user_id: null })], next: 8 } }));
    await u.click(screen.getByRole("button", { name: "Показать" }));
    const table = await screen.findByTestId("audit-table");
    expect(urlOf(0)).toBe("/x/audit");
    expect(bodyOf(0)).toEqual({ code: "111111", params: { limit: 50, user_id: 3, action: "session.*", device_id: 7, result: "denied" }, ticket: "ticket-1" });
    expect(table.textContent).toContain(EVIL); /* as text */
    expect(table.querySelector("img")).toBeNull();
    expect(screen.getByTestId("audit-8")).toHaveTextContent("хост");
    expect((screen.getByLabelText("Код TOTP изменений") as HTMLInputElement).value).toBe(""); /* a code is sent once */
    /* the next page: the shown page's filters, the cursor, a new code */
    await u.clear(screen.getByLabelText("Пользователь (id)"));
    await u.type(screen.getByLabelText("Код TOTP изменений"), "222222");
    reply(json(200, { result: { rows: [row(7)], next: 0 } }));
    await u.click(screen.getByRole("button", { name: "Следующая страница" }));
    await screen.findByTestId("audit-7");
    expect(bodyOf(1)).toEqual({ code: "222222", params: { limit: 50, user_id: 3, action: "session.*", device_id: 7, result: "denied", before: 8 }, ticket: "ticket-2" });
    expect(screen.queryByRole("button", { name: "Следующая страница" })).toBeNull();
  });

  it("sends nothing for a malformed filter and names the executor's refusals", async () => {
    const u = userEvent.setup();
    render(<AuditPage poster={poster()} />);
    await u.type(screen.getByLabelText("Действие (точно или префикс с *)"), "drop table;");
    await u.type(screen.getByLabelText("Код TOTP изменений"), "333333");
    await u.click(screen.getByRole("button", { name: "Показать" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Проверьте фильтры");
    expect(fetchMock).not.toHaveBeenCalled();
    await u.clear(screen.getByLabelText("Действие (точно или префикс с *)"));
    reply(json(422, { error: { code: "view_limit" } }));
    await u.click(screen.getByRole("button", { name: "Показать" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Превышен лимит просмотров аудита");
    expect(screen.queryByTestId("audit-table")).toBeNull();
  });
});
