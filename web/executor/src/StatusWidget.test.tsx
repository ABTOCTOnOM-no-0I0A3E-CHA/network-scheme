import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "./i18n";
import { StatusWidget } from "./StatusWidget";

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("StatusWidget", () => {
  it("shows enabled and frozen state as text, nothing about grants", async () => {
    fetchMock.mockResolvedValue(json(200, { enabled: true, frozen: false }));
    render(<StatusWidget />);
    expect(await screen.findByTestId("enabled")).toHaveTextContent("Включён");
    expect(screen.getByTestId("frozen")).toHaveTextContent("Не заморожен");
    expect(screen.queryByTestId("failure")).toBeNull();
  });

  it("shows disabled and frozen", async () => {
    fetchMock.mockResolvedValue(json(200, { enabled: false, frozen: true }));
    render(<StatusWidget />);
    expect(await screen.findByTestId("enabled")).toHaveTextContent("Выключен политикой хоста");
    expect(screen.getByTestId("frozen")).toHaveTextContent("Заморожен");
  });

  it("when /x/status cannot be reached and nothing is known: unknown and 'not reachable'", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    render(<StatusWidget />);
    expect(await screen.findByText("Состояние неизвестно")).toBeInTheDocument();
    expect(screen.getByTestId("failure")).toHaveTextContent("Executor недоступен.");
    expect(screen.queryByTestId("enabled")).toBeNull();
  });

  it.each([
    [423, { error: { code: "locked", permanent: true } }, {}, "Вход заблокирован."],
    [429, { error: { code: "rate_limited" } }, { "Retry-After": "12" }, "Повторите через 12 с."],
    [503, { error: { code: "executor_disabled" } }, {}, "выключен политикой хоста"],
    [503, { error: { code: "frozen" } }, {}, "заморожен"],
    [503, { error: { code: "unavailable" } }, {}, "следующего кода TOTP"],
  ])("maps %i to its own text", async (status, body, headers, text) => {
    fetchMock.mockResolvedValue(json(status, body, headers));
    render(<StatusWidget />);
    expect(await screen.findByTestId("failure")).toHaveTextContent(text);
  });

  it("keeps the last good answer, marked stale, when a refresh fails", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { enabled: true, frozen: false }));
    render(<StatusWidget />);
    await screen.findByTestId("enabled");
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await userEvent.click(screen.getByRole("button", { name: "Обновить" }));
    expect(await screen.findByTestId("stale")).toHaveTextContent("Данные устарели");
    expect(screen.getByTestId("enabled")).toHaveTextContent("Включён");
    expect(screen.getByTestId("failure")).toHaveTextContent("Executor недоступен.");
    fetchMock.mockResolvedValueOnce(json(200, { enabled: true, frozen: true }));
    await userEvent.click(screen.getByRole("button", { name: "Обновить" }));
    await waitFor(() => expect(screen.queryByTestId("stale")).toBeNull());
    expect(screen.getByTestId("frozen")).toHaveTextContent("Заморожен");
  });

  it("every request is cookie-less", async () => {
    fetchMock.mockResolvedValue(json(200, { enabled: true, frozen: false }));
    render(<StatusWidget />);
    await screen.findByTestId("enabled");
    for (const c of fetchMock.mock.calls) expect((c[1] as RequestInit).credentials).toBe("omit");
  });
});
