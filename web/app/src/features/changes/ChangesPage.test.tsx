// @vitest-environment-options {"url": "https://nms.example.org/"}
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { BackupsTab } from "@/features/devices/BackupsTab";
import { SessionHostProvider } from "@/features/executor/SessionHost";
import { ChangesPage } from "./ChangesPage";

const PANEL = "https://nms.example.org";
const EXECUTOR = "https://nms.example.org:8443";
const ID = "7d1e5c3a-2b4f-4a6e-8c9d-0e1f2a3b4c5d";
const HOSTILE = "<img src=x onerror=alert(1)>‮evil";
const row = (over: Record<string, unknown> = {}) => ({
  changeset_id: ID, author_id: 7, author: "alice", kind: "lines", title: HOSTILE, status: "rolled_back", device_count: 6,
  created_at: "2026-11-11T09:00:00Z", updated_at: "2026-11-11T10:00:00Z", failed_device_id: 21, ...over,
});
const server = setupServer(
  http.get("*/origins.json", () => HttpResponse.json({ panel: PANEL, executor: EXECUTOR })),
  http.get("*/api/executor/changesets", () => HttpResponse.json({ items: [row(), row({ changeset_id: "1a2b3c4d-0000-4000-8000-000000000002", author: null, status: "done", failed_device_id: null, title: "ntp" })] })),
  http.get("*/api/devices/7/backup-state", () => HttpResponse.json({ last_ok_at: null, last_error: null, needs_write: false, last_sha256: null, latest_version: null })),
  http.get("*/api/devices/7/backups", () => HttpResponse.json({ items: [{ id: 345, taken_at: "2026-11-10T10:00:00Z", source: "pre_session", size: 120, sha256: "abcdef012345", drift: false }], next_cursor: null })),
);
beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterAll(() => server.close());
afterEach(cleanup);

const wrap = (ui: ReactNode) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SessionHostProvider>{ui}</SessionHostProvider>
    </QueryClientProvider>,
  );
const frame = async () => (await screen.findByTitle(ru.executor.dock.title)) as HTMLIFrameElement;

describe("«Изменения»", () => {
  it("lists the changesets' metadata as text and opens one in the executor's dock", async () => {
    wrap(<ChangesPage />);
    const tr = await screen.findByTestId(`change-${ID}`);
    expect(tr).toHaveTextContent("<img src=x onerror=alert(1)>");
    expect(tr).not.toHaveTextContent("‮");
    expect(document.querySelector("img")).toBeNull();
    expect(tr).toHaveTextContent(ru.changes.status.rolled_back);
    expect(tr).toHaveTextContent("остановлен на устройстве 21");
    expect(screen.getByTestId("change-1a2b3c4d-0000-4000-8000-000000000002")).toHaveTextContent("пользователь 7 (удалён)");
    await userEvent.click(screen.getAllByRole("button", { name: /Открыть changeset/ })[0]);
    expect(await frame()).toHaveAttribute("src", `${EXECUTOR}/#changeset=${ID}`);
  });

  it("«Создать» opens the executor's section, never while a session is open", async () => {
    wrap(<ChangesPage />);
    await userEvent.click(await screen.findByTestId("changes-create"));
    const f = await frame();
    expect(f).toHaveAttribute("src", `${EXECUTOR}/#view=changesets`);
    act(() => void window.dispatchEvent(Object.assign(new Event("message"), { data: { v: 1, type: "status", state: "session", open: true }, origin: EXECUTOR, source: f.contentWindow })));
    await userEvent.click(screen.getAllByRole("button", { name: /Открыть changeset/ })[0]);
    expect(await screen.findByText(ru.changes.sessionOpen)).toBeInTheDocument();
    expect(await frame()).toHaveAttribute("src", `${EXECUTOR}/#view=changesets`);
  });
});

describe("«Бэкапы» → «Восстановить»", () => {
  it("opens a restore changeset of that version in the executor", async () => {
    wrap(<BackupsTab deviceId={7} canBackup />);
    await userEvent.click(await screen.findByRole("button", { name: /Восстановить версию от/ }));
    expect(await frame()).toHaveAttribute("src", `${EXECUTOR}/#restore=7:345`);
  });
});
