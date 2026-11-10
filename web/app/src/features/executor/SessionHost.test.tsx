// @vitest-environment-options {"url": "https://nms.example.org/"}
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { SessionHostProvider } from "./SessionHost";
import { SessionHistory, SessionTab } from "./SessionTab";

const PANEL = "https://nms.example.org";
const EXECUTOR = "https://nms.example.org:8443";
const SID = "3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c";
const server = setupServer(
  http.get("*/origins.json", () => HttpResponse.json({ panel: PANEL, executor: EXECUTOR })),
  http.get("*/api/devices/7/sessions", () =>
    HttpResponse.json({ items: [{ session_id: SID, user_id: 1, username: "admin", opened_at: "2026-11-10T09:00:00Z", closed_at: "2026-11-10T09:20:00Z", status: "closed", post_sha256: "abcdef012345" }] }),
  ),
);
beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterAll(() => server.close());
afterEach(cleanup);

/* a stand-in for the shell: a "device window" that can be closed and a "route" that can change */
function Shell() {
  const [win, setWin] = useState(true);
  const [route, setRoute] = useState("map");
  return (
    <SessionHostProvider>
      <button type="button" onClick={() => setWin(false)}>close-window</button>
      <button type="button" onClick={() => setRoute("problems")}>navigate</button>
      <p>route:{route}</p>
      {win && <SessionTab deviceId={7} />}
      {win && <SessionHistory deviceId={7} />}
    </SessionHostProvider>
  );
}
const renderShell = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <Shell />
    </QueryClientProvider>,
  );
const fromExecutor = (frame: HTMLIFrameElement, data: unknown) =>
  act(() => void window.dispatchEvent(Object.assign(new Event("message"), { data, origin: EXECUTOR, source: frame.contentWindow })));

describe("the change session dock", () => {
  it("opens the executor for the device and keeps the same frame across navigation, closing the window and collapsing", async () => {
    renderShell();
    expect(screen.queryByTestId("session-dock")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: ru.session.open }));
    const frame = (await screen.findByTitle(ru.executor.dock.title)) as HTMLIFrameElement;
    expect(frame).toHaveAttribute("src", `${EXECUTOR}/#device=7`);
    expect(frame).toHaveAttribute("sandbox", "allow-scripts allow-same-origin");

    fromExecutor(frame, { v: 1, type: "status", state: "session", open: true });
    expect(await screen.findByRole("button", { name: ru.session.show })).toBeInTheDocument();
    const dock = screen.getByTestId("session-dock");
    expect(within(dock).getByRole("button", { name: ru.executor.dock.close })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "navigate" }));
    await userEvent.click(within(dock).getByRole("button", { name: ru.executor.dock.collapse }));
    expect(dock).toHaveClass("h-14");
    await userEvent.click(screen.getByRole("button", { name: "close-window" }));
    expect(screen.getByTitle(ru.executor.dock.title)).toBe(frame);

    /* the compact strip asks to be shown at full size */
    fromExecutor(frame, { v: 1, type: "status", state: "expand" });
    await waitFor(() => expect(dock).toHaveClass("h-[72vh]"));
    expect(screen.getByTitle(ru.executor.dock.title)).toBe(frame);
  });

  it("opens the player of one session in the frame while no session is open, and never reloads an open one", async () => {
    renderShell();
    const row = await screen.findByTestId(`session-${SID}`);
    await userEvent.click(within(row).getByRole("button", { name: ru.journal.replay }));
    const frame = (await screen.findByTitle(ru.executor.dock.title)) as HTMLIFrameElement;
    expect(frame).toHaveAttribute("src", `${EXECUTOR}/#replay=${SID}&device=7`);
    fromExecutor(frame, { v: 1, type: "status", state: "session", open: true });
    await userEvent.click(within(row).getByRole("button", { name: ru.journal.replay }));
    expect(await screen.findByText(ru.journal.replayBusy)).toBeInTheDocument();
    expect(screen.getByTitle(ru.executor.dock.title)).toBe(frame);
    expect(frame).toHaveAttribute("src", `${EXECUTOR}/#replay=${SID}&device=7`);
  });

  it("ignores session statuses from another origin", async () => {
    renderShell();
    await userEvent.click(screen.getByRole("button", { name: ru.session.open }));
    const frame = (await screen.findByTitle(ru.executor.dock.title)) as HTMLIFrameElement;
    act(() => void window.dispatchEvent(Object.assign(new Event("message"), { data: { v: 1, type: "status", state: "session", open: true }, origin: "https://evil.example", source: frame.contentWindow })));
    expect(within(screen.getByTestId("session-dock")).getByRole("button", { name: ru.executor.dock.close })).toBeEnabled();
  });
});
