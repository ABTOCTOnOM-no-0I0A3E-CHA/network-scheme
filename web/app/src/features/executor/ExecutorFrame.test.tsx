// @vitest-environment-options {"url": "https://nms.example.org/"}
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { delay, http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import { ExecutorFrame } from "./ExecutorFrame";

const PANEL = "https://nms.example.org";
const EXECUTOR = "https://nms.example.org:8443";
const ID = "0123456789abcdef0123456789abcdef";

let origins: Record<string, string> = { panel: PANEL, executor: EXECUTOR };
let tickets = 0;
let slow = false;
const server = setupServer(
  http.get("*/origins.json", () => HttpResponse.json(origins)),
  http.post("*/api/executor/ticket", async () => {
    tickets++;
    await delay(slow ? 150 : 0);
    return HttpResponse.json({ ticket: "payload.signature", expires_at: "2026-10-26T10:00:00Z" });
  }),
);
beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterAll(() => server.close());
afterEach(() => {
  cleanup();
  origins = { panel: PANEL, executor: EXECUTOR };
  tickets = 0;
  slow = false;
});

const renderFrame = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ExecutorFrame title="Executor" />
    </QueryClientProvider>,
  );

const say = (data: unknown, origin: string, source: unknown) => act(() => void window.dispatchEvent(Object.assign(new Event("message"), { data, origin, source })));
const needTicket = { v: 1, type: "status", state: "ticket_needed", id: ID };

describe("ExecutorFrame", () => {
  it("embeds the executor origin from /origins.json with the tightest sandbox that works", async () => {
    renderFrame();
    const f = await screen.findByTitle("Executor");
    expect(f).toHaveAttribute("src", EXECUTOR + "/");
    expect(f).toHaveAttribute("sandbox", "allow-scripts allow-same-origin");
    expect(f).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(f.getAttribute("sandbox")).not.toMatch(/allow-(forms|popups|modals|top-navigation|downloads|pointer-lock|presentation)/);
  });

  it("does not embed anything when the published panel origin is not the one this page runs on", async () => {
    origins = { panel: "https://other.example", executor: EXECUTOR };
    renderFrame();
    expect(await screen.findByRole("alert")).toHaveTextContent("недоступно");
    expect(screen.queryByTitle("Executor")).toBeNull();
  });

  it("hands one fresh ticket to the executor origin only, when the executor frame asks", async () => {
    renderFrame();
    const f = (await screen.findByTitle("Executor")) as HTMLIFrameElement;
    const post = vi.spyOn(f.contentWindow!, "postMessage");
    say(needTicket, EXECUTOR, f.contentWindow);
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    expect(post).toHaveBeenCalledWith({ v: 1, type: "ticket", id: ID, ticket: "payload.signature" }, EXECUTOR);
    say({ ...needTicket, id: "fedcba9876543210fedcba9876543210" }, EXECUTOR, f.contentWindow);
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
    expect(tickets).toBe(2); /* one ticket per request, none kept */
  });

  it("asks the api for one ticket at a time", async () => {
    slow = true;
    renderFrame();
    const f = (await screen.findByTitle("Executor")) as HTMLIFrameElement;
    const post = vi.spyOn(f.contentWindow!, "postMessage");
    say(needTicket, EXECUTOR, f.contentWindow);
    say({ ...needTicket, id: "fedcba9876543210fedcba9876543210" }, EXECUTOR, f.contentWindow);
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    expect(tickets).toBe(1);
  });

  it.each([
    ["another origin", needTicket, "https://evil.example", "frame"],
    ["the panel's own origin", needTicket, PANEL, "frame"],
    ["another window of the executor origin", needTicket, EXECUTOR, "other"],
    ["an unknown field", { ...needTicket, extra: 1 }, EXECUTOR, "frame"],
    ["a malformed id", { ...needTicket, id: "1" }, EXECUTOR, "frame"],
    ["a ready message (needs no answer)", { v: 1, type: "status", state: "ready" }, EXECUTOR, "frame"],
  ])("drops %s without asking the api for a ticket", async (_n, data, origin, from) => {
    renderFrame();
    const f = (await screen.findByTitle("Executor")) as HTMLIFrameElement;
    const post = vi.spyOn(f.contentWindow!, "postMessage");
    say(data, origin, from === "frame" ? f.contentWindow : window);
    await new Promise((r) => setTimeout(r, 50));
    expect(tickets).toBe(0);
    expect(post).not.toHaveBeenCalled();
  });
});
