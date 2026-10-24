import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import { installCanvasStub } from "./canvasStub";
import { node } from "./fixtures";
import { MiniMap } from "./MiniMap";

const navigate = vi.fn();
vi.mock("@tanstack/react-router", async (orig) => ({ ...(await orig<typeof import("@tanstack/react-router")>()), useNavigate: () => navigate }));

let queries: URLSearchParams[] = [];
const server = setupServer(
  http.get("*/api/map/views", () => HttpResponse.json([{ id: 3, name: "HQ", kind: "plan", background_id: 5 }])),
  http.get("*/api/topology", ({ request }) => {
    queries.push(new URL(request.url).searchParams);
    return HttpResponse.json({ nodes: [node(1, { x: 0, y: 0 }), node(2, { x: 50, y: 50, state: "down" })], links: [], areas: [] });
  }),
  http.get("*/api/problems", () => HttpResponse.json({ items: [], next_cursor: null })),
);
beforeAll(() => {
  installCanvasStub();
  server.listen({ onUnhandledFrame: "error" });
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  queries = [];
  navigate.mockReset();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());

const mm = (reduced: boolean) =>
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: reduced && q.includes("reduce"), media: q, addEventListener() {}, removeEventListener() {} }));
const renderMini = (props: { viewId?: number } = {}) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MiniMap {...props} />
    </QueryClientProvider>,
  );

describe("MiniMap", () => {
  it("renders the compact map of the first view with the same background, without editors or layout button", async () => {
    mm(false);
    const { container } = renderMini();
    await waitFor(() => expect(container.querySelector("[data-testid='network-map'] canvas")).not.toBeNull());
    expect(queries[0].get("view_id")).toBe("3");
    expect(container.querySelector("img[src='/api/map/backgrounds/5']")).not.toBeNull();
    expect(screen.getByRole("button", { name: "Показать всё" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Автораскладка" })).toBeNull();
    expect(container.querySelector("[data-testid^='area-'], [data-testid='draw-surface']")).toBeNull();
  });

  it("takes an explicit viewId", async () => {
    mm(false);
    renderMini({ viewId: 7 });
    await waitFor(() => expect(queries[0]?.get("view_id")).toBe("7"));
  });

  it("opens the full map with the same view", async () => {
    mm(false);
    renderMini();
    await userEvent.click(await screen.findByRole("button", { name: "Открыть" }));
    expect(navigate).toHaveBeenCalledWith({ to: "/map", search: { view: 3 } });
  });

  it("keeps the Open button in a header strip above and outside the map box", async () => {
    mm(false);
    renderMini();
    const btn = await screen.findByRole("button", { name: "Открыть" });
    const box = screen.getByTestId("mini-map-box");
    const header = screen.getByTestId("mini-map-header");
    expect(header.contains(btn)).toBe(true);
    expect(box.contains(btn)).toBe(false);
    expect(header.compareDocumentPosition(box) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(box.className).toContain("origin-top");
  });

  it("has the bubble classes normally and none under prefers-reduced-motion", () => {
    mm(false);
    const a = renderMini();
    expect(a.getByTestId("mini-map-box").className).toContain("hover:scale-");
    a.unmount();
    mm(true);
    renderMini();
    expect(screen.getByTestId("mini-map-box").className).not.toMatch(/scale|transition|shadow/);
  });
});
