import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { Core } from "cytoscape";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import { installCanvasStub } from "./canvasStub";
import { area, node } from "./fixtures";
import { DeviceWindowsProvider } from "@/features/devices/DeviceWindows";
import { MapPage } from "./MapPage";

const navigate = vi.fn();
vi.mock("@tanstack/react-router", async (orig) => ({ ...(await orig<typeof import("@tanstack/react-router")>()), useNavigate: () => navigate }));

let topoQueries: URLSearchParams[] = [];
let bodies: { method: string; url: string; body: unknown }[] = [];
const rec = async (request: Request) => {
  const ct = request.headers.get("content-type") ?? "";
  bodies.push({ method: request.method, url: new URL(request.url).pathname, body: ct.includes("json") ? await request.json() : ct.split(";")[0] });
};
const views = [
  { id: 1, name: "<b>HQ</b>", kind: "plan", background_id: 5 },
  { id: 2, name: "Logical", kind: "logical", background_id: null },
];
const server = setupServer(
  http.get("*/api/map/views", () => HttpResponse.json(views)),
  http.get("*/api/topology", ({ request }) => {
    topoQueries.push(new URL(request.url).searchParams);
    return HttpResponse.json({ nodes: [node(1, { area_id: 1, x: 0, y: 0 })], links: [], areas: [area(1, { name: "Floor <i>1</i>", device_count: 1 })] });
  }),
  http.get("*/api/problems", () => HttpResponse.json({ items: [], next_cursor: null })),
  http.get("*/api/map/backgrounds", () =>
    HttpResponse.json([
      { id: 5, mime: "image/svg+xml", width: 800, height: 600, size: 4096, sha256: "aa", uploaded_at: "2026-10-01T10:00:00Z", views: 1, unused: false },
      { id: 8, mime: "image/png", width: 10, height: 10, size: 100, sha256: "bb", uploaded_at: "2026-10-02T10:00:00Z", views: 0, unused: true },
    ]),
  ),
  http.post("*/api/map/views", async ({ request }) => {
    await rec(request);
    return HttpResponse.json({ id: 9 }, { status: 201 });
  }),
  http.post("*/api/map/backgrounds", async ({ request }) => {
    await rec(request);
    return HttpResponse.json({ id: 77, mime: "image/png", width: 1, height: 1, size: 3, sha256: "ab" }, { status: 201 });
  }),
  http.patch("*/api/map/views/:id", async ({ request }) => {
    await rec(request);
    return new HttpResponse(null, { status: 204 });
  }),
  http.delete("*/api/map/backgrounds/:id", async ({ request }) => {
    await rec(request);
    return new HttpResponse(null, { status: 204 });
  }),
  http.delete("*/api/map/views/:id", async ({ request }) => {
    await rec(request);
    return new HttpResponse(null, { status: 204 });
  }),
  http.patch("*/api/map/views/:id/areas/:aid", async ({ request }) => {
    await rec(request);
    return new HttpResponse(null, { status: 204 });
  }),
  http.post("*/api/map/views/:id/areas", async ({ request }) => {
    await rec(request);
    return HttpResponse.json({ id: 4 }, { status: 201 });
  }),
  http.put("*/api/map/views/:id/positions", async ({ request }) => {
    await rec(request);
    return new HttpResponse(null, { status: 204 });
  }),
);
beforeAll(() => {
  installCanvasStub();
  server.listen({ onUnhandledFrame: "error" });
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  topoQueries = [];
  bodies = [];
});
afterAll(() => server.close());

const cyOf = () => (screen.getByTestId("map-canvas") as unknown as { _cyreg: { cy: Core } })._cyreg.cy;

const renderPage = (canManage: boolean) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MapPage canManage={canManage} />
    </QueryClientProvider>,
  );

describe("MapPage", () => {
  it("opens the first view with its background and lists view names as text", async () => {
    const { container } = renderPage(false);
    await waitFor(() => expect(topoQueries).toHaveLength(1));
    expect(topoQueries[0].get("view_id")).toBe("1");
    const sel = await screen.findByRole("combobox", { name: "Вид карты" });
    expect(within(sel).getByRole("option", { name: "<b>HQ</b>" })).toBeInTheDocument();
    await waitFor(() => expect(container.querySelector("img[src='/api/map/backgrounds/5']")).not.toBeNull());
    expect(container.querySelector("b")).toBeNull();
    expect(screen.queryByRole("button", { name: "Виды и подложки" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Правка" })).toBeNull();
  });

  it("opens the view from ?view=", async () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MapPage canManage={false} initialViewId={2} />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(topoQueries[0]?.get("view_id")).toBe("2"));
  });

  it("switches views and can show all devices without a view", async () => {
    renderPage(false);
    const sel = await screen.findByRole("combobox", { name: "Вид карты" });
    await userEvent.selectOptions(sel, "Все устройства");
    await waitFor(() => expect(topoQueries.at(-1)?.has("view_id")).toBe(false));
    await userEvent.selectOptions(sel, "Logical");
    await waitFor(() => expect(topoQueries.at(-1)?.get("view_id")).toBe("2"));
  });

  it("lets map.manage create a view, upload a background into it and delete it after confirmation", async () => {
    renderPage(true);
    await userEvent.click(await screen.findByRole("button", { name: "Виды и подложки" }));
    await userEvent.type(screen.getByLabelText("Название вида"), "New floor");
    await userEvent.click(screen.getByRole("button", { name: "Создать вид" }));
    await waitFor(() => expect(bodies).toContainEqual({ method: "POST", url: "/api/map/views", body: { name: "New floor", kind: "logical" } }));

    const file = new File([new Uint8Array([1, 2, 3])], "plan.png", { type: "image/png" });
    await userEvent.upload(screen.getByLabelText("Загрузить подложку"), file);
    await waitFor(() => expect(bodies).toContainEqual({ method: "PATCH", url: "/api/map/views/1", body: { background_id: 77 } }));
    expect(bodies.find((b) => b.url === "/api/map/backgrounds")?.body).toBe("multipart/form-data");

    await userEvent.click(screen.getByRole("button", { name: "Удалить вид" }));
    expect(bodies.some((b) => b.method === "DELETE")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Подтвердить" }));
    await waitFor(() => expect(bodies).toContainEqual({ method: "DELETE", url: "/api/map/views/1", body: "" }));
  });

  it("deletes the background of the view for everyone after confirmation", async () => {
    renderPage(true);
    await userEvent.click(await screen.findByRole("button", { name: "Виды и подложки" }));
    await userEvent.click(await screen.findByRole("button", { name: "Удалить подложку везде" }));
    expect(bodies.some((b) => b.method === "DELETE")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Подтвердить" }));
    await waitFor(() => expect(bodies).toContainEqual({ method: "DELETE", url: "/api/map/backgrounds/5", body: "" }));
  });

  it("lists backgrounds and deletes only an unused one, after confirmation", async () => {
    renderPage(true);
    await userEvent.click(await screen.findByRole("button", { name: "Виды и подложки" }));
    const list = await screen.findByRole("list", { name: "Подложки" });
    expect(await within(list).findByText("№5 · image/svg+xml · 800×600 · 4 КиБ")).toBeInTheDocument();
    expect(within(list).getByText("Используется в видах: 1")).toBeInTheDocument();
    expect(within(list).queryByRole("button", { name: "Удалить неиспользуемую подложку №5" })).toBeNull();
    await userEvent.click(within(list).getByRole("button", { name: "Удалить неиспользуемую подложку №8" }));
    expect(bodies.some((b) => b.method === "DELETE")).toBe(false);
    await userEvent.click(within(list).getByRole("button", { name: "Подтвердить" }));
    await waitFor(() => expect(bodies).toContainEqual({ method: "DELETE", url: "/api/map/backgrounds/8", body: "" }));
  });

  it("gates editing behind the Правка mode: devices and zones are fixed until it is on", async () => {
    renderPage(true);
    const map = await screen.findByTestId("network-map");
    await waitFor(() => expect(cyOf().nodes()).toHaveLength(1));
    expect(cyOf().getElementById("d1").grabbable()).toBe(false);
    expect(within(map).queryByTestId("area-editor")).toBeNull();
    expect(screen.queryByRole("button", { name: "Зона" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Правка" }));
    expect(await within(map).findByTestId("area-editor")).toBeInTheDocument();
    expect(cyOf().getElementById("d1").grabbable()).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Правка" }));
    expect(within(map).queryByTestId("area-editor")).toBeNull();
  });

  it("saves a dragged device into the view, pinned", async () => {
    renderPage(true);
    await screen.findByTestId("network-map");
    await userEvent.click(screen.getByRole("button", { name: "Правка" }));
    await waitFor(() => expect(cyOf().getElementById("d1").grabbable()).toBe(true));
    const n = cyOf().getElementById("d1");
    n.position({ x: 210, y: 120 });
    n.emit("dragfree");
    await waitFor(() => expect(bodies).toContainEqual({ method: "PUT", url: "/api/map/views/1/positions", body: { items: [{ device_id: 1, x: 210, y: 120, pinned: true }] } }), { timeout: 3000 });
  });

  it("draws a zone on the map in edit mode and creates it with its name and kind", async () => {
    renderPage(true);
    await screen.findByTestId("network-map");
    await userEvent.click(screen.getByRole("button", { name: "Правка" }));
    await userEvent.click(screen.getByRole("button", { name: "Зона" }));
    const s = await screen.findByTestId("draw-surface");
    fireEvent.pointerDown(s, { clientX: 10, clientY: 10, pointerId: 1, button: 0 });
    fireEvent.pointerMove(s, { clientX: 40, clientY: 30, pointerId: 1 });
    fireEvent.pointerUp(s, { pointerId: 1 });
    await userEvent.type(screen.getByLabelText("Название"), "Rack <1>");
    await userEvent.click(screen.getByRole("button", { name: "Создать" }));
    await waitFor(() => expect(bodies.find((b) => b.method === "POST" && b.url === "/api/map/views/1/areas")).toBeDefined());
    const body = bodies.find((b) => b.url === "/api/map/views/1/areas")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ name: "Rack <1>", kind: "room" });
    for (const k of ["x", "y", "w", "h"]) expect(Number.isFinite(body[k])).toBe(true);
    expect("parent_id" in body).toBe(true);
  });

  it("keeps the positions of all devices: editing them switches to a default view, created on first use", async () => {
    server.use(http.get("*/api/map/views", () => HttpResponse.json([])));
    renderPage(true);
    const sel = await screen.findByRole("combobox", { name: "Вид карты" });
    expect(sel).toHaveValue("0");
    await userEvent.click(screen.getByRole("button", { name: "Правка" }));
    await waitFor(() => expect(bodies).toContainEqual({ method: "POST", url: "/api/map/views", body: { name: "Основная схема", kind: "logical" } }));
    await waitFor(() => expect(topoQueries.at(-1)?.get("view_id")).toBe("9"));
  });

  it("opens a device window when a device is clicked", async () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <DeviceWindowsProvider renderBody={(id) => <p>card {id}</p>} onOpenPage={vi.fn()}>
          <MapPage canManage={false} />
        </DeviceWindowsProvider>
      </QueryClientProvider>,
    );
    await screen.findByTestId("network-map");
    await waitFor(() => expect(cyOf().nodes()).toHaveLength(1));
    cyOf().getElementById("d1").emit("tap");
    const win = await screen.findByRole("dialog", { name: "sw1" });
    expect(within(win).getByText("card 1")).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalled();
  });
});
