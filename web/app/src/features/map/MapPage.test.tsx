import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import { installCanvasStub } from "./canvasStub";
import { area, node } from "./fixtures";
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
    expect(screen.queryByRole("button", { name: "Редактор карты" })).toBeNull();
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
    await userEvent.click(await screen.findByRole("button", { name: "Редактор карты" }));
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
    await userEvent.click(await screen.findByRole("button", { name: "Редактор карты" }));
    await userEvent.click(await screen.findByRole("button", { name: "Удалить подложку везде" }));
    expect(bodies.some((b) => b.method === "DELETE")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Подтвердить" }));
    await waitFor(() => expect(bodies).toContainEqual({ method: "DELETE", url: "/api/map/backgrounds/5", body: "" }));
  });

  it("edits an area through the form", async () => {
    renderPage(true);
    await userEvent.click(await screen.findByRole("button", { name: "Редактор карты" }));
    await userEvent.click(await screen.findByRole("button", { name: "Floor <i>1</i>" }));
    const name = screen.getByLabelText("Название области");
    await userEvent.clear(name);
    await userEvent.type(name, "Lobby");
    await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    await waitFor(() =>
      expect(bodies).toContainEqual({ method: "PATCH", url: "/api/map/views/1/areas/1", body: { name: "Lobby", kind: "building", parent_id: null, x: 0, y: 0, w: 100, h: 100 } }),
    );
  });
});
