import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { z } from "zod";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { registerWidget, unregisterWidget } from "@/widgets/registry";
import { pickDashboard, type Dashboard, type DashboardDetail } from "./api";
import { addItem, applyLayout, DashboardPage } from "./DashboardPage";

vi.mock("@tanstack/react-router", async (orig) => ({ ...(await orig<typeof import("@tanstack/react-router")>()), useNavigate: () => vi.fn() }));

let roles: { role: string; group_id: number | null }[] = [];
let list: Dashboard[] = [];
let stored: Record<number, DashboardDetail> = {};
let puts: { id: number; body: { widgets: Record<string, unknown>[] } }[] = [];

const server = setupServer(
  http.get("*/api/auth/me", () => HttpResponse.json({ id: 1, username: "u", roles, csrf_token: "tok" })),
  http.get("*/api/dashboards", () => HttpResponse.json(list)),
  http.get("*/api/dashboards/:id", ({ params }) => HttpResponse.json(stored[Number(params.id)])),
  http.put("*/api/dashboards/:id/widgets", async ({ params, request }) => {
    const id = Number(params.id);
    const body = (await request.json()) as { widgets: Record<string, unknown>[] };
    puts.push({ id, body });
    let next = 100;
    stored[id] = { ...stored[id], widgets: body.widgets.map((w) => ({ ...(w as DashboardDetail["widgets"][number]), id: (w.id as number | undefined) ?? next++ })) };
    return HttpResponse.json(stored[id]);
  }),
  http.get("*/api/stats/device-states", () => HttpResponse.json({ total: 5, up: 3, partial: 1, down: 1, unknown: 0 })),
  http.get("*/api/test-widget", () => HttpResponse.json({ text: "данные тестового виджета" })),
);
beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  roles = [];
  list = [];
  stored = {};
  puts = [];
});
afterAll(() => server.close());

const dash = (id: number, extra: Partial<Dashboard> = {}): Dashboard => ({ id, name: `Дашборд ${id}`, shared: false, default_for_role: null, editable: true, ...extra });
/* already compact (the grid compacts upwards), so the saved layout must equal the stored one */
const status = { id: 7, type: "device_status" as const, x: 2, y: 0, w: 4, h: 4, config: {} };

function renderPage(requested?: number) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <DashboardPage requested={requested} />
    </QueryClientProvider>,
  );
}

describe("widget registry contract", () => {
  it("shows a widget added by registration only: its schema, data query and render, no core change", async () => {
    const schema = z.strictObject({ title: z.string().optional() });
    registerWidget({
      type: "test_widget",
      title: "widgets.empty",
      description: "widgets.empty",
      configSchema: schema,
      defaultConfig: {},
      size: { w: 2, h: 2 },
      dataQuery: () => ({ queryKey: ["test-widget"], queryFn: async () => ((await (await fetch(`${window.location.origin}/api/test-widget`)).json()) as { text: string }).text }),
      render: (text: string, c) => <p data-testid="test-widget">{`${c.title ?? ""}${text}`}</p>,
    });
    try {
      list = [dash(1)];
      stored[1] = { ...list[0], widgets: [{ id: 1, type: "test_widget" as never, x: 0, y: 0, w: 2, h: 2, config: { title: "T:" } }] };
      renderPage();
      expect(await screen.findByTestId("test-widget")).toHaveTextContent("T:данные тестового виджета");
    } finally {
      unregisterWidget("test_widget");
    }
  });

  it("shows an unknown type and a config outside the schema as such instead of rendering them", async () => {
    list = [dash(1)];
    stored[1] = {
      ...list[0],
      widgets: [
        { id: 1, type: "gone_widget" as never, x: 0, y: 0, w: 2, h: 2, config: {} },
        { id: 2, type: "problems", x: 2, y: 0, w: 2, h: 2, config: { limit: 999 } },
      ],
    };
    renderPage();
    expect(await screen.findByText(ru.widgets.unknown.title)).toBeInTheDocument();
    expect(await screen.findByText(ru.widgets.invalidConfig)).toBeInTheDocument();
  });
});

describe("dashboard page", () => {
  it("shows the shared default of the user's role", async () => {
    roles = [{ role: "viewer", group_id: 3 }];
    list = [dash(1), dash(2, { shared: true, default_for_role: "operator", editable: false }), dash(3, { shared: true, default_for_role: "viewer", editable: false })];
    stored[3] = { ...list[2], widgets: [status] };
    renderPage();
    expect(await screen.findByTestId("device-total")).toHaveTextContent("5");
    expect((screen.getByRole("combobox", { name: ru.dashboards.select }) as HTMLSelectElement).value).toBe("3");
    /* a shared dashboard without dashboards.manage is not editable */
    expect(screen.queryByRole("button", { name: ru.dashboards.edit })).toBeNull();
  });

  it("saves the layout with a widget added from the catalog and restores it from the stored dashboard", async () => {
    roles = [{ role: "viewer", group_id: null }];
    list = [dash(1)];
    stored[1] = { ...list[0], widgets: [status] };
    server.use(http.get("*/api/problems", () => HttpResponse.json({ items: [], next_cursor: null })));
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: ru.dashboards.edit }));
    const catalog = screen.getByRole("region", { name: ru.dashboards.catalog });
    await user.click(within(catalog).getByRole("button", { name: `Добавить виджет «${ru.widgets.problems.title}»` }));
    await user.click(screen.getByRole("button", { name: ru.dashboards.save }));

    await waitFor(() => expect(puts).toHaveLength(1));
    expect(puts[0].body.widgets).toEqual([
      { id: 7, type: "device_status", x: 2, y: 0, w: 4, h: 4, config: {} },
      { type: "problems", x: 0, y: 4, w: 4, h: 6, config: { limit: 10 } },
    ]);
    /* back in view mode, drawn from the stored dashboard the server answered */
    expect(await screen.findByText(ru.widgets.problems.none)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: ru.dashboards.save })).toBeNull();
    expect(stored[1].widgets.map((w) => [w.id, w.x, w.y, w.w, w.h])).toEqual([
      [7, 2, 0, 4, 4],
      [100, 0, 4, 4, 6],
    ]);
  });

  it("removes a widget in edit mode and saves the smaller set", async () => {
    list = [dash(1)];
    stored[1] = { ...list[0], widgets: [status] };
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: ru.dashboards.edit }));
    await user.click(screen.getByRole("button", { name: `Убрать виджет «${ru.widgets.deviceStatus.title}»` }));
    await user.click(screen.getByRole("button", { name: ru.dashboards.save }));
    await waitFor(() => expect(puts[0]?.body.widgets).toEqual([]));
  });

  it("says so when there is no dashboard", async () => {
    renderPage();
    expect(await screen.findByText(ru.dashboards.none)).toBeInTheDocument();
  });
});

describe("dashboard helpers", () => {
  it("picks the requested dashboard, else the default of the highest role, else a personal one", () => {
    const l = [dash(1, { shared: true }), dash(2), dash(3, { shared: true, default_for_role: "viewer" }), dash(4, { shared: true, default_for_role: "admin" })];
    expect(pickDashboard(l, ["viewer"], 1)?.id).toBe(1);
    expect(pickDashboard(l, ["viewer"], 99)?.id).toBe(3);
    expect(pickDashboard(l, ["viewer", "admin"])?.id).toBe(4);
    expect(pickDashboard(l, ["auditor"])?.id).toBe(2);
    expect(pickDashboard([dash(5, { shared: true })], ["auditor"])?.id).toBe(5);
    expect(pickDashboard([], ["viewer"])).toBeUndefined();
  });

  it("applies a grid layout clamped to the 12-column grid and adds below everything", () => {
    const items = [{ key: "a", id: 1, type: "device_status", x: 0, y: 0, w: 3, h: 4, config: {} }];
    expect(applyLayout(items, [{ i: "a", x: 11, y: 2, w: 3, h: 60 }])[0]).toMatchObject({ x: 9, y: 2, w: 3, h: 48 });
    const added = addItem(items, "mini_map");
    expect(added[1]).toMatchObject({ type: "mini_map", x: 0, y: 4, w: 6, h: 8, config: {} });
    expect(addItem(items, "nope")).toBe(items);
  });
});
