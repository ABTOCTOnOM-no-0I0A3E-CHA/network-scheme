import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { checkWindow, MaintenancePage } from "./MaintenancePage";

const H = 3_600_000;
const D = 24 * H;

describe("checkWindow", () => {
  const now = Date.UTC(2026, 9, 22, 12);
  it("applies the server rules", () => {
    expect(checkWindow(now, now + H, now)).toBeUndefined();
    expect(checkWindow(now - H, now + H, now)).toBeUndefined();
    expect(checkWindow(NaN, now, now)).toBe("required");
    expect(checkWindow(now, now, now)).toBe("order");
    expect(checkWindow(now + 2 * H, now + H, now)).toBe("order");
    expect(checkWindow(now, now + 7 * D, now)).toBeUndefined();
    expect(checkWindow(now, now + 7 * D + 1, now)).toBe("tooLong");
    expect(checkWindow(now - 2 * H, now - H, now)).toBe("past");
  });
});

let posted: Record<string, unknown>[] = [];
let queries: URLSearchParams[] = [];
let ended: string[] = [];
let postFn: () => Response;
const future = new Date(Date.now() + 10 * H).toISOString();
const past = new Date(Date.now() - 10 * H).toISOString();
const server = setupServer(
  http.get("*/api/maintenance", ({ request }) => {
    queries.push(new URL(request.url).searchParams);
    return HttpResponse.json([
      { id: 1, group_id: 4, group_name: "<i>HQ</i>", starts_at: past, ends_at: future, comment: "uplink work" },
      { id: 2, group_id: 4, group_name: "HQ", starts_at: past, ends_at: past, comment: "" },
    ]);
  }),
  http.post("*/api/maintenance", async ({ request }) => {
    posted.push((await request.json()) as Record<string, unknown>);
    return postFn();
  }),
  http.delete("*/api/maintenance/:id", ({ params }) => {
    ended.push(String(params.id));
    return new HttpResponse(null, { status: 204 });
  }),
  http.get("*/api/groups", () => HttpResponse.json([{ id: 4, parent_id: null, name: "HQ" }])),
);
beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  posted = [];
  queries = [];
  ended = [];
});
afterAll(() => server.close());

function setup(canManage: boolean, canListGroups = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MaintenancePage canManage={canManage} canListGroups={canListGroups} />
    </QueryClientProvider>,
  );
}

describe("MaintenancePage", () => {
  it("a viewer sees the windows as text but cannot create or end them", async () => {
    setup(false);
    expect(await screen.findByText("<i>HQ</i>")).toBeInTheDocument();
    expect(document.querySelector("i")).toBeNull();
    expect(screen.queryByRole("form", { name: ru.maintenance.add })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: ru.maintenance.end })).not.toBeInTheDocument();
  });

  it("asks for finished windows on request and marks them over", async () => {
    setup(false);
    await screen.findByText("uplink work");
    expect(queries[queries.length - 1].get("include_ended")).toBe("false");
    await userEvent.click(screen.getByLabelText(ru.maintenance.showEnded));
    await waitFor(() => expect(queries[queries.length - 1].get("include_ended")).toBe("true"));
    expect(await screen.findByText(ru.maintenance.over)).toBeInTheDocument();
  });

  it("creates a window after local validation and maps server errors", async () => {
    postFn = () => HttpResponse.json({ error: { code: "invalid_window", message: "RAW SERVER MESSAGE" } }, { status: 400 });
    setup(true);
    const form = await screen.findByRole("form", { name: ru.maintenance.add });
    await within(form).findByRole("option", { name: "HQ" });
    await userEvent.click(within(form).getByRole("button", { name: ru.maintenance.create }));
    expect(await within(form).findByRole("alert")).toHaveTextContent(ru.templates.err.group);

    await userEvent.selectOptions(within(form).getByLabelText(ru.maintenance.col.group), "4");
    const ends = within(form).getByLabelText(ru.maintenance.col.ends);
    await userEvent.clear(ends);
    await userEvent.type(ends, "2020-01-01T10:00");
    await userEvent.click(within(form).getByRole("button", { name: ru.maintenance.create }));
    expect(await within(form).findByRole("alert")).toHaveTextContent(ru.maintenance.err.order);
    expect(posted).toHaveLength(0);

    await userEvent.clear(ends);
    await userEvent.type(ends, "2099-01-01T10:00");
    await userEvent.click(within(form).getByRole("button", { name: ru.maintenance.create }));
    expect(await within(form).findByRole("alert")).toHaveTextContent(ru.maintenance.err.tooLong);

    const d = new Date(Date.now() + 2 * H);
    const pad = (n: number) => String(n).padStart(2, "0");
    await userEvent.clear(ends);
    await userEvent.type(ends, `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`);
    await userEvent.type(within(form).getByLabelText(ru.maintenance.col.comment), "patching");
    await userEvent.click(within(form).getByRole("button", { name: ru.maintenance.create }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toMatchObject({ group_id: 4, comment: "patching" });
    expect(Date.parse(posted[0].ends_at as string)).toBeGreaterThan(Date.parse(posted[0].starts_at as string));
    expect(await within(form).findByText(ru.errors.invalid_window)).toBeInTheDocument();
    expect(screen.queryByText("RAW SERVER MESSAGE")).not.toBeInTheDocument();
  });

  it("ends a running window early", async () => {
    setup(true, false);
    await userEvent.click(await screen.findByRole("button", { name: /Завершить окно группы/ }));
    await waitFor(() => expect(ended).toEqual(["1"]));
    /* groups cannot be listed: the group is typed as an id */
    expect(screen.getByLabelText(ru.maintenance.col.group)).toHaveAttribute("type", "number");
  });
});
