import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { ProblemList } from "./ProblemList";
import i18n from "@/i18n";
import { problemTitle, validateComment, type Problem } from "./api";

const HOSTILE = "<script>alert(1)</script>\u0007‮evil";

const problem = (id: number, over: Partial<Problem> = {}): Problem => ({
  id,
  device_id: 1,
  device_name: "core-sw",
  group_id: 1,
  severity: "high",
  state: "problem",
  suppressed: false,
  name: `Problem ${id}`,
  object: "",
  opened_at: "2026-10-22T10:00:00Z",
  acknowledged_at: null,
  resolved_at: null,
  trigger_id: 1,
  system_kind: null,
  resolve_reason: null,
  last_value: null,
  ...over,
});

let queries: URLSearchParams[] = [];
let listFn: (q: URLSearchParams) => Response;
let ackBody: unknown;
let ackFn: () => Response;
const server = setupServer(
  http.get("*/api/problems/:id", ({ params }) => HttpResponse.json({ ...problem(Number(params.id)), acks: [{ id: 1, user_id: 5, username: "alice", comment: `seen ${HOSTILE}`, at: "2026-10-22T10:05:00Z" }] })),
  http.get("*/api/problems", ({ request }) => {
    const q = new URL(request.url).searchParams;
    queries.push(q);
    return listFn(q);
  }),
  http.post("*/api/problems/:id/ack", async ({ request }) => {
    ackBody = await request.json();
    return ackFn();
  }),
  http.get("*/api/devices", () => HttpResponse.json([{ id: 1, name: "core-sw", address: "192.0.2.10", group_id: 1, driver: "generic-snmp", model: "", firmware: "", insecure_protocols: false, state: "up", state_since: null }])),
);

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  queries = [];
  ackBody = undefined;
});
afterAll(() => server.close());

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}
const last = () => queries[queries.length - 1];

describe("problemTitle", () => {
  const t = i18n.t.bind(i18n);
  it("translates system kinds and seeded trigger names, keeps other names as stored", () => {
    expect(problemTitle(t, { name: "Poller is unavailable", system_kind: "poller_unavailable" })).toBe(ru.problems.systemKind.poller_unavailable);
    expect(problemTitle(t, { name: "New kind", system_kind: "future_kind" })).toBe("New kind");
    expect(problemTitle(t, { name: "Device is unavailable", system_kind: null })).toBe(ru.problems.seeded.deviceUnavailable);
    expect(problemTitle(t, { name: "Custom trigger", system_kind: null })).toBe("Custom trigger");
  });
});

describe("validateComment", () => {
  it("mirrors the server rule", () => {
    expect(validateComment("ok")).toBe(true);
    expect(validateComment("two\nlines\tand tab")).toBe(true);
    expect(validateComment("")).toBe(false);
    expect(validateComment("   ")).toBe(false);
    expect(validateComment("bell\u0007")).toBe(false);
    expect(validateComment("x".repeat(1000))).toBe(true);
    expect(validateComment("x".repeat(1001))).toBe(false);
  });
});

describe("ProblemList", () => {
  it("lists problems as text, marks suppressed ones and sends the filters", async () => {
    listFn = () =>
      HttpResponse.json({
        items: [problem(1, { name: HOSTILE, object: "if:3", device_name: HOSTILE }), problem(2, { suppressed: true, state: "acknowledged" })],
        next_cursor: null,
      });
    const { container } = wrap(<ProblemList canAck />);
    expect(await screen.findByText(ru.problems.suppressed)).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).not.toContain("‮");
    expect(container.textContent).toContain("<script>alert(1)</script>��evil (if:3)");
    expect(last().get("suppressed")).toBeNull();

    await userEvent.selectOptions(screen.getByLabelText(ru.problems.filter.suppressed), "true");
    await waitFor(() => expect(last().get("suppressed")).toBe("true"));
    await userEvent.selectOptions(screen.getByLabelText(ru.problems.filter.state), "problem");
    await waitFor(() => expect(last().get("state")).toBe("problem"));
    await userEvent.selectOptions(screen.getByLabelText(ru.problems.filter.severity), "high");
    await waitFor(() => expect(last().get("severity_min")).toBe("high"));
    await userEvent.selectOptions(screen.getByLabelText(ru.events.filter.device), "1");
    await waitFor(() => expect(last().get("device_id")).toBe("1"));
    expect(last().get("suppressed")).toBe("true");
  });

  it("a fixed device is sent as is and its filter and column are hidden", async () => {
    listFn = () => HttpResponse.json({ items: [problem(1)], next_cursor: null });
    wrap(<ProblemList deviceId={7} canAck={false} />);
    await screen.findByText("Problem 1");
    expect(last().get("device_id")).toBe("7");
    expect(screen.queryByLabelText(ru.events.filter.device)).not.toBeInTheDocument();
  });

  it("pages with the cursor", async () => {
    listFn = (q) => (q.get("cursor") ? HttpResponse.json({ items: [problem(2)], next_cursor: null }) : HttpResponse.json({ items: [problem(1)], next_cursor: "c1" }));
    wrap(<ProblemList canAck />);
    await userEvent.click(await screen.findByRole("button", { name: ru.events.loadMore }));
    expect(await screen.findByText("Problem 2")).toBeInTheDocument();
    expect(last().get("cursor")).toBe("c1");
  });

  it("acknowledges with a comment: empty is refused locally, the history is shown as text", async () => {
    listFn = () => HttpResponse.json({ items: [problem(1)], next_cursor: null });
    ackFn = () => new HttpResponse(null, { status: 204 });
    wrap(<ProblemList canAck />);
    await userEvent.click(await screen.findByRole("button", { name: /Подробности/ }));
    const details = await screen.findByTestId("problem-details");
    expect(await within(details).findByText(/alice/)).toBeInTheDocument();
    expect(details.textContent).toContain("seen <script>alert(1)</script>��evil");

    const form = within(details).getByRole("form", { name: ru.problems.ack.title });
    await userEvent.click(within(form).getByRole("button", { name: ru.problems.ack.submit }));
    expect(await within(form).findByRole("alert")).toHaveTextContent(ru.problems.ack.invalid);
    expect(ackBody).toBeUndefined();

    await userEvent.type(within(form).getByLabelText(ru.problems.ack.comment), "on it");
    await userEvent.click(within(form).getByRole("button", { name: ru.problems.ack.submit }));
    await waitFor(() => expect(ackBody).toEqual({ comment: "on it" }));
  });

  it("maps a server refusal to a localized message", async () => {
    listFn = () => HttpResponse.json({ items: [problem(1)], next_cursor: null });
    ackFn = () => HttpResponse.json({ error: { code: "problem_resolved", message: "RAW SERVER MESSAGE" } }, { status: 409 });
    wrap(<ProblemList canAck />);
    await userEvent.click(await screen.findByRole("button", { name: /Подробности/ }));
    const form = await screen.findByRole("form", { name: ru.problems.ack.title });
    await userEvent.type(within(form).getByLabelText(ru.problems.ack.comment), "late");
    await userEvent.click(within(form).getByRole("button", { name: ru.problems.ack.submit }));
    expect(await within(form).findByText(ru.errors.problem_resolved)).toBeInTheDocument();
    expect(screen.queryByText("RAW SERVER MESSAGE")).not.toBeInTheDocument();
  });

  it("without problems.ack and for a resolved problem there is no acknowledge form", async () => {
    listFn = () => HttpResponse.json({ items: [problem(1), problem(2, { state: "resolved", resolved_at: "2026-10-22T11:00:00Z", resolve_reason: "recovered" })], next_cursor: null });
    wrap(<ProblemList canAck={false} />);
    const buttons = await screen.findAllByRole("button", { name: /Подробности/ });
    expect(screen.queryByRole("button", { name: ru.problems.ack.open })).not.toBeInTheDocument();
    await userEvent.click(buttons[0]);
    await screen.findByTestId("problem-details");
    expect(screen.queryByRole("form", { name: ru.problems.ack.title })).not.toBeInTheDocument();
  });
});
