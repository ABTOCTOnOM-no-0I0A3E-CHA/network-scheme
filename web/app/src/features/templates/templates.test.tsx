import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { buildParams, EMPTY_PARAMS, KINDS, parseDuration, parseInterval, validName, type Kind, type ParamsForm } from "./params";
import { TemplatesPage } from "./TemplatesPage";

const form = (over: Partial<ParamsForm>): ParamsForm => ({ ...EMPTY_PARAMS, ...over });
const ok = (kind: Kind, over: Partial<ParamsForm>) => buildParams(kind, form(over));

describe("params validation (mirror of internal/triggers)", () => {
  it("knows exactly the closed set of user kinds, no system ones", () => {
    expect([...KINDS]).toEqual(["availability", "if_oper_down", "metric_threshold", "trap", "syslog"]);
  });

  it("availability needs down and/or partial", () => {
    expect(ok("availability", { states: { down: false, partial: false } })).toEqual({ err: "states" });
    expect(ok("availability", { states: { down: true, partial: true } })).toEqual({ ok: { states: ["down", "partial"] } });
    expect(ok("availability", { states: { down: false, partial: true } })).toEqual({ ok: { states: ["partial"] } });
  });

  it("if_oper_down: optional interface index 1..2147483647", () => {
    expect(ok("if_oper_down", { ifIndex: "" })).toEqual({ ok: {} });
    expect(ok("if_oper_down", { ifIndex: "5" })).toEqual({ ok: { if_index: 5 } });
    for (const bad of ["0", "-1", "2147483648", "1.5", "x"]) expect(ok("if_oper_down", { ifIndex: bad })).toEqual({ err: "ifIndex" });
    expect(ok("if_oper_down", { ifIndex: "2147483647" })).toEqual({ ok: { if_index: 2147483647 } });
  });

  it("metric_threshold: per-metric value ranges and interface scope", () => {
    expect(ok("metric_threshold", { metric: "cpu", value: "90" })).toEqual({ ok: { metric: "cpu", op: "gt", value: 90 } });
    expect(ok("metric_threshold", { metric: "cpu", value: "100.1" })).toEqual({ err: "value" });
    expect(ok("metric_threshold", { metric: "cpu", value: "-0.1" })).toEqual({ err: "value" });
    expect(ok("metric_threshold", { metric: "cpu", value: "" })).toEqual({ err: "value" });
    expect(ok("metric_threshold", { metric: "mem", value: "100" })).toEqual({ ok: { metric: "mem", op: "gt", value: 100 } });
    expect(ok("metric_threshold", { metric: "temp", op: "lt", value: "-50" })).toEqual({ ok: { metric: "temp", op: "lt", value: -50 } });
    expect(ok("metric_threshold", { metric: "temp", value: "150" })).toHaveProperty("ok");
    expect(ok("metric_threshold", { metric: "temp", value: "151" })).toEqual({ err: "value" });
    expect(ok("metric_threshold", { metric: "temp", value: "-50.5" })).toEqual({ err: "value" });
    expect(ok("metric_threshold", { metric: "if_util_in", value: "50", ifIndex: "3" })).toEqual({ ok: { metric: "if_util_in", op: "gt", value: 50, if_index: 3 } });
    expect(ok("metric_threshold", { metric: "if_errors", value: "1000000000" })).toHaveProperty("ok");
    expect(ok("metric_threshold", { metric: "if_errors", value: "1000000001" })).toEqual({ err: "value" });
    expect(ok("metric_threshold", { metric: "if_errors", value: "-1" })).toEqual({ err: "value" });
    expect(ok("metric_threshold", { metric: "cpu", value: "50", ifIndex: "3" })).toEqual({ err: "ifScope" });
    expect(ok("metric_threshold", { metric: "if_util_in", value: "50", ifIndex: "0" })).toEqual({ err: "ifIndex" });
  });

  it("trap: 1..1024 bytes, no control characters", () => {
    expect(ok("trap", { trapName: "linkDown" })).toEqual({ ok: { name: "linkDown" } });
    expect(ok("trap", { trapName: "" })).toEqual({ err: "trapName" });
    expect(ok("trap", { trapName: "a".repeat(1024) })).toHaveProperty("ok");
    expect(ok("trap", { trapName: "a".repeat(1025) })).toEqual({ err: "trapName" });
    /* bytes, not characters: 513 two-byte characters */
    expect(ok("trap", { trapName: "я".repeat(513) })).toEqual({ err: "trapName" });
    expect(ok("trap", { trapName: "a\u0007b" })).toEqual({ err: "trapName" });
  });

  it("syslog: severity 0..7 required, substring up to 128 characters without controls", () => {
    expect(ok("syslog", { syslogSeverity: "3", contains: "" })).toEqual({ ok: { severity_min: 3 } });
    expect(ok("syslog", { syslogSeverity: "0", contains: "Fan" })).toEqual({ ok: { severity_min: 0, contains: "Fan" } });
    for (const bad of ["", "8", "-1", "2.5"]) expect(ok("syslog", { syslogSeverity: bad })).toEqual({ err: "syslogSeverity" });
    expect(ok("syslog", { contains: "я".repeat(128) })).toHaveProperty("ok");
    expect(ok("syslog", { contains: "я".repeat(129) })).toEqual({ err: "contains" });
    expect(ok("syslog", { contains: "a‎b" })).toEqual({ err: "contains" });
  });

  it("name, duration and interval bounds", () => {
    expect(validName("ok name")).toBe(true);
    expect(validName(" lead")).toBe(false);
    expect(validName("x".repeat(201))).toBe(false);
    expect(validName("a\nb")).toBe(false);
    expect([parseDuration("0"), parseDuration("86400"), parseDuration("86401"), parseDuration("-1"), parseDuration(""), parseDuration("1.5")]).toEqual([0, 86400, null, null, null, null]);
    expect([parseInterval(""), parseInterval("10"), parseInterval("9"), parseInterval("86400"), parseInterval("86401")]).toEqual([null, 10, undefined, 86400, undefined]);
  });
});

type Body = Record<string, unknown>;
let created: Body[] = [];
let patched: Body[] = [];
let createdTemplates: Body[] = [];
let createFn: () => Response;
const triggerList = [{ id: 11, template_id: 1, kind: "metric_threshold", params: { metric: "cpu", op: "gt", value: 90 }, duration_s: 60, severity: "high", enabled: true, name: "<b>CPU</b>\u0007hot" }];
const server = setupServer(
  http.get("*/api/templates", () => HttpResponse.json([{ id: 1, name: "Core", driver: "eltex-mes", group_id: null, interval_avail_s: null, interval_metrics_s: 60, interval_inventory_s: null }])),
  http.post("*/api/templates", async ({ request }) => {
    createdTemplates.push((await request.json()) as Body);
    return HttpResponse.json({ id: 2 }, { status: 201 });
  }),
  http.get("*/api/templates/1/triggers", () => HttpResponse.json(triggerList)),
  http.post("*/api/templates/1/triggers", async ({ request }) => {
    created.push((await request.json()) as Body);
    return createFn();
  }),
  http.patch("*/api/templates/1/triggers/11", async ({ request }) => {
    patched.push((await request.json()) as Body);
    return new HttpResponse(null, { status: 204 });
  }),
  http.get("*/api/groups", () => HttpResponse.json([{ id: 4, parent_id: null, name: "HQ" }])),
);

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  created = [];
  patched = [];
  createdTemplates = [];
});
afterAll(() => server.close());

function setup(canManage: boolean) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <TemplatesPage canManage={canManage} canListGroups={false} />
    </QueryClientProvider>,
  );
}

async function openCore() {
  await userEvent.click(await screen.findByRole("button", { name: /Открыть шаблон Core/ }));
  return screen.findByTestId("template-detail");
}

describe("TemplatesPage", () => {
  it("a viewer sees the template and triggers as text but no controls", async () => {
    setup(false);
    const detail = await openCore();
    expect(await within(detail).findByText(/CPU.*hot/)).toBeInTheDocument();
    expect(detail.querySelector("b")).toBeNull();
    expect(screen.queryByRole("button", { name: ru.templates.add })).not.toBeInTheDocument();
    for (const name of [ru.templates.edit, ru.templates.delete, ru.templates.trigger.add]) expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
  });

  it("adds a trigger of a chosen kind with only its parameters, after client validation", async () => {
    createFn = () => HttpResponse.json({ id: 12 }, { status: 201 });
    setup(true);
    const detail = await openCore();
    await userEvent.click(within(detail).getByRole("button", { name: ru.templates.trigger.add }));
    const f = await screen.findByRole("form", { name: ru.templates.trigger.add });
    const kind = within(f).getByLabelText(ru.templates.trigger.kind) as HTMLSelectElement;
    expect([...kind.options].map((o) => o.value)).toEqual([...KINDS]);

    await userEvent.type(within(f).getByLabelText(ru.templates.col.name), "Syslog fans");
    await userEvent.selectOptions(kind, "syslog");
    await userEvent.clear(within(f).getByLabelText(ru.templates.trigger.duration));
    await userEvent.type(within(f).getByLabelText(ru.templates.trigger.duration), "86401");
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    expect(await within(f).findByRole("alert")).toHaveTextContent("от 0 до 86400");
    expect(created).toHaveLength(0);

    await userEvent.clear(within(f).getByLabelText(ru.templates.trigger.duration));
    await userEvent.type(within(f).getByLabelText(ru.templates.trigger.duration), "30");
    await userEvent.type(within(f).getByLabelText(ru.templates.param.contains), "Fan");
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0]).toEqual({ name: "Syslog fans", kind: "syslog", params: { severity_min: 4, contains: "Fan" }, duration_s: 30, severity: "warning", enabled: true });
  });

  it("refuses an out-of-range metric value locally and maps the server error through i18n", async () => {
    createFn = () => HttpResponse.json({ error: { code: "invalid_trigger", message: "RAW SERVER MESSAGE" } }, { status: 400 });
    setup(true);
    const detail = await openCore();
    await userEvent.click(within(detail).getByRole("button", { name: ru.templates.trigger.add }));
    const f = await screen.findByRole("form", { name: ru.templates.trigger.add });
    await userEvent.type(within(f).getByLabelText(ru.templates.col.name), "CPU");
    await userEvent.selectOptions(within(f).getByLabelText(ru.templates.trigger.kind), "metric_threshold");
    await userEvent.type(within(f).getByLabelText(/Значение/), "101");
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    expect(await within(f).findByRole("alert")).toHaveTextContent("вне допустимых границ");
    expect(created).toHaveLength(0);

    await userEvent.clear(within(f).getByLabelText(/Значение/));
    await userEvent.type(within(f).getByLabelText(/Значение/), "99");
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    expect(await within(f).findByText(ru.errors.invalid_trigger)).toBeInTheDocument();
    expect(screen.queryByText("RAW SERVER MESSAGE")).not.toBeInTheDocument();
  });

  it("edits a trigger: the kind is fixed and the full params are sent", async () => {
    setup(true);
    const detail = await openCore();
    await userEvent.click(await within(detail).findByRole("button", { name: /Изменить триггер/ }));
    const f = await screen.findByRole("form", { name: ru.templates.trigger.edit });
    expect(within(f).getByLabelText(ru.templates.trigger.kind)).toBeDisabled();
    expect(within(f).getByLabelText(/Значение/)).toHaveValue(90);
    /* the stored name carries a control character, which the form refuses until it is retyped */
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    expect(await within(f).findByRole("alert")).toHaveTextContent("Название");
    await userEvent.clear(within(f).getByLabelText(ru.templates.col.name));
    await userEvent.type(within(f).getByLabelText(ru.templates.col.name), "CPU hot");
    await userEvent.clear(within(f).getByLabelText(/Значение/));
    await userEvent.type(within(f).getByLabelText(/Значение/), "95");
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0]).toMatchObject({ params: { metric: "cpu", op: "gt", value: 95 }, duration_s: 60, severity: "high", enabled: true });
  });

  it("creates a driver template and validates the driver name and intervals", async () => {
    setup(true);
    await userEvent.click(await screen.findByRole("button", { name: ru.templates.add }));
    const f = await screen.findByRole("form", { name: ru.templates.add });
    await userEvent.type(within(f).getByLabelText(ru.templates.col.name), "Edge");
    await userEvent.type(within(f).getByLabelText(ru.templates.bind.driver), "Bad Driver");
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    expect(await within(f).findByRole("alert")).toHaveTextContent("Драйвер");
    await userEvent.clear(within(f).getByLabelText(ru.templates.bind.driver));
    await userEvent.type(within(f).getByLabelText(ru.templates.bind.driver), "eltex-esr");
    await userEvent.type(within(f).getByLabelText(ru.card.edit.intervalAvail), "5");
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    expect(await within(f).findByRole("alert")).toHaveTextContent("от 10 до 86400");
    await userEvent.clear(within(f).getByLabelText(ru.card.edit.intervalAvail));
    await userEvent.click(within(f).getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(createdTemplates).toHaveLength(1));
    expect(createdTemplates[0]).toEqual({ name: "Edge", driver: "eltex-esr", interval_avail_s: null, interval_metrics_s: null, interval_inventory_s: null });
  });
});
