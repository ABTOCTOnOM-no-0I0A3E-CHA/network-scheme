import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import ru from "../i18n/ru.json";
import { createPoster } from "../client";
import { parseChangesetPreset, stages, variablesOf } from "./api";
import { ChangesetsPage } from "./ChangesetsPage";

const vis = vi.hoisted(() => ({ unobscured: true }));
vi.mock("../useUnobscured", () => ({ useUnobscured: () => ({ ref: () => {}, unobscured: vis.unobscured, supported: true }) }));

const C = ru.executor.changesets;
const ID = "7d1e5c3a-2b4f-4a6e-8c9d-0e1f2a3b4c5d";
const H = "9c".repeat(32);
const PLAN = "ab".repeat(32);
const NOW = "2026-11-11T10:00:00Z";
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const item = (over: Record<string, unknown> = {}) => ({
  changeset_id: ID, title: "<img src=x onerror=alert(1)> vlan 120", kind: "lines", author_id: 7, author: "alice", status: "draft", device_count: 2, revision: 1, updated: NOW, ...over,
});
const detail = (over: Record<string, unknown> = {}) => ({
  ...item(),
  content: { title: "vlan 120", device_ids: [12, 14], steps: [{ line: "configure" }, { line: "interface {{port}}" }, { line: "description <b>x</b>" }], vars: { 12: { port: "gi1/0/2" }, 14: { port: "gi1/0/3" } }, batch_size: 1, settle_s: 30 },
  events: [],
  ...over,
});

type Call = { url: string; init: RequestInit; body: Record<string, unknown> };
let calls: Call[];
let answers: Record<string, (c: Call) => Response>;
let tickets: number;
beforeEach(() => {
  vis.unobscured = true;
  calls = [];
  tickets = 0;
  answers = {
    "/x/changesets/open": () => json(200, { result: { token: "ws-1", expires: NOW, idle_seconds: 600, user_id: 7, username: "alice" } }),
    "/x/changesets/list": () => json(200, { result: [item()] }),
  };
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    const c = { url, init, body: JSON.parse((init.body as string) ?? "{}") as Record<string, unknown> };
    calls.push(c);
    const a = answers[url];
    if (!a) throw new Error(`unexpected ${url}`);
    return a(c);
  }));
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const poster = () => createPoster({ requestTicket: () => Promise.resolve(`ticket-${++tickets}`) });
const onRecordings = vi.fn();
function page(hash = "") {
  return render(<ChangesetsPage poster={poster()} preset={parseChangesetPreset(hash)} onRecordings={onRecordings} />);
}
async function openWorkspace(hash = "") {
  page(hash);
  await userEvent.type(screen.getByLabelText(ru.executor.confirm.code, { selector: "#cs-code" }), "123456");
  await userEvent.click(screen.getByRole("button", { name: C.open }));
}
const bearer = (c: Call) => new Headers(c.init.headers).get("Authorization");

describe("the workspace", () => {
  it("opens with one code and one ticket, then uses only its bearer token; titles are text", async () => {
    await openWorkspace();
    await screen.findByTestId(`cs-row-${ID}`);
    expect(calls[0].body).toEqual({ totp: "123456", ticket: "ticket-1" });
    expect(calls[1].url).toBe("/x/changesets/list");
    expect(bearer(calls[1])).toBe("Bearer ws-1");
    expect(calls[1].body).toEqual({});
    expect(calls[1].body.ticket).toBeUndefined();
    expect(screen.getByTestId(`cs-row-${ID}`)).toHaveTextContent("<img src=x onerror=alert(1)> vlan 120");
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByTestId("cs-status")).toHaveTextContent(C.status.draft);
  });

  it("goes back to the code when the token is gone", async () => {
    answers["/x/changesets/list"] = () => json(401, { error: { code: "no_workspace" } });
    await openWorkspace();
    expect(await screen.findByTestId("cs-open")).toHaveTextContent(C.refused.no_workspace);
  });
});

describe("the editor", () => {
  it("picks devices from the executor's writable list, sets variables per device and saves exactly that content", async () => {
    answers["/x/changesets/devices"] = () =>
      json(200, { result: [{ device_id: 12, address: "10.0.0.12:22", write_group: "access", line: "mes6" }, { device_id: 14, address: "10.0.0.14:22", write_group: "access", line: "mes10" }] });
    answers["/x/changesets/save"] = () => json(200, { result: { changeset_id: ID, revision: 1 } });
    answers["/x/changesets/get"] = () => json(200, { result: detail() });
    await openWorkspace();
    await userEvent.click(await screen.findByTestId("cs-new"));
    await userEvent.type(screen.getByLabelText(C.editor.name), "vlan 120");
    await userEvent.click(await screen.findByTestId("pick-14"));
    await userEvent.click(screen.getByTestId("pick-12"));
    expect(within(screen.getByTestId("cs-order")).getAllByRole("listitem")[0]).toHaveTextContent(C.canary);
    await userEvent.click(screen.getByRole("button", { name: C.editor.paste }));
    await userEvent.type(screen.getByRole("textbox", { name: C.editor.paste }), "configure{enter}interface {{{{cfg}}");
    await userEvent.click(screen.getByRole("button", { name: C.editor.pasteAdd }));
    await userEvent.type(screen.getByLabelText("cfg 14"), "gi0/2");
    await userEvent.type(screen.getByLabelText("cfg 12"), "gi1/0/2");
    await userEvent.click(screen.getByRole("button", { name: C.editor.addForm }));
    await userEvent.click(screen.getByTestId("cs-save"));
    await screen.findByTestId("cs-detail");
    const save = calls.find((c) => c.url === "/x/changesets/save")!;
    expect(bearer(save)).toBe("Bearer ws-1");
    expect(save.body).toEqual({
      changeset_id: "", revision: 0,
      content: { title: "vlan 120", device_ids: [14, 12], batch_size: 5, settle_s: 30, vars: { 14: { cfg: "gi0/2" }, 12: { cfg: "gi1/0/2" } },
        steps: [{ line: "configure" }, { line: "interface {{cfg}}" }, { form: { kind: "interface-description", interface: "", description: "", up: true, vlan: 0, name: "" } }] },
    });
  });

  it("shows a refusal with the device, step and the executor's reason", async () => {
    answers["/x/changesets/devices"] = () => json(200, { result: [{ device_id: 12, address: "10.0.0.12:22", write_group: "access", line: "mes6" }] });
    answers["/x/changesets/save"] = () => json(422, { error: { code: "bad_line", detail: { device_id: 12, step: 2, reason: "line 2: unknown command" } } });
    await openWorkspace();
    await userEvent.click(await screen.findByTestId("cs-new"));
    await userEvent.type(screen.getByLabelText(C.editor.name), "x");
    await userEvent.click(await screen.findByTestId("pick-12"));
    await userEvent.type(screen.getByLabelText(C.stepN.replace("{{n}}", "1")), "hostnam x");
    await userEvent.click(screen.getByTestId("cs-save"));
    expect(await screen.findByTestId("failure")).toHaveTextContent(C.refused.bad_line);
    expect(screen.getByTestId("failure-detail")).toHaveTextContent("Устройство 12 · шаг 2 · line 2: unknown command");
  });

  it("a restore from the panel's fragment prefills the device and its version, picked from the executor's metadata", async () => {
    answers["/x/changesets/devices"] = () => json(200, { result: [{ device_id: 12, address: "10.0.0.12:22", write_group: "access", line: "mes6" }] });
    answers["/x/changesets/versions"] = () => json(200, { result: [{ version_id: 345, taken_at: NOW, source: "pre_session", sha256: PLAN, size: 900 }, { version_id: 300, taken_at: NOW, source: "schedule", sha256: H, size: 880 }] });
    answers["/x/changesets/save"] = () => json(200, { result: { changeset_id: ID, revision: 1 } });
    answers["/x/changesets/get"] = () => json(200, { result: detail({ kind: "restore", content: { title: "r", device_ids: [12], restore: [{ device_id: 12, version_id: 345 }], batch_size: 5, settle_s: 30 } }) });
    await openWorkspace("#restore=12:345");
    expect(await screen.findByTestId("version-12")).toHaveValue("345");
    expect(calls.find((c) => c.url === "/x/changesets/versions")!.body).toEqual({ device_id: 12 });
    expect(screen.getByLabelText(C.editor.name)).toHaveValue("Восстановление #12");
    await userEvent.clear(screen.getByLabelText(C.editor.name));
    await userEvent.type(screen.getByLabelText(C.editor.name), "back");
    await userEvent.click(screen.getByTestId("cs-save"));
    await screen.findByTestId("cs-detail");
    expect(calls.find((c) => c.url === "/x/changesets/save")!.body.content).toEqual({ title: "back", device_ids: [12], batch_size: 5, settle_s: 30, restore: [{ device_id: 12, version_id: 345 }] });
  });
});

describe("dry-run", () => {
  it("shows each device's refusal with its line, and the equivalent commands as text", async () => {
    answers["/x/changesets/get"] = () =>
      json(200, {
        result: detail({
          status: "dry_run_failed",
          dry_run: {
            running: false,
            result: {
              revision: 1, ok: false, plan_sha256: PLAN,
              devices: [
                { device_id: 12, address: "10.0.0.12:22", write_group: "access", line: "mes6", pre_sha256: PLAN, ok: true },
                { device_id: 14, address: "10.0.0.14:22", write_group: "access", line: "mes10", ok: false, refused: { code: "not_safe", step: 3, line: 3, class: "dangerous", reason: "mgmt_interface" } },
              ],
              preview: [{ device_ids: [12], lines: ["configure", "interface gi1/0/2", "description <b>x</b>"], contexts: [] }],
            },
          },
        }),
      });
    await openWorkspace(`#changeset=${ID}`);
    expect(await screen.findByTestId("dry-run-outcome")).toHaveTextContent("Отказ на устройствах: 1 из 2");
    expect(screen.getByTestId("refused-14")).toHaveTextContent(`${C.deviceRefused.not_safe}шаг 3, строка 3dangerousmgmt_interface`);
    expect(screen.getAllByTestId("equivalent-line").map((e) => e.textContent)).toEqual(["configure", "interface gi1/0/2", "description <b>x</b>"]);
    expect(document.querySelector("b")).toBeNull();
    expect(screen.queryByTestId("cs-approve")).toBeNull();
  });

  it("starts with the revision and polls progress until it ends", async () => {
    let n = 0;
    answers["/x/changesets/get"] = () => json(200, { result: detail() });
    answers["/x/changesets/dry-run"] = () => json(200, { result: { started: true, revision: 1 } });
    answers["/x/changesets/progress"] = () =>
      json(200, { result: detail(++n < 2 ? { dry_run: { running: true } } : { status: "dry_run_ok", dry_run: { running: false, result: { revision: 1, ok: true, plan_sha256: PLAN, devices: [], preview: null } } }) });
    await openWorkspace(`#changeset=${ID}`);
    await userEvent.click(await screen.findByTestId("cs-dry-run-button"));
    expect(calls.find((c) => c.url === "/x/changesets/dry-run")!.body).toEqual({ changeset_id: ID, revision: 1 });
    await screen.findByTestId("dry-run-running");
    expect(await screen.findByTestId("cs-approve", {}, { timeout: 4000 })).toBeInTheDocument();
  });
});

describe("approval", () => {
  const fields = [
    { key: "author", value: "7 alice" }, { key: "batch_size", value: "1" }, { key: "canary", value: "12" }, { key: "changeset", value: ID }, { key: "groups", value: "access" },
    { key: "kind", value: "lines" }, { key: "plan_sha256", value: PLAN }, { key: "revision", value: "1" }, { key: "settle_s", value: "30" }, { key: "title", value: "vlan 120" },
  ];
  const issue = () => json(200, { challenge_id: "c-1", action: "changeset.approve", h: H, fields, expires: NOW });

  it("shows H and every field, takes the typed device count and the code, and never resends a spent code", async () => {
    answers["/x/changesets/get"] = () => json(200, { result: detail({ status: "dry_run_ok" }) });
    answers["/x/changesets/progress"] = answers["/x/changesets/get"];
    answers["/x/confirm/issue"] = issue;
    answers[`/x/changesets/${ID}/approve/3`] = () => json(422, { error: { code: "device_count" } });
    answers[`/x/changesets/${ID}/approve/2`] = () => json(200, { result: { status: "running" } });
    await openWorkspace(`#changeset=${ID}`);
    await userEvent.click(await screen.findByTestId("cs-approve"));
    await userEvent.click(screen.getByTestId("approve-issue"));
    expect(calls.find((c) => c.url === "/x/confirm/issue")!.body).toEqual({ action: "changeset.approve", params: { changeset_id: ID }, ticket: "ticket-2" });
    expect(await screen.findByTestId("h")).toHaveTextContent(`H: ${H}`);
    expect(screen.getByTestId("field-plan_sha256")).toHaveTextContent(PLAN);
    const confirm = screen.getByRole("button", { name: C.approve.confirm });
    await userEvent.type(screen.getByLabelText(ru.executor.confirm.code, { selector: "#cp-code" }), "111111");
    expect(confirm).toBeDisabled(); /* no device count yet */
    await userEvent.type(screen.getByLabelText(C.approve.count, { exact: false }), "3");
    await userEvent.click(confirm);
    expect(await screen.findByTestId("approve-failure")).toHaveTextContent(C.refused.device_count);
    const sent = calls.find((c) => c.url === `/x/changesets/${ID}/approve/3`)!;
    expect(sent.body).toEqual({ challenge_id: "c-1", h: H, code: "111111", ticket: "ticket-3" });
    /* the challenge is spent: describe again, the same code is refused locally */
    await userEvent.click(screen.getByTestId("approve-issue"));
    await userEvent.type(await screen.findByLabelText(C.approve.count, { exact: false }), "2");
    await userEvent.type(screen.getByLabelText(ru.executor.confirm.code, { selector: "#cp-code" }), "111111");
    await userEvent.click(screen.getByRole("button", { name: C.approve.confirm }));
    expect(await screen.findByTestId("approve-failure")).toHaveTextContent(ru.executor.error.code_reused);
    await userEvent.type(screen.getByLabelText(ru.executor.confirm.code, { selector: "#cp-code" }), "222222");
    await userEvent.type(screen.getByLabelText(C.approve.count, { exact: false }), "2");
    await userEvent.click(screen.getByRole("button", { name: C.approve.confirm }));
    await waitFor(() => expect(screen.queryByTestId("approve-dialog")).toBeNull());
    expect(screen.getByText(C.approve.started)).toBeInTheDocument();
  });

  it("refuses a description of another revision", async () => {
    answers["/x/changesets/get"] = () => json(200, { result: detail({ status: "dry_run_ok", revision: 2 }) });
    answers["/x/confirm/issue"] = issue;
    await openWorkspace(`#changeset=${ID}`);
    await userEvent.click(await screen.findByTestId("cs-approve"));
    await userEvent.click(screen.getByTestId("approve-issue"));
    expect(await screen.findByTestId("approve-failure")).toHaveTextContent(C.approve.mismatch);
    expect(screen.queryByTestId("h")).toBeNull();
  });

  it("the author waits; another user sees who authored it and approves as the second person", async () => {
    const approved = detail({ status: "approved", events: [{ revision: 1, at: NOW, kind: "approved", payload: { by: 7, until: "2026-11-11T10:30:00Z" } }] });
    answers["/x/changesets/get"] = () => json(200, { result: approved });
    await openWorkspace(`#changeset=${ID}`);
    expect(await screen.findByTestId("awaiting-second")).toHaveTextContent("Ждёт одобрения второго лица до");
    expect(screen.queryByTestId("cs-approve-second")).toBeNull();
    expect(screen.queryByTestId("cs-approve")).toBeNull();
  });

  it("a second person is told whose changeset they approve", async () => {
    answers["/x/changesets/open"] = () => json(200, { result: { token: "ws-2", expires: NOW, idle_seconds: 600, user_id: 9, username: "bob" } });
    answers["/x/changesets/get"] = () => json(200, { result: detail({ status: "approved" }) });
    answers["/x/confirm/issue"] = issue;
    await openWorkspace(`#changeset=${ID}`);
    await userEvent.click(await screen.findByTestId("cs-approve-second"));
    expect(screen.getByTestId("approve-role")).toHaveTextContent("Автор: alice (id 7). Вы одобряете как второе лицо.");
    await userEvent.click(screen.getByTestId("approve-issue"));
    expect(await screen.findByRole("button", { name: C.approve.confirmSecond })).toBeInTheDocument();
  });
});

describe("the run", () => {
  it("shows the canary and batches with each device's state, and «Стоп» says it rolls back", async () => {
    answers["/x/changesets/get"] = () =>
      json(200, {
        result: detail({
          status: "running",
          run: { phase: "batch 1", devices: [{ device_id: 12, state: "applied", lines_sent: 3, session_id: ID }, { device_id: 14, state: "opened", lines_sent: 1 }] },
        }),
      });
    answers["/x/changesets/progress"] = answers["/x/changesets/get"];
    answers["/x/changesets/stop"] = () => json(200, { result: { stopping: true } });
    await openWorkspace(`#changeset=${ID}`);
    expect(await screen.findByTestId("run-phase")).toHaveTextContent("Батч 1");
    expect(screen.getByTestId("run-12")).toHaveAttribute("data-state", "applied");
    expect(within(screen.getByTestId("stage-0")).getByText(C.canary)).toBeInTheDocument();
    await userEvent.click(within(screen.getByTestId("run-12")).getByRole("button", { name: C.recording }));
    expect(onRecordings).toHaveBeenCalledWith(ID, 12);
    await userEvent.click(screen.getByTestId("cs-stop"));
    expect(screen.getByTestId("stop-dialog")).toHaveTextContent(C.stop.rule2);
    await userEvent.click(screen.getByTestId("cs-stop-confirm"));
    await waitFor(() => expect(calls.some((c) => c.url === "/x/changesets/stop")).toBe(true));
    expect(calls.find((c) => c.url === "/x/changesets/stop")!.body).toEqual({ changeset_id: ID });
  });

  it("an interrupted run says nothing was rolled back and offers a restore of the pre-session versions", async () => {
    answers["/x/changesets/get"] = () =>
      json(200, { result: detail({ status: "interrupted", events: [{ revision: 1, at: NOW, kind: "interrupted", payload: { reason: "restart", pre_session_versions: { 12: 501 } } }] }) });
    answers["/x/changesets/devices"] = () => json(200, { result: [{ device_id: 12, address: "10.0.0.12:22", write_group: "access", line: "mes6" }] });
    answers["/x/changesets/versions"] = () => json(200, { result: [{ version_id: 501, taken_at: NOW, source: "pre_session", sha256: PLAN, size: 1 }] });
    await openWorkspace(`#changeset=${ID}`);
    expect(await screen.findByTestId("run-outcome")).toHaveTextContent(C.outcome.interrupted);
    expect(screen.getByTestId("run-outcome")).toHaveTextContent("#14: версия до сессии нет");
    await userEvent.click(screen.getByTestId("cs-restore-interrupted"));
    expect(await screen.findByTestId("version-12")).toHaveValue("501");
  });
});

describe("helpers", () => {
  it("parses the panel's fragment strictly", () => {
    expect(parseChangesetPreset(`#changeset=${ID}`)).toEqual({ section: true, changeset: ID, restore: undefined });
    expect(parseChangesetPreset("#restore=12:345")).toEqual({ section: true, changeset: undefined, restore: { device: 12, version: 345 } });
    expect(parseChangesetPreset("#view=changesets")).toEqual({ section: true, changeset: undefined, restore: undefined });
    expect(parseChangesetPreset("#changeset=../x&restore=0:1")).toEqual({ section: false, changeset: undefined, restore: undefined });
  });
  it("groups the run like the executor and finds the variables", () => {
    expect(stages([1, 2, 3, 4, 5], 2)).toEqual([[1], [2, 3], [4, 5]]);
    expect(variablesOf([{ line: "interface {{port}}" }, { line: "{{cfg}} {{port}}" }, {}])).toEqual(["port", "cfg"]);
  });
});
