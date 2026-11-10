import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import ru from "../i18n/ru.json";
import { createPoster } from "../client";
import { SessionApp } from "./SessionApp";
import { SessionView } from "./SessionView";

/* jsdom has no IntersectionObserver v2: the visibility gate is driven by the test */
const vis = vi.hoisted(() => ({ unobscured: true }));
vi.mock("../useUnobscured", () => ({ useUnobscured: () => ({ ref: () => {}, unobscured: vis.unobscured, supported: true }) }));

const S = ru.executor.session;
const SID = "3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c";
const H = "9c".repeat(32);
const PRE = "a1".repeat(32);
const CUR = "5e".repeat(32);
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const opened = (over: Record<string, unknown> = {}) => ({
  result: { session_id: SID, token: "tok-1", expires: new Date(Date.now() + 30 * 60_000).toISOString(), idle_seconds: 600,
    devices: [{ device_id: 12, line: "mes6", pre_sha256: PRE, address: "10.0.0.12:22", write_group: "access", model: "MES2324", firmware: "6.6.2" },
      { device_id: 14, line: "esr", pre_sha256: PRE, address: "10.0.0.14:22", write_group: "branch", model: "ESR-20", firmware: "1.30.2" }], ...over },
});
const diff = (device: number, over: Record<string, unknown> = {}) => ({ device_id: device, line: device === 14 ? "esr" : "mes6", pre_sha256: PRE, sha256: CUR,
  diff: "--- pre-session\n+++ running\n@@ -1 +1 @@\n-a\n+b\n", ...over });

class FakeWS {
  readyState = 0;
  sent: Record<string, unknown>[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(readonly url: string) {
    sockets.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.();
    });
  }
  send(d: string) {
    this.sent.push(JSON.parse(d) as Record<string, unknown>);
  }
  close() {
    this.readyState = 3;
  }
  push(m: unknown) {
    act(() => this.onmessage?.({ data: JSON.stringify(m) }));
  }
  frames(type: string) {
    return this.sent.filter((f) => f.type === type);
  }
}
let sockets: FakeWS[];
const factory = (u: string) => new FakeWS(u) as unknown as WebSocket;

type Call = { url: string; init: RequestInit; body: Record<string, unknown> };
let calls: Call[];
let answers: Record<string, (c: Call) => Response>;
let tickets: number;
beforeEach(() => {
  vis.unobscured = true;
  sockets = [];
  calls = [];
  tickets = 0;
  answers = {};
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
const onOpenChange = vi.fn();
function app() {
  return render(<SessionApp poster={poster()} preset={[12, 14]} compact={false} onOpenChange={onOpenChange} onExpand={vi.fn()} onRecordings={vi.fn()} open={factory} />);
}
const sock = (device: number) => sockets.find((s) => s.sent[0]?.device_id === device)!;
const headers = (c: Call) => new Headers(c.init.headers);

async function openSession() {
  answers["/x/sessions"] = () => json(200, opened());
  app();
  await userEvent.type(screen.getByLabelText(ru.executor.confirm.code, { selector: "#ss-code" }), "123456");
  await userEvent.click(screen.getByRole("button", { name: S.start.open }));
  await screen.findByTestId("session-view");
  await waitFor(() => expect(sockets.every((s) => s.sent.length > 0)).toBe(true));
}

describe("opening a session", () => {
  it("sends the code once with one fresh ticket and connects every device with the token in the first frame only", async () => {
    await openSession();
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toEqual({ totp: "123456", device_ids: [12, 14], ticket: "ticket-1" });
    expect(calls[0].init.credentials).toBe("omit");
    expect(sockets).toHaveLength(2);
    for (const s of sockets) {
      expect(s.url).not.toContain("tok-1");
      expect(s.sent[0]).toMatchObject({ type: "auth", session_id: SID, token: "tok-1" });
    }
    expect(sockets.map((s) => s.sent[0].device_id).sort()).toEqual([12, 14]);
    expect(screen.getByTestId("tab-12")).toHaveTextContent("MES 6.x");
    expect(screen.getByTestId("tab-14")).toHaveTextContent("ESR");
    expect(onOpenChange).toHaveBeenLastCalledWith(true);
    expect(screen.getByTestId("timer")).toHaveTextContent(/Осталось (29:5\d|30:00)/);
  });

  it("shows a refusal in plain words and never sends the same code twice", async () => {
    answers["/x/sessions"] = () => json(422, { error: { code: "not_exclusive" } });
    app();
    const code = screen.getByLabelText(ru.executor.confirm.code, { selector: "#ss-code" });
    await userEvent.type(code, "123456");
    await userEvent.click(screen.getByRole("button", { name: S.start.open }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("откат недоступен, очистите кандидат на устройстве");
    expect(code).toHaveValue("");
    await userEvent.type(code, "123456");
    await userEvent.click(screen.getByRole("button", { name: S.start.open }));
    expect(await screen.findByTestId("failure")).toHaveTextContent(ru.executor.error.code_reused);
    expect(calls).toHaveLength(1);
    expect(tickets).toBe(1);
  });

  it("maps a lock to its end", async () => {
    answers["/x/sessions"] = () => json(423, { error: { code: "locked", until: "2026-11-10T10:00:00Z" } });
    app();
    await userEvent.type(screen.getByLabelText(ru.executor.confirm.code, { selector: "#ss-code" }), "123456");
    await userEvent.click(screen.getByRole("button", { name: S.start.open }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Вход заблокирован до");
  });
});

describe("which devices the session is on (review 4c.6 I2)", () => {
  it("says before the code that the ids are the panel's, and right after the open shows the registry's address of each", async () => {
    answers["/x/sessions"] = () => json(200, opened());
    app();
    expect(screen.getByTestId("preset-note")).toHaveTextContent("только ID устройств, которые запросила панель");
    expect(document.body).not.toHaveTextContent("10.0.0.12");
    await userEvent.type(screen.getByLabelText(ru.executor.confirm.code, { selector: "#ss-code" }), "123456");
    await userEvent.click(screen.getByRole("button", { name: S.start.open }));
    const on = await screen.findByTestId("opened-on");
    expect(within(on).getByTestId("opened-12")).toHaveTextContent("№12 — 10.0.0.12:22, группа записи access, MES2324");
    expect(within(on).getByTestId("opened-14")).toHaveTextContent("10.0.0.14:22");
    expect(screen.getByTestId("tab-12")).toHaveTextContent("10.0.0.12:22");
    /* a wrong device: end it from there */
    await userEvent.click(within(on).getByRole("button", { name: S.actions.end }));
    expect(await screen.findByTestId("end-dialog")).toBeInTheDocument();
  });

  it("the end of a session is gated like a confirm", async () => {
    await openSession();
    await userEvent.click(within(screen.getByTestId("session-view")).getAllByRole("button", { name: S.actions.end })[0]);
    const dlg = await screen.findByTestId("end-dialog");
    vis.unobscured = false;
    sock(12).push({ type: "edit", text: "", cursor: 0, prompt: "#" });
    await userEvent.click(screen.getByTestId("tab-14"));
    expect(within(dlg).getByRole("button", { name: S.end.confirm })).toBeDisabled();
  });

  it("names the devices with their registry address in the compact strip", async () => {
    render(<SessionView poster={poster()} opened={opened().result} token="tok-1" compact onExpand={vi.fn()} onUpdate={vi.fn()} onEnded={vi.fn()} open={factory} />);
    expect(screen.getByTestId("compact-devices")).toHaveTextContent("№12 10.0.0.12:22, №14 10.0.0.14:22");
  });
});

describe("terminal", () => {
  it("renders device text only as text", async () => {
    await openSession();
    sock(12).push({ type: "output", sent: "show x", text: "<img src=x onerror=alert(1)><b>bold</b>", limited: false, prompt: "sw#" });
    const term = within(screen.getByTestId("device-term-12")).getByTestId("terminal");
    expect(term).toHaveTextContent("<img src=x onerror=alert(1)><b>bold</b>");
    expect(term.querySelector("img, b")).toBeNull();
  });

  it("a dangerous line needs the challenge, the exact device name and a new code, each step with its own ticket", async () => {
    await openSession();
    const s = sock(12);
    s.push({ type: "dangerous", line: "shutdown", reason: "mgmt" });
    const dlg = await screen.findByTestId("dangerous-dialog");
    expect(within(dlg).getByTestId("dangerous-line")).toHaveTextContent("shutdown");
    await userEvent.click(within(dlg).getByRole("button", { name: S.dangerous.issue }));
    await waitFor(() => expect(s.frames("dangerous_issue")).toEqual([{ type: "dangerous_issue", ticket: "ticket-2" }]));
    s.push({ type: "challenge", challenge_id: "c9", action: "session.line", h: H, expires: "x", fields: [
      { key: "address", value: "10.0.0.12:22" }, { key: "device", value: "sw-a3" }, { key: "device_id", value: "12" },
      { key: "line", value: "shutdown" }, { key: "mode", value: "config-if" }, { key: "session", value: SID }] });
    expect(await within(dlg).findByTestId("field-address")).toHaveTextContent("10.0.0.12:22");
    expect(within(dlg).getByTestId("h")).toHaveTextContent(H);
    const send = within(dlg).getByRole("button", { name: S.dangerous.send });
    await userEvent.type(within(dlg).getByLabelText(ru.executor.confirm.code), "654321");
    expect(send).toBeDisabled();
    await userEvent.type(within(dlg).getByLabelText(S.dangerous.typeName), "SW-A3");
    expect(send).toBeDisabled();
    expect(within(dlg).getByTestId("name-mismatch")).toBeInTheDocument();
    await userEvent.clear(within(dlg).getByLabelText(S.dangerous.typeName));
    await userEvent.type(within(dlg).getByLabelText(S.dangerous.typeName), "sw-a3");
    expect(send).toBeEnabled();
    vis.unobscured = false;
    await userEvent.type(within(dlg).getByLabelText(S.dangerous.typeName), " ");
    await userEvent.type(within(dlg).getByLabelText(S.dangerous.typeName), "{Backspace}");
    expect(send).toBeDisabled();
    vis.unobscured = true;
    await userEvent.type(within(dlg).getByLabelText(S.dangerous.typeName), " {Backspace}");
    await userEvent.click(send);
    await waitFor(() => expect(s.frames("dangerous_confirm")).toEqual([
      { type: "dangerous_confirm", challenge_id: "c9", device_name: "sw-a3", totp: "654321", ticket: "ticket-3" }]));
    /* the executor refuses the code: the line is spent, a notice says so */
    s.push({ type: "refused", code: "denied" });
    await waitFor(() => expect(screen.queryByTestId("dangerous-dialog")).toBeNull());
    expect(screen.getByTestId("term-notice")).toHaveTextContent(S.term.denied);
    /* the same code cannot be sent for the next dangerous line */
    s.push({ type: "dangerous", line: "shutdown", reason: "mgmt" });
    await userEvent.click(await screen.findByRole("button", { name: S.dangerous.issue }));
    s.push({ type: "challenge", challenge_id: "c10", action: "session.line", h: H, expires: "x", fields: [{ key: "device", value: "sw-a3" }] });
    const dlg2 = screen.getByTestId("dangerous-dialog");
    await userEvent.type(await within(dlg2).findByLabelText(S.dangerous.typeName), "sw-a3");
    await userEvent.type(within(dlg2).getByLabelText(ru.executor.confirm.code), "654321");
    await userEvent.click(within(dlg2).getByRole("button", { name: S.dangerous.send }));
    expect(await within(dlg2).findByText(ru.executor.error.code_reused)).toBeInTheDocument();
    expect(s.frames("dangerous_confirm")).toHaveLength(1);
  });

  it("cancelling a dangerous line sends Ctrl-C", async () => {
    await openSession();
    const s = sock(12);
    s.push({ type: "dangerous", line: "reload", reason: "grammar" });
    await userEvent.click(await screen.findByRole("button", { name: S.dangerous.drop }));
    expect(s.frames("keys")).toEqual([{ type: "keys", data: "\x03" }]);
    expect(screen.queryByTestId("dangerous-dialog")).toBeNull();
  });

  it("a held paste is shown as text and goes only when accepted while visible", async () => {
    await openSession();
    const s = sock(12);
    s.push({ type: "paste_pending", text: "vlan 10\nvlan 20\n<script>x</script>\n", lines: 3 });
    const dlg = await screen.findByTestId("paste-dialog");
    expect(within(dlg).getByTestId("paste-text")).toHaveTextContent("<script>x</script>");
    expect(dlg.querySelector("script")).toBeNull();
    vis.unobscured = false;
    s.push({ type: "edit", text: "", cursor: 0, prompt: "#" });
    expect(within(screen.getByTestId("paste-dialog")).getByRole("button", { name: /Вставить/ })).toBeDisabled();
    vis.unobscured = true;
    s.push({ type: "edit", text: "", cursor: 0, prompt: "#" });
    await userEvent.click(within(screen.getByTestId("paste-dialog")).getByRole("button", { name: /Вставить \(строк: 3\)/ }));
    expect(s.frames("paste_confirm")).toEqual([{ type: "paste_confirm", accept: true }]);
  });

  it("a typed save opens the save flow with the diff the executor sent", async () => {
    await openSession();
    sock(12).push({ type: "flow", flow: "save", diff: diff(12) });
    expect(await screen.findByTestId("save-dialog")).toHaveTextContent("+b");
  });
});

describe("session actions", () => {
  it("save names the hash of the diff shown, with the bearer token and no ticket", async () => {
    await openSession();
    answers[`/x/sessions/${SID}/diff`] = () => json(200, { result: [diff(12), diff(14)] });
    answers[`/x/sessions/${SID}/save`] = () => json(200, { result: diff(12, { pre_sha256: CUR }) });
    await userEvent.click(screen.getByTestId("save-button"));
    const dlg = await screen.findByTestId("save-dialog");
    await userEvent.click(within(dlg).getByRole("button", { name: S.save.confirm }));
    await waitFor(() => expect(screen.queryByTestId("save-dialog")).toBeNull());
    const save = calls.find((c) => c.url.endsWith("/save"))!;
    expect(save.body).toEqual({ device_id: 12, sha256: CUR });
    expect(headers(save).get("Authorization")).toBe("Bearer tok-1");
    expect(tickets).toBe(1); /* only the open asked for one */
    expect(screen.getByText(S.save.done.replace("{{id}}", "12"))).toBeInTheDocument();
  });

  it("forms show the equivalent commands exactly and apply only those lines", async () => {
    await openSession();
    const lines = ["configure", "interface gigabitethernet1/0/7", 'description "<b>x</b>"', "end"];
    answers[`/x/sessions/${SID}/form`] = () => json(200, { result: { device_id: 12, lines } });
    answers[`/x/sessions/${SID}/form-apply`] = () => json(200, { result: { sent: 4, diff: diff(12) } });
    const panel = screen.getByTestId("form-panel");
    expect(panel.querySelector("form")).toBeNull();
    for (const i of panel.querySelectorAll("input, select")) expect(i).toHaveAttribute("autocomplete", "off");
    await userEvent.type(within(panel).getByLabelText(S.form.field.interface), "gigabitethernet1/0/7");
    await userEvent.type(within(panel).getByLabelText(S.form.field.description), "<b>x</b>");
    await userEvent.click(within(panel).getByRole("button", { name: S.form.render }));
    expect((await within(panel).findAllByTestId("equivalent-line")).map((e) => e.textContent)).toEqual(lines);
    expect(calls.at(-1)!.body).toEqual({ device_id: 12, form: { kind: "interface-description", interface: "gigabitethernet1/0/7", description: "<b>x</b>", up: true, vlan: 0, name: "" } });
    /* changing a field drops the lines shown */
    await userEvent.type(within(panel).getByLabelText(S.form.field.description), "!");
    expect(within(panel).queryByTestId("equivalent")).toBeNull();
    await userEvent.type(within(panel).getByLabelText(S.form.field.description), "{Backspace}");
    await userEvent.click(within(panel).getByRole("button", { name: S.form.render }));
    await userEvent.click(await within(panel).findByRole("button", { name: /Применить/ }));
    await waitFor(() => expect(calls.at(-1)!.url).toBe(`/x/sessions/${SID}/form-apply`));
    expect(calls.at(-1)!.body.lines).toEqual(lines);
    expect(await within(panel).findByText(S.form.applied.replace("{{sent}}", "4"))).toBeInTheDocument();
  });

  it("rollback shows every field of the description and H, and confirms with a new code and a fresh ticket", async () => {
    await openSession();
    const fields = [{ key: "address_12", value: "10.0.0.12:22" }, { key: "address_14", value: "10.0.0.14:22" }, { key: "devices", value: "12,14" },
      { key: "groups", value: "g1" }, { key: "pre_sha256_12", value: PRE }, { key: "pre_sha256_14", value: PRE }, { key: "session", value: SID },
      { key: "state_12", value: "open" }, { key: "state_14", value: "commit_pending" }];
    answers["/x/confirm/issue"] = () => json(200, { challenge_id: "r1", action: "session.rollback", h: H, fields, expires: "x" });
    answers["/x/confirm"] = () => json(200, { action: "session.rollback", result: { devices: [{ device_id: 12, sha256: PRE }, { device_id: 14, error: "commit_timer" }] } });
    await userEvent.click(screen.getAllByRole("button", { name: S.actions.rollback })[0]);
    await userEvent.click(screen.getByRole("button", { name: S.rollback.issue }));
    const dlg = await screen.findByTestId("rollback-dialog");
    expect(calls.at(-1)!.body).toEqual({ action: "session.rollback", params: { session_id: SID }, ticket: "ticket-2" });
    for (const f of fields) expect(await within(dlg).findByTestId(`field-${f.key}`)).toHaveTextContent(f.value);
    /* one row per device: its registry address, state and full pre-session hash */
    expect(within(dlg).getByTestId("rollback-row-14")).toHaveTextContent(`10.0.0.14:22commit_pending`);
    expect(within(within(dlg).getByTestId("rollback-row-14")).getByTestId("field-pre_sha256_14")).toHaveTextContent(PRE);
    expect(within(dlg).getByTestId("field-state_14")).toHaveTextContent(S.rollback.state.commit_pending);
    expect(within(dlg).getByTestId("h")).toHaveTextContent(H);
    await userEvent.type(within(dlg).getByLabelText(ru.executor.confirm.code), "111222");
    vis.unobscured = false;
    await userEvent.type(within(dlg).getByLabelText(ru.executor.confirm.code), "{Backspace}2");
    expect(within(dlg).getByRole("button", { name: S.rollback.confirm })).toBeDisabled();
    vis.unobscured = true;
    await userEvent.type(within(dlg).getByLabelText(ru.executor.confirm.code), "{Backspace}2");
    await userEvent.click(within(dlg).getByRole("button", { name: S.rollback.confirm }));
    expect(await within(dlg).findByTestId("rollback-result")).toHaveTextContent(S.refused.commit_timer);
    expect(calls.at(-1)!.body).toEqual({ challenge_id: "r1", h: H, code: "111222", ticket: "ticket-3" });
  });

  it("extend asks a new code; end closes with the bearer token; the panel learns the session is closed", async () => {
    await openSession();
    answers[`/x/sessions/${SID}/extend`] = () => json(200, opened({ token: undefined, expires: new Date(Date.now() + 60 * 60_000).toISOString() }));
    answers[`/x/sessions/${SID}/close`] = () => json(200, { result: { closed: true } });
    await userEvent.click(screen.getByRole("button", { name: S.actions.extend }));
    await userEvent.type(within(screen.getByTestId("extend-dialog")).getByLabelText(ru.executor.confirm.code), "777888");
    await userEvent.click(within(screen.getByTestId("extend-dialog")).getByRole("button", { name: S.extend.confirm }));
    await waitFor(() => expect(screen.getByTestId("timer")).toHaveTextContent(/Осталось (59:5\d|1:00:00)/));
    expect(calls.at(-1)!.body).toEqual({ totp: "777888", ticket: "ticket-2" });
    await userEvent.click(within(screen.getByTestId("session-view")).getAllByRole("button", { name: S.actions.end })[0]);
    await userEvent.click(screen.getByRole("button", { name: S.end.confirm }));
    expect(await screen.findByTestId("session-ended")).toHaveTextContent(S.ended.closed);
    const close = calls.at(-1)!;
    expect(close.body).toEqual({});
    expect(headers(close).get("Authorization")).toBe("Bearer tok-1"); /* the token of the open: extend gave none */
    expect(onOpenChange).toHaveBeenLastCalledWith(false);
  });

  it("a gone session ends the screen and keeps the rollback offered", async () => {
    await openSession();
    answers[`/x/sessions/${SID}/diff`] = () => json(401, { error: { code: "no_token" } });
    await userEvent.click(screen.getAllByRole("button", { name: S.actions.diff })[0]);
    const ended = await screen.findByTestId("session-ended");
    expect(ended).toHaveTextContent(S.ended.gone);
    expect(within(ended).getByRole("button", { name: S.actions.rollback })).toBeInTheDocument();
  });
});

describe("ESR commit", () => {
  it("shows the countdown of the device's timer and no confirm within its last 15 s", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let now = Date.parse("2026-11-10T10:00:00Z");
    const o = opened().result;
    answers[`/x/sessions/${SID}/commit`] = () => json(200, { result: diff(14, { commit_pending_until: "2026-11-10T10:02:00Z" }) });
    render(<SessionView poster={poster()} opened={{ ...o, expires: "2026-11-10T10:30:00Z" }} token="tok-1" compact={false} onExpand={vi.fn()} onUpdate={vi.fn()} onEnded={vi.fn()}
      now={() => now} open={factory} />);
    await userEvent.click(screen.getByTestId("tab-14"));
    await userEvent.click(screen.getByRole("button", { name: S.actions.commit }));
    /* the commit is gated like a confirm */
    const commitDialog = await screen.findByTestId("commit-dialog");
    vis.unobscured = false;
    await userEvent.click(screen.getByTestId("tab-12"));
    await userEvent.click(screen.getByTestId("tab-14"));
    expect(within(commitDialog).getByRole("button", { name: S.commit.confirm })).toBeDisabled();
    vis.unobscured = true;
    await userEvent.click(screen.getByTestId("tab-12"));
    await userEvent.click(screen.getByTestId("tab-14"));
    await userEvent.click(within(screen.getByTestId("commit-dialog")).getByRole("button", { name: S.commit.confirm }));
    const banner = await screen.findByTestId("esr-banner-14");
    expect(banner).toHaveTextContent("Устройство 14: конфигурация не подтверждена, автооткат через 120 с");
    expect(within(banner).getByRole("button", { name: S.esr.confirm })).toBeInTheDocument();
    act(() => {
      now += 106_000;
      vi.advanceTimersByTime(1000);
    });
    expect(banner).toHaveTextContent("автооткат через 14 с");
    expect(within(banner).queryByRole("button")).toBeNull();
    act(() => {
      now += 20_000;
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByTestId("esr-banner-14")).toHaveTextContent("таймер подтверждения истёк");
  });
});
