import { afterEach, describe, expect, it, vi } from "vitest";
import { BridgeError, createExecutorBridge } from "./bridge";

const PANEL = "https://nms.example.org";
const EXECUTOR = "https://nms.example.org:8443";
const ID = "0123456789abcdef0123456789abcdef";
const OTHER = "fedcba9876543210fedcba9876543210";

/* A window whose parent is a spy; events are dispatched by hand with the origin and source the test wants. */
function setup(opts: { embedded?: boolean; timeoutMs?: number } = {}) {
  const parent = { postMessage: vi.fn() };
  const self = new EventTarget() as EventTarget & { parent: unknown; location: { origin: string } };
  self.parent = opts.embedded === false ? self : parent;
  self.location = { origin: EXECUTOR };
  const bridge = createExecutorBridge({ panelOrigin: PANEL, self: self as unknown as Window, newId: () => ID, timeoutMs: opts.timeoutMs });
  const deliver = (data: unknown, origin = PANEL, source: unknown = parent) => self.dispatchEvent(Object.assign(new Event("message"), { data, origin, source }));
  return { parent, bridge, deliver };
}
const ticket = (over: Record<string, unknown> = {}) => ({ v: 1, type: "ticket", id: ID, ticket: "payload.signature", ...over });

afterEach(() => vi.useRealTimers());

describe("executor bridge", () => {
  it("asks the panel for a ticket with the exact targetOrigin and takes the answer from the exact origin", async () => {
    const { parent, bridge, deliver } = setup();
    const p = bridge.requestTicket();
    expect(parent.postMessage).toHaveBeenCalledWith({ v: 1, type: "status", state: "ticket_needed", id: ID }, PANEL);
    deliver(ticket());
    await expect(p).resolves.toBe("payload.signature");
  });

  it("tells the panel whether a session is open and asks it to expand the frame", () => {
    const { parent, bridge } = setup();
    bridge.session(true);
    bridge.expand();
    bridge.session(false);
    bridge.dialog(true);
    expect(parent.postMessage.mock.calls).toEqual([
      [{ v: 1, type: "status", state: "session", open: true }, PANEL],
      [{ v: 1, type: "status", state: "expand" }, PANEL],
      [{ v: 1, type: "status", state: "session", open: false }, PANEL],
      [{ v: 1, type: "status", state: "dialog", open: true }, PANEL],
    ]);
  });

  it("never posts to '*': every send names the panel origin", async () => {
    const { parent, bridge, deliver } = setup();
    bridge.ready();
    const p = bridge.requestTicket();
    deliver(ticket());
    await p;
    expect(parent.postMessage.mock.calls.length).toBe(2);
    for (const c of parent.postMessage.mock.calls) expect(c[1]).toBe(PANEL);
  });

  it.each([
    ["another origin", ticket(), "https://evil.example", undefined],
    ["a longer origin with the panel as prefix", ticket(), PANEL + ".evil.example", undefined],
    ["the same host on another port", ticket(), PANEL + ":8443", undefined],
    ["the panel over http", ticket(), "http://nms.example.org", undefined],
    ["the executor's own origin", ticket(), EXECUTOR, undefined],
    ["the opaque origin", ticket(), "null", undefined],
    ["another window of the panel origin", ticket(), PANEL, {}],
    ["an unknown field", ticket({ extra: 1 }), PANEL, undefined],
    ["a missing field", { v: 1, type: "ticket", id: ID }, PANEL, undefined],
    ["a wrong version", ticket({ v: 2 }), PANEL, undefined],
    ["a wrong type", ticket({ type: "status" }), PANEL, undefined],
    ["a ticket with whitespace", ticket({ ticket: "a b" }), PANEL, undefined],
    ["an empty ticket", ticket({ ticket: "" }), PANEL, undefined],
    ["an oversize ticket", ticket({ ticket: "a".repeat(1025) }), PANEL, undefined],
    ["a ticket for another request", ticket({ id: OTHER }), PANEL, undefined],
    ["a string", JSON.stringify(ticket()), PANEL, undefined],
    ["null", null, PANEL, undefined],
    ["an array", [ticket()], PANEL, undefined],
  ])("drops %s silently", async (_n, data, origin, source) => {
    const { parent, bridge, deliver } = setup();
    const p = bridge.requestTicket();
    parent.postMessage.mockClear();
    let settled = false;
    void p.then(
      () => (settled = true),
      () => (settled = true),
    );
    deliver(data, origin, source === undefined ? parent : source);
    await Promise.resolve();
    expect(settled).toBe(false);
    expect(parent.postMessage).not.toHaveBeenCalled(); /* never answered */
    deliver(ticket()); /* the genuine answer still works */
    await expect(p).resolves.toBe("payload.signature");
  });

  it("counts what it drops", () => {
    const { bridge, deliver } = setup();
    deliver(ticket(), "https://evil.example");
    deliver({ nope: 1 });
    expect(bridge.dropped).toBe(2);
  });

  it("hands a ticket out once: a repeat of it never satisfies a later request", async () => {
    const ids = [ID, OTHER];
    const parent = { postMessage: vi.fn() };
    const self = new EventTarget() as EventTarget & { parent: unknown };
    self.parent = parent;
    const bridge = createExecutorBridge({ panelOrigin: PANEL, self: self as unknown as Window, newId: () => ids.shift()! });
    const deliver = (data: unknown) => self.dispatchEvent(Object.assign(new Event("message"), { data, origin: PANEL, source: parent }));
    const first = bridge.requestTicket();
    deliver(ticket());
    await expect(first).resolves.toBe("payload.signature");
    deliver(ticket({ ticket: "late.repeat" })); /* nothing is waiting for it */
    const second = bridge.requestTicket();
    let settled = false;
    void second.then(() => (settled = true));
    deliver(ticket({ ticket: "late.repeat" })); /* the old request id */
    await Promise.resolve();
    expect(settled).toBe(false);
    deliver(ticket({ id: OTHER, ticket: "fresh.ticket" }));
    await expect(second).resolves.toBe("fresh.ticket");
  });

  it("one request at a time", async () => {
    const { bridge, deliver } = setup();
    const first = bridge.requestTicket();
    await expect(bridge.requestTicket()).rejects.toMatchObject({ code: "busy" });
    deliver(ticket());
    await first;
  });

  it("is not embedded: there is no panel to ask", async () => {
    const { bridge } = setup({ embedded: false });
    await expect(bridge.requestTicket()).rejects.toEqual(new BridgeError("no_panel"));
  });

  it("gives up when the panel does not answer", async () => {
    vi.useFakeTimers();
    const { bridge } = setup({ timeoutMs: 1000 });
    const p = bridge.requestTicket();
    const assertion = expect(p).rejects.toMatchObject({ code: "no_ticket" });
    await vi.advanceTimersByTimeAsync(1001);
    await assertion;
  });

  it("refuses to be configured with a wildcard or a non-https panel origin", () => {
    for (const bad of ["*", "http://nms.example.org", "https://nms.example.org/", "https://nms.example.org/x", "nms.example.org", ""]) {
      expect(() => createExecutorBridge({ panelOrigin: bad, self: new EventTarget() as unknown as Window })).toThrow();
    }
  });

  it("stops listening after close", async () => {
    const { bridge, deliver } = setup();
    const p = bridge.requestTicket();
    const assertion = expect(p).rejects.toMatchObject({ code: "no_ticket" });
    bridge.close();
    await assertion;
    deliver(ticket());
    expect(bridge.dropped).toBe(0);
  });
});
