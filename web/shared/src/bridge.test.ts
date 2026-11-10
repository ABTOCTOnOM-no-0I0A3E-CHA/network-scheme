import { describe, expect, it, vi } from "vitest";
import { createChannel, statusMessage, ticketMessage, MAX_TICKET } from "./bridge";

const EXECUTOR = "https://nms.example.org:8443";
const ID = "0123456789abcdef0123456789abcdef";

/* the panel's side of the channel: it listens for status, sends ticket, the peer is the iframe's window */
function panel(peerOrigin = EXECUTOR) {
  const frame = { postMessage: vi.fn() };
  const self = new EventTarget();
  const got: unknown[] = [];
  const ch = createChannel({ peerOrigin, peer: () => frame as unknown as Window, incoming: statusMessage, outgoing: ticketMessage, onMessage: (m) => got.push(m), self: self as unknown as Window });
  const deliver = (data: unknown, origin = EXECUTOR, source: unknown = frame) => self.dispatchEvent(Object.assign(new Event("message"), { data, origin, source }));
  return { frame, ch, got, deliver };
}

describe("channel (panel side)", () => {
  it("accepts a status from the exact peer origin and window", () => {
    const { got, deliver } = panel();
    deliver({ v: 1, type: "status", state: "ready" });
    deliver({ v: 1, type: "status", state: "ticket_needed", id: ID });
    deliver({ v: 1, type: "status", state: "session", open: true });
    deliver({ v: 1, type: "status", state: "expand" });
    deliver({ v: 1, type: "status", state: "dialog", open: true });
    expect(got).toEqual([
      { v: 1, type: "status", state: "ready" },
      { v: 1, type: "status", state: "ticket_needed", id: ID },
      { v: 1, type: "status", state: "session", open: true },
      { v: 1, type: "status", state: "expand" },
      { v: 1, type: "status", state: "dialog", open: true },
    ]);
  });

  it("drops a session status without a boolean and an expand with extra fields", () => {
    const { got, deliver } = panel();
    deliver({ v: 1, type: "status", state: "session" });
    deliver({ v: 1, type: "status", state: "session", open: "yes" });
    deliver({ v: 1, type: "status", state: "expand", to: "full" });
    expect(got).toEqual([]);
  });

  it("drops foreign origins, other windows and malformed messages, silently", () => {
    const { frame, ch, got, deliver } = panel();
    deliver({ v: 1, type: "status", state: "ready" }, "https://evil.example");
    deliver({ v: 1, type: "status", state: "ready" }, EXECUTOR, {});
    deliver({ v: 1, type: "status", state: "ready", extra: 1 });
    deliver({ v: 1, type: "status", state: "ticket_needed" }); /* no id */
    deliver({ v: 1, type: "status", state: "ticket_needed", id: "x".repeat(10_000) });
    deliver("ready");
    expect(got).toEqual([]);
    expect(ch.dropped).toBe(6);
    expect(frame.postMessage).not.toHaveBeenCalled();
  });

  it("sends only schema-valid messages, always with the exact targetOrigin", () => {
    const { frame, ch } = panel();
    expect(ch.send({ v: 1, type: "ticket", id: ID, ticket: "a.b" })).toBe(true);
    expect(frame.postMessage).toHaveBeenCalledWith({ v: 1, type: "ticket", id: ID, ticket: "a.b" }, EXECUTOR);
    expect(ch.send({ v: 1, type: "ticket", id: ID, ticket: "a".repeat(MAX_TICKET + 1) })).toBe(false);
    expect(ch.send({ v: 1, type: "ticket", id: ID, ticket: "a.b", extra: 1 } as never)).toBe(false);
    expect(frame.postMessage).toHaveBeenCalledTimes(1);
    for (const c of frame.postMessage.mock.calls) expect(c[1]).not.toBe("*");
  });

  it("sends nothing when the peer has no window", () => {
    const self = new EventTarget();
    const ch = createChannel({ peerOrigin: EXECUTOR, peer: () => null, incoming: statusMessage, outgoing: ticketMessage, onMessage() {}, self: self as unknown as Window });
    expect(ch.send({ v: 1, type: "ticket", id: ID, ticket: "a.b" })).toBe(false);
  });

  it.each(["*", "", "null", "http://nms.example.org:8443", EXECUTOR + "/", "https://nms.example.org:8443/x"])("refuses the peer origin %j", (o) => {
    expect(() => panel(o)).toThrow();
  });
});
