import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { BridgeError } from "./bridge";
import { createPoster, getStatus } from "./client";

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
const ok = z.object({ ok: z.boolean() });

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("getStatus", () => {
  it("GETs /x/status without cookies and returns enabled/frozen", async () => {
    fetchMock.mockResolvedValue(json(200, { enabled: true, frozen: false }));
    await expect(getStatus()).resolves.toEqual({ ok: true, value: { enabled: true, frozen: false } });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/x/status");
    expect(init).toMatchObject({ method: "GET", credentials: "omit", mode: "cors", cache: "no-store" });
  });

  it("maps an HTTP error with its code, a lost connection and a malformed answer", async () => {
    fetchMock.mockResolvedValueOnce(json(423, { error: { code: "locked", permanent: true } }));
    await expect(getStatus()).resolves.toMatchObject({ ok: false, failure: { kind: "http", status: 423, permanent: true } });
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await expect(getStatus()).resolves.toEqual({ ok: false, failure: { kind: "network" } });
    fetchMock.mockResolvedValueOnce(json(200, { enabled: "yes" }));
    await expect(getStatus()).resolves.toEqual({ ok: false, failure: { kind: "bad_response" } });
    fetchMock.mockResolvedValueOnce(new Response("<html>", { status: 200 }));
    await expect(getStatus()).resolves.toEqual({ ok: false, failure: { kind: "bad_response" } });
  });
});

describe("poster", () => {
  const bridge = () => {
    let n = 0;
    return { requestTicket: vi.fn(async () => `ticket-${++n}`) };
  };

  it("takes a fresh ticket for every request and POSTs JSON with credentials omitted and mode cors (so the browser sends Origin)", async () => {
    const b = bridge();
    fetchMock.mockImplementation(async () => json(200, { ok: true }));
    const p = createPoster(b);
    await p.post("/x/confirm", (ticket) => ({ ticket, code: "111111" }), ok);
    await p.post("/x/confirm", (ticket) => ({ ticket, code: "222222" }), ok);
    expect(b.requestTicket).toHaveBeenCalledTimes(2);
    const bodies = fetchMock.mock.calls.map((c) => JSON.parse((c[1] as RequestInit).body as string));
    expect(bodies.map((x) => x.ticket)).toEqual(["ticket-1", "ticket-2"]);
    for (const c of fetchMock.mock.calls) {
      expect(c[1]).toMatchObject({ method: "POST", credentials: "omit", mode: "cors", headers: { "Content-Type": "application/json" } });
    }
  });

  it("never sends the same TOTP code twice, not even after a failure", async () => {
    const b = bridge();
    fetchMock.mockResolvedValue(json(503, { error: { code: "unavailable" } }));
    const p = createPoster(b);
    const first = await p.post("/x/confirm", (ticket) => ({ ticket, code: "123456" }), ok);
    expect(first).toMatchObject({ ok: false, failure: { kind: "http", status: 503, code: "unavailable" } });
    const again = await p.post("/x/confirm", (ticket) => ({ ticket, code: "123456" }), ok);
    expect(again).toEqual({ ok: false, failure: { kind: "local", code: "code_reused" } });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("never retries by itself: one lost connection is one request", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    const p = createPoster(bridge());
    await expect(p.post("/x/confirm", (ticket) => ({ ticket, code: "123456" }), ok)).resolves.toEqual({ ok: false, failure: { kind: "network" } });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refuses a second request while one is in flight (no parallel submit)", async () => {
    let release!: (r: Response) => void;
    fetchMock.mockReturnValue(new Promise<Response>((r) => (release = r)));
    const p = createPoster(bridge());
    const first = p.post("/x/confirm", (ticket) => ({ ticket, code: "111111" }), ok);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());
    await expect(p.post("/x/confirm", (ticket) => ({ ticket, code: "222222" }), ok)).resolves.toEqual({ ok: false, failure: { kind: "local", code: "busy" } });
    release(json(200, { ok: true }));
    await expect(first).resolves.toMatchObject({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("sends nothing when the panel gives no ticket, and the code stays usable", async () => {
    const b = { requestTicket: vi.fn().mockRejectedValueOnce(new BridgeError("no_ticket")).mockResolvedValue("t") };
    fetchMock.mockResolvedValue(json(200, { ok: true }));
    const p = createPoster(b);
    await expect(p.post("/x/confirm", (ticket) => ({ ticket, code: "123456" }), ok)).resolves.toEqual({ ok: false, failure: { kind: "local", code: "no_ticket" } });
    expect(fetchMock).not.toHaveBeenCalled();
    await expect(p.post("/x/confirm", (ticket) => ({ ticket, code: "123456" }), ok)).resolves.toMatchObject({ ok: true });
  });
});
