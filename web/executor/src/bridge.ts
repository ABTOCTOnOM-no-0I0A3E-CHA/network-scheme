import { createChannel, statusMessage, ticketMessage, type Channel, type StatusMessage } from "@nms/shared/bridge";

/* How long a request waits for the panel's ticket (the panel makes one API call). */
export const TICKET_TIMEOUT_MS = 10_000;

export class BridgeError extends Error {
  constructor(readonly code: "no_panel" | "no_ticket" | "busy") {
    super(code);
  }
}

export type ExecutorBridge = {
  /*
   * Asks the panel for one fresh session ticket. One request at a time; the ticket is handed out once, held only in
   * this closure, and every request gets its own. Rejects with a BridgeError.
   */
  requestTicket(): Promise<string>;
  /* Tells the panel the page is loaded. */
  ready(): void;
  /* Tells the panel whether a change session is open here (it keeps this frame mounted and shown while one is). */
  session(open: boolean): void;
  /* Asks the panel to show this frame at full size. */
  expand(): void;
  /* Tells the panel a dialog opened or closed (it gives the frame the whole viewport meanwhile). */
  dialog(open: boolean): void;
  readonly dropped: number;
  close(): void;
};

const randomId = () => [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");

type Pending = { id: string; resolve: (ticket: string) => void; reject: (e: BridgeError) => void; timer: ReturnType<typeof setTimeout> };

/* panelOrigin comes from the gateway's /origins.json; the panel is the embedder (window.parent). */
export function createExecutorBridge(o: { panelOrigin: string; self?: Window; timeoutMs?: number; newId?: () => string }): ExecutorBridge {
  const self = o.self ?? window;
  const newId = o.newId ?? randomId;
  let pending: Pending | null = null;
  const settle = (): Pending | null => {
    const p = pending;
    if (p) clearTimeout(p.timer);
    pending = null;
    return p;
  };
  /* not embedded (the page is the top window): there is no panel to ask */
  const peer = () => (self.parent !== self ? self.parent : null);
  const ch: Channel<StatusMessage> = createChannel({
    peerOrigin: o.panelOrigin,
    peer,
    incoming: ticketMessage,
    outgoing: statusMessage,
    self,
    onMessage(m) {
      /* only the answer to the outstanding request: a stale, repeated or unsolicited ticket is dropped */
      if (pending?.id !== m.id) return;
      settle()?.resolve(m.ticket);
    },
  });
  return {
    requestTicket() {
      if (peer() === null) return Promise.reject(new BridgeError("no_panel"));
      if (pending) return Promise.reject(new BridgeError("busy"));
      const id = newId();
      return new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => settle()?.reject(new BridgeError("no_ticket")), o.timeoutMs ?? TICKET_TIMEOUT_MS);
        pending = { id, resolve, reject, timer };
        if (!ch.send({ v: 1, type: "status", state: "ticket_needed", id })) settle()?.reject(new BridgeError("no_ticket"));
      });
    },
    ready() {
      ch.send({ v: 1, type: "status", state: "ready" });
    },
    session(open) {
      ch.send({ v: 1, type: "status", state: "session", open });
    },
    expand() {
      ch.send({ v: 1, type: "status", state: "expand" });
    },
    dialog(open) {
      ch.send({ v: 1, type: "status", state: "dialog", open });
    },
    get dropped() {
      return ch.dropped;
    },
    close() {
      settle()?.reject(new BridgeError("no_ticket"));
      ch.close();
    },
  };
}
