import { z } from "zod";
import { isHttpsOrigin } from "./origins";

/*
 * The postMessage protocol between the panel (embedder) and the executor UI (iframe), build-time shared by both
 * bundles. Panel -> executor: `ticket`, an answer to a request. Executor -> panel: `status` (`ready`, or
 * `ticket_needed` with a request id). Every message is a strict object: unknown fields are refused, every string is
 * bounded. A message is accepted only from the exact peer origin AND the peer window; anything else is dropped
 * silently (counted, never answered). Every send names the exact peer origin as targetOrigin, never "*".
 */

/* Longest session ticket the executor accepts (internal/ticket MaxLen). */
export const MAX_TICKET = 1024;
const ID = z.string().regex(/^[0-9a-f]{32}$/);

export const ticketMessage = z.strictObject({
  v: z.literal(1),
  type: z.literal("ticket"),
  id: ID,
  /* printable ASCII without spaces: base64url.base64url */
  ticket: z.string().min(1).max(MAX_TICKET).regex(/^[\x21-\x7e]+$/),
});

/*
 * `session` tells the panel whether a change session is open in the frame (it keeps the frame mounted and shown while
 * one is: FR-CHG-7); `expand` asks the panel to show the frame at full size (a button of the compact session bar).
 * Both only steer the panel's own layout: the panel decides nothing else from them.
 */
export const statusMessage = z.discriminatedUnion("state", [
  z.strictObject({ v: z.literal(1), type: z.literal("status"), state: z.literal("ready") }),
  z.strictObject({ v: z.literal(1), type: z.literal("status"), state: z.literal("ticket_needed"), id: ID }),
  z.strictObject({ v: z.literal(1), type: z.literal("status"), state: z.literal("session"), open: z.boolean() }),
  z.strictObject({ v: z.literal(1), type: z.literal("status"), state: z.literal("expand") }),
]);

export type TicketMessage = z.infer<typeof ticketMessage>;
export type StatusMessage = z.infer<typeof statusMessage>;

export type Channel<Out> = {
  /* Validates the message against the outgoing schema and posts it to the peer; false when nothing was sent. */
  send(msg: Out): boolean;
  /* Messages dropped so far (wrong origin, wrong window, wrong shape). A debug counter: never sent anywhere. */
  readonly dropped: number;
  close(): void;
};

export type ChannelOptions<In, Out> = {
  /* The one origin messages are accepted from and posted to: an https origin, no path. */
  peerOrigin: string;
  /* The peer's window (the iframe's contentWindow, or window.parent); null when there is none. */
  peer: () => Window | null;
  incoming: z.ZodType<In>;
  outgoing: z.ZodType<Out>;
  onMessage: (msg: In) => void;
  /* The window that receives the events (tests); the default is the global window. */
  self?: Window;
};

export function createChannel<In, Out>(o: ChannelOptions<In, Out>): Channel<Out> {
  if (!isHttpsOrigin(o.peerOrigin)) throw new Error("bridge: the peer origin must be exactly an https origin (scheme, host, optional port)");
  const self = o.self ?? window;
  let dropped = 0;
  let closed = false;
  const listener = (e: MessageEvent) => {
    const peer = o.peer();
    if (closed || e.origin !== o.peerOrigin || peer === null || e.source !== peer) {
      dropped++;
      return;
    }
    const m = o.incoming.safeParse(e.data);
    if (!m.success) {
      dropped++;
      return;
    }
    o.onMessage(m.data);
  };
  self.addEventListener("message", listener);
  return {
    send(msg) {
      const peer = o.peer();
      const m = o.outgoing.safeParse(msg);
      if (closed || peer === null || !m.success) return false;
      peer.postMessage(m.data, o.peerOrigin);
      return true;
    },
    get dropped() {
      return dropped;
    },
    close() {
      closed = true;
      self.removeEventListener("message", listener);
    },
  };
}
