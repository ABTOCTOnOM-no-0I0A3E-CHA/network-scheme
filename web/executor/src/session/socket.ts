import { z } from "zod";
import { deviceDiff } from "./api";

/*
 * The terminal of one device of a session: WebSocket /x/ws of this origin (cmd/executor/internal/terminal). The first
 * frame is auth {session_id, token, device_id} (the token never goes into the URL); then keys, paste, paste_confirm,
 * dangerous_issue {ticket} and dangerous_confirm {challenge_id, device_name, totp, ticket}. Every server message is
 * parsed strictly; one that does not parse is dropped. All text in them is device or executor text: shown as text.
 */
const text = (n: number) => z.string().max(n);
const OUT = 1 << 20;

export const serverMessage = z.discriminatedUnion("type", [
  z.object({ type: z.literal("ready"), device_id: z.number().int(), line: text(16) }),
  z.object({ type: z.literal("edit"), text: text(8192), cursor: z.number().int().nonnegative(), prompt: text(1024) }),
  z.object({ type: z.literal("output"), sent: text(8192), text: text(OUT), limited: z.boolean(), prompt: text(1024) }),
  z.object({ type: z.literal("help"), words: z.array(text(256)).max(4096).nullable() }),
  z.object({ type: z.literal("dangerous"), line: text(8192), reason: text(256) }),
  z.object({
    type: z.literal("challenge"),
    challenge_id: text(64),
    action: text(64),
    h: z.string().regex(/^[0-9a-f]{64}$/),
    fields: z.array(z.object({ key: text(64), value: text(8192) })).max(64),
    expires: text(64),
  }),
  z.object({ type: z.literal("refused"), code: text(64), line: text(8192).optional(), reason: text(256).optional() }),
  z.object({ type: z.literal("paste_pending"), text: text(OUT), lines: z.number().int().nonnegative() }),
  /* the rollback flow carries an empty diff (zero values): a diff that does not parse is none */
  z.object({ type: z.literal("flow"), flow: z.enum(["commit", "save", "rollback"]), diff: z.unknown().transform((d) => deviceDiff.safeParse(d).data) }),
  z.object({ type: z.literal("ended"), code: text(64).optional() }),
]);
export type ServerMessage = z.infer<typeof serverMessage>;

export type ClientFrame =
  | { type: "keys"; data: string }
  | { type: "paste"; data: string }
  | { type: "paste_confirm"; accept: boolean }
  | { type: "dangerous_issue"; ticket: string }
  | { type: "dangerous_confirm"; challenge_id: string; device_name: string; totp: string; ticket: string };

export type TermSocket = { send(f: ClientFrame): boolean; close(): void };

/* Something that opens a WebSocket (tests pass a fake). */
export type SocketFactory = (url: string) => WebSocket;

/*
 * Connects one device's terminal. onMessage gets every parsed message; onClose once, when the connection ends for any
 * reason. Nothing is retried here: reconnecting is the user's choice (a new connection replaces the old one).
 */
export function connectTerminal(o: {
  session: string;
  token: string;
  device: number;
  onMessage: (m: ServerMessage) => void;
  onClose: () => void;
  open?: SocketFactory;
  url?: string;
}): TermSocket {
  const url = o.url ?? `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/x/ws`;
  const ws = (o.open ?? ((u) => new WebSocket(u)))(url);
  let closed = false;
  const end = () => {
    if (closed) return;
    closed = true;
    o.onClose();
  };
  ws.onopen = () => ws.send(JSON.stringify({ type: "auth", session_id: o.session, token: o.token, device_id: o.device }));
  ws.onmessage = (e: MessageEvent) => {
    if (closed || typeof e.data !== "string") return;
    let raw: unknown;
    try {
      raw = JSON.parse(e.data);
    } catch {
      return;
    }
    const m = serverMessage.safeParse(raw);
    if (m.success) o.onMessage(m.data);
  };
  ws.onclose = end;
  ws.onerror = end;
  return {
    send(f) {
      if (closed || ws.readyState !== WebSocket.OPEN) return false;
      ws.send(JSON.stringify(f));
      return true;
    },
    close() {
      closed = true;
      ws.close();
    },
  };
}
