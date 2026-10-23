import type { EventSeverity, ProblemSummary } from "@/features/problems/api";
import { SEVERITIES } from "@/features/problems/api";

export type ProblemEvent = "opened" | "acknowledged" | "resolved" | "suppressed_changed";
export type ProblemMessage = { type: "problem"; event: ProblemEvent; problem: ProblemSummary };

const EVENTS: ProblemEvent[] = ["opened", "acknowledged", "resolved", "suppressed_changed"];

/** Parses a frame of /api/ws; anything but a well-formed problem message gives null (pong/subscribed frames are ignored). */
export function parseMessage(data: unknown): ProblemMessage | null {
  if (typeof data !== "string") return null;
  let m: { type?: unknown; event?: unknown; problem?: Record<string, unknown> | null };
  try {
    m = JSON.parse(data) as typeof m;
  } catch {
    return null;
  }
  const p = m?.problem;
  if (m?.type !== "problem" || !EVENTS.includes(m.event as ProblemEvent) || !p || typeof p !== "object") return null;
  const ok =
    typeof p.id === "number" &&
    typeof p.name === "string" &&
    typeof p.device_name === "string" &&
    typeof p.suppressed === "boolean" &&
    SEVERITIES.includes(p.severity as EventSeverity) &&
    (p.group_id === null || typeof p.group_id === "number");
  return ok ? (m as ProblemMessage) : null;
}

/** Notification preferences; only booleans, a severity and group ids are persisted. */
export type NotifySettings = { sound: boolean; severityMin: EventSeverity; groups: number[] };
export const DEFAULT_SETTINGS: NotifySettings = { sound: false, severityMin: "average", groups: [] };
export const SETTINGS_KEY = "nms.notify.v1";

/** Reads the preferences, falling back to the defaults for missing, unreadable or malformed data. */
export function loadSettings(): NotifySettings {
  try {
    const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? "null") as Partial<NotifySettings> | null;
    if (!raw || typeof raw !== "object") return DEFAULT_SETTINGS;
    return {
      sound: raw.sound === true,
      severityMin: SEVERITIES.includes(raw.severityMin as EventSeverity) ? (raw.severityMin as EventSeverity) : DEFAULT_SETTINGS.severityMin,
      groups: Array.isArray(raw.groups) ? raw.groups.filter((g): g is number => Number.isInteger(g) && g > 0).slice(0, 1000) : [],
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

/** Persists the preferences (best effort: storage may be unavailable). */
export function saveSettings(s: NotifySettings): void {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  } catch {
    /* private mode or quota: the preferences just do not persist */
  }
}

/** Whether a message is announced (badge and sound): a newly opened, not suppressed problem at or above the severity, in the chosen groups (none chosen = all). */
export function shouldNotify(m: ProblemMessage, s: NotifySettings): boolean {
  const p = m.problem;
  if (m.event !== "opened" || p.suppressed) return false;
  if (SEVERITIES.indexOf(p.severity) < SEVERITIES.indexOf(s.severityMin)) return false;
  return s.groups.length === 0 || (p.group_id !== null && s.groups.includes(p.group_id));
}

const BACKOFF_MIN_MS = 1000;
const BACKOFF_MAX_MS = 30_000;

/** Reconnect delay: 1 s doubling to 30 s, with up to 20% jitter downwards. */
export function backoffMs(attempt: number, rnd: () => number = Math.random): number {
  const base = Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** Math.min(attempt, 10));
  return Math.round(base * (1 - 0.2 * rnd()));
}

export type SocketHandlers = {
  onMessage: (data: unknown) => void;
  /** Called on every open; `reconnect` is true after a drop (the caller should resync what it missed). */
  onOpen?: (reconnect: boolean) => void;
  onClose?: (code: number) => void;
};

/** Same-origin WebSocket with automatic reconnect. Nothing is ever put in the URL; the session cookie authenticates. */
export class ProblemSocket {
  private ws: WebSocket | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private attempt = 0;
  private stopped = true;
  private dropped = false;

  constructor(
    private readonly h: SocketHandlers,
    private readonly url: () => string = defaultUrl,
    private readonly rnd: () => number = Math.random,
  ) {}

  /** Sends a text frame if the socket is open (the severity preference goes to the server this way). */
  send(data: string): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(data);
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    clearTimeout(this.timer);
    this.timer = undefined;
    const ws = this.ws;
    this.ws = undefined;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null;
      ws.close();
    }
  }

  private connect(): void {
    const ws = new WebSocket(this.url());
    this.ws = ws;
    ws.onopen = () => {
      this.attempt = 0;
      this.h.onOpen?.(this.dropped);
      this.dropped = false;
    };
    ws.onmessage = (e: MessageEvent) => this.h.onMessage(e.data);
    ws.onclose = (e: CloseEvent) => {
      if (this.ws !== ws) return;
      this.ws = undefined;
      this.dropped = true;
      this.h.onClose?.(e.code);
      if (this.stopped) return;
      this.timer = setTimeout(() => this.connect(), backoffMs(this.attempt++, this.rnd));
    };
  }
}

function defaultUrl(): string {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ws`;
}
