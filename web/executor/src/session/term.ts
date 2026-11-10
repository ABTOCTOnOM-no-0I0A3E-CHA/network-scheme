import type { DeviceDiff } from "./api";
import type { ServerMessage } from "./socket";

/*
 * The state of one device's terminal, built only from the executor's messages (a pure reducer, unit-tested). The
 * transcript is what the read-only part of the screen shows; the current line is prompt + the executor's editor text.
 * Nothing here is ever interpreted: every string is shown as a text node.
 */
export type Challenge = Extract<ServerMessage, { type: "challenge" }>;
export type Pending = { line: string; reason: string; challenge?: Challenge };
export type Notice = { code: string; line?: string; reason?: string };

export type TermState = {
  conn: "connecting" | "ready" | "closed";
  line: string;
  transcript: string;
  prompt: string;
  edit: { text: string; cursor: number };
  dangerous: Pending | null;
  paste: { text: string; lines: number } | null;
  flow: { kind: "commit" | "save" | "rollback"; diff?: DeviceDiff; seq: number } | null;
  notice: Notice | null;
  ended: string | null;
  /* the device answered with more than the browser is sent (the recording keeps it all) */
  limited: boolean;
};

export const initialTerm: TermState = {
  conn: "connecting",
  line: "",
  transcript: "",
  prompt: "",
  edit: { text: "", cursor: 0 },
  dangerous: null,
  paste: null,
  flow: null,
  notice: null,
  ended: null,
  limited: false,
};

/* The transcript keeps at most this many characters, the tail (a session can print megabytes). */
export const MAX_TRANSCRIPT = 1 << 20;

function append(t: string, more: string): string {
  const s = t + more;
  return s.length > MAX_TRANSCRIPT ? s.slice(s.length - MAX_TRANSCRIPT) : s;
}

export type TermAction = { type: "message"; m: ServerMessage } | { type: "closed" } | { type: "dismiss" } | { type: "flow_done" } | { type: "local_cancel" };

export function termReducer(s: TermState, a: TermAction): TermState {
  switch (a.type) {
    case "closed":
      return { ...s, conn: "closed", dangerous: null, paste: null };
    case "dismiss":
      return { ...s, notice: null };
    case "flow_done":
      return { ...s, flow: null };
    case "local_cancel":
      /* the user dropped a pending dangerous line or paste (the executor drops it on Ctrl-C) */
      return { ...s, dangerous: null, paste: null };
    case "message":
      break;
  }
  const m = a.m;
  switch (m.type) {
    case "ready":
      return { ...s, conn: "ready", line: m.line, ended: null };
    case "edit":
      return { ...s, prompt: m.prompt || s.prompt, edit: { text: m.text, cursor: Math.min(m.cursor, m.text.length) } };
    case "output": {
      const echo = `${s.prompt}${m.sent}\n`;
      const out = m.text === "" ? "" : m.text.endsWith("\n") ? m.text : `${m.text}\n`;
      return { ...s, transcript: append(s.transcript, echo + out), prompt: m.prompt, dangerous: null, limited: s.limited || m.limited, notice: null };
    }
    case "help":
      return { ...s, transcript: append(s.transcript, `${s.prompt}${s.edit.text}?\n${(m.words ?? []).join("  ")}\n`) };
    case "dangerous":
      return { ...s, transcript: append(s.transcript, `${s.prompt}${m.line}\n`), dangerous: { line: m.line, reason: m.reason }, notice: null };
    case "challenge":
      return s.dangerous ? { ...s, dangerous: { ...s.dangerous, challenge: m } } : s;
    case "refused":
      return {
        ...s,
        transcript: m.line !== undefined ? append(s.transcript, `${s.prompt}${m.line}\n`) : s.transcript,
        /* any refusal spends a pending dangerous line: the executor dropped it and its challenge */
        dangerous: null,
        notice: { code: m.code, line: m.line, reason: m.reason },
      };
    case "paste_pending":
      /* the lines the user will see typed (a final line break ends the last line, it does not start one) */
      return { ...s, paste: { text: m.text, lines: m.text.replace(/\n$/, "").split("\n").length } };
    case "flow":
      return { ...s, flow: { kind: m.flow, diff: m.diff, seq: (s.flow?.seq ?? 0) + 1 } };
    case "ended":
      return { ...s, conn: "closed", ended: m.code ?? "ended", dangerous: null, paste: null };
  }
}

/* The text the terminal shows and where its caret is: the transcript, then the current line. */
export function screenOf(s: TermState): { text: string; caret: number } {
  const head = s.transcript + s.prompt;
  return { text: head + s.edit.text, caret: head.length + s.edit.cursor };
}
