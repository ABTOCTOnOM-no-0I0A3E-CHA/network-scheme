import { describe, expect, it } from "vitest";
import { serverMessage, type ServerMessage } from "./socket";
import { initialTerm, MAX_TRANSCRIPT, screenOf, termReducer, type TermState } from "./term";

const run = (msgs: ServerMessage[], s: TermState = initialTerm) => msgs.reduce((st, m) => termReducer(st, { type: "message", m }), s);
const H = "ab".repeat(32);

describe("terminal state", () => {
  it("echoes a sent line after the prompt it was typed at, then shows the answer and the new prompt", () => {
    const s = run([
      { type: "ready", device_id: 12, line: "mes6" },
      { type: "edit", text: "", cursor: 0, prompt: "sw#" },
      { type: "output", sent: "configure", text: "", limited: false, prompt: "sw(config)#" },
      { type: "output", sent: "do show clock", text: "12:00:01", limited: false, prompt: "sw(config)#" },
      { type: "edit", text: "inter", cursor: 3, prompt: "sw(config)#" },
    ]);
    expect(s.conn).toBe("ready");
    expect(s.transcript).toBe("sw#configure\nsw(config)#do show clock\n12:00:01\n");
    expect(screenOf(s)).toEqual({ text: "sw#configure\nsw(config)#do show clock\n12:00:01\nsw(config)#inter", caret: s.transcript.length + "sw(config)#".length + 3 });
  });

  it("a dangerous line waits for its challenge; any refusal or output spends it", () => {
    let s = run([{ type: "edit", text: "", cursor: 0, prompt: "sw(config-if)#" }, { type: "dangerous", line: "shutdown", reason: "mgmt" }]);
    expect(s.dangerous).toEqual({ line: "shutdown", reason: "mgmt" });
    s = run([{ type: "challenge", challenge_id: "c1", action: "session.line", h: H, fields: [{ key: "device", value: "sw" }], expires: "x" }], s);
    expect(s.dangerous?.challenge?.challenge_id).toBe("c1");
    const refused = run([{ type: "refused", code: "device_name" }], s);
    expect(refused.dangerous).toBeNull();
    expect(refused.notice).toEqual({ code: "device_name", line: undefined, reason: undefined });
    expect(run([{ type: "output", sent: "shutdown", text: "", limited: false, prompt: "sw(config-if)#" }], s).dangerous).toBeNull();
  });

  it("a challenge without a pending line is ignored", () => {
    expect(run([{ type: "challenge", challenge_id: "c1", action: "session.line", h: H, fields: [], expires: "x" }]).dangerous).toBeNull();
  });

  it("counts the lines of a held paste as typed and keeps flows with a sequence", () => {
    expect(run([{ type: "paste_pending", text: "a\nb\nc\n", lines: 3 }]).paste).toEqual({ text: "a\nb\nc\n", lines: 3 });
    expect(run([{ type: "paste_pending", text: "a\nb", lines: 1 }]).paste?.lines).toBe(2);
    const s = run([{ type: "flow", flow: "rollback", diff: undefined }, { type: "flow", flow: "save", diff: undefined }]);
    expect(s.flow).toMatchObject({ kind: "save", seq: 2 });
  });

  it("keeps only the tail of a long transcript", () => {
    const big = "x".repeat(MAX_TRANSCRIPT);
    const s = run([{ type: "output", sent: "show", text: big, limited: true, prompt: "#" }, { type: "output", sent: "show", text: "END", limited: false, prompt: "#" }]);
    expect(s.transcript.length).toBe(MAX_TRANSCRIPT);
    expect(s.transcript.endsWith("#show\nEND\n")).toBe(true);
    expect(s.limited).toBe(true);
  });

  it("ended and closed drop what waits", () => {
    const s = run([{ type: "dangerous", line: "reload", reason: "grammar" }, { type: "paste_pending", text: "a\nb", lines: 1 }]);
    expect(termReducer(s, { type: "closed" })).toMatchObject({ conn: "closed", dangerous: null, paste: null });
    expect(run([{ type: "ended", code: "no_session" }], s)).toMatchObject({ ended: "no_session", dangerous: null, paste: null });
  });
});

describe("server messages", () => {
  it("parse strictly by type; the rollback flow's zero diff is no diff", () => {
    expect(serverMessage.safeParse({ type: "output", sent: "x", text: "y", limited: false, prompt: "#" }).success).toBe(true);
    expect(serverMessage.safeParse({ type: "output", sent: "x" }).success).toBe(false);
    expect(serverMessage.safeParse({ type: "eval", code: "alert(1)" }).success).toBe(false);
    const f = serverMessage.parse({ type: "flow", flow: "rollback", diff: { device_id: 0, line: "", pre_sha256: "", sha256: "", diff: "" } });
    expect(f).toEqual({ type: "flow", flow: "rollback", diff: undefined });
    expect(serverMessage.safeParse({ type: "challenge", challenge_id: "c", action: "a", h: "zz", fields: [], expires: "x" }).success).toBe(false);
  });
});
