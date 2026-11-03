import { describe, expect, it } from "vitest";
import i18n from "./i18n";
import { codeSpent, failureMessage, parseFailure, type Failure } from "./errors";

const text = (f: Failure) => {
  const m = failureMessage(f);
  return i18n.t(m.key, m.params) as string;
};

describe("failureMessage", () => {
  it("423: a lock until a time, a permanent lock and a lock with no usable end", () => {
    const until = text(parseFailure(423, { error: { code: "locked", until: "2026-10-26T10:00:00Z" } }, null));
    expect(until).toMatch(/^Вход заблокирован до .+\.$/);
    expect(until).not.toContain("Invalid");
    expect(text(parseFailure(423, { error: { code: "locked", permanent: true } }, null))).toContain("на хосте");
    expect(text(parseFailure(423, { error: { code: "locked", until: "garbage" } }, null))).toBe("Вход заблокирован.");
    expect(text(parseFailure(423, undefined, null))).toBe("Вход заблокирован.");
  });

  it("429: with and without Retry-After, and too many challenges", () => {
    expect(text(parseFailure(429, { error: { code: "rate_limited" } }, "7"))).toBe("Слишком много запросов. Повторите через 7 с.");
    expect(text(parseFailure(429, { error: { code: "rate_limited" } }, null))).toBe("Слишком много запросов. Повторите позже.");
    expect(text(parseFailure(429, { error: { code: "rate_limited" } }, "soon"))).toBe("Слишком много запросов. Повторите позже.");
    expect(text(parseFailure(429, { error: { code: "too_many_challenges" } }, "7"))).toContain("неподтверждённых");
  });

  it("503: disabled, frozen, unavailable; anything else from the gateway is 'not reachable'", () => {
    expect(text(parseFailure(503, { error: { code: "executor_disabled" } }, null))).toContain("выключен политикой хоста");
    expect(text(parseFailure(503, { error: { code: "frozen" } }, null))).toContain("заморожен");
    expect(text(parseFailure(503, { error: { code: "unavailable" } }, null))).toContain("следующего кода TOTP");
    expect(text(parseFailure(503, { error: { code: "gateway_error" } }, null))).toBe("Executor недоступен.");
    expect(text(parseFailure(502, undefined, null))).toBe("Executor недоступен.");
  });

  it("other statuses, network failures and local refusals have texts of their own; none is a raw key", () => {
    const all: Failure[] = [
      parseFailure(403, { error: { code: "origin" } }, null),
      parseFailure(403, { error: { code: "denied" } }, null),
      parseFailure(421, undefined, null),
      parseFailure(418, undefined, null),
      { kind: "network" },
      { kind: "bad_response" },
      ...(["no_panel", "no_ticket", "busy", "code_reused"] as const).map((code): Failure => ({ kind: "local", code })),
    ];
    for (const f of all) {
      expect(text(f), JSON.stringify(f)).not.toMatch(/^executor\.|\{\{/);
    }
  });

  it("never shows anything of the body but a validated end of a lock", () => {
    const f = parseFailure(403, { error: { code: "<img src=x onerror=alert(1)>" } }, null);
    expect(text(f)).toBe("Недостаточно прав.");
    expect(parseFailure(423, { error: { code: "x".repeat(65) } }, null)).toMatchObject({ code: "" });
  });
});

describe("codeSpent", () => {
  it("is true after any answer and after a lost connection, false for refusals before sending", () => {
    expect(codeSpent(parseFailure(503, { error: { code: "unavailable" } }, null))).toBe(true);
    expect(codeSpent({ kind: "network" })).toBe(true);
    expect(codeSpent({ kind: "local", code: "busy" })).toBe(false);
    expect(codeSpent({ kind: "local", code: "no_ticket" })).toBe(false);
  });
});
