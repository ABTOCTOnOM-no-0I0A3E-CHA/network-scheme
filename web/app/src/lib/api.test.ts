import { afterEach, describe, expect, it, vi } from "vitest";
import { api, clearCsrfToken } from "./api";

const me = JSON.stringify({ id: "1", username: "a", roles: [], csrf_token: "tok123" });

describe("api csrf middleware", () => {
  afterEach(() => clearCsrfToken());

  it("sends the token cached from /api/auth/me on non-GET requests only", async () => {
    const fetchMock = vi.fn(async (req: Request) =>
      new URL(req.url).pathname === "/api/auth/me"
        ? new Response(me, { headers: { "content-type": "application/json" } })
        : new Response(null, { status: 204 }),
    );
    const call = fetchMock as unknown as typeof fetch;
    const sent = () => (fetchMock.mock.calls.at(-1)![0] as Request).headers.get("X-CSRF-Token");

    await api.POST("/api/auth/logout", { fetch: call } as never);
    expect(sent()).toBeNull();

    await api.GET("/api/auth/me", { fetch: call });
    expect(sent()).toBeNull();

    await api.POST("/api/auth/logout", { fetch: call } as never);
    expect(sent()).toBe("tok123");
  });
});
