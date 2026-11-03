import { afterEach, describe, expect, it, vi } from "vitest";
import { loadOrigins, parseOrigins } from "./origins";

const P = "https://nms.example.org";
const E = "https://nms.example.org:8443";

describe("parseOrigins", () => {
  it("accepts exactly two different https origins", () => {
    expect(parseOrigins({ panel: P, executor: E })).toEqual({ panel: P, executor: E });
  });

  it.each([
    ["not an object", null],
    ["an array", [P, E]],
    ["an extra field", { panel: P, executor: E, extra: E }],
    ["a missing field", { panel: P }],
    ["http", { panel: P, executor: "http://nms.example.org:8443" }],
    ["a path", { panel: P, executor: E + "/x" }],
    ["a trailing slash", { panel: P + "/", executor: E }],
    ["credentials", { panel: P, executor: "https://u:p@nms.example.org:8443" }],
    ["the same origin twice", { panel: P, executor: P }],
    ["a wildcard", { panel: "*", executor: E }],
    ["a non-string", { panel: 1, executor: E }],
    ["an oversize string", { panel: "https://" + "a".repeat(300) + ".example", executor: E }],
  ])("refuses %s", (_n, doc) => {
    expect(() => parseOrigins(doc)).toThrow();
  });
});

describe("loadOrigins", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("fetches /origins.json without cookies and without the HTTP cache", async () => {
    const f = vi.fn().mockResolvedValue(new Response(JSON.stringify({ panel: P, executor: E })));
    vi.stubGlobal("fetch", f);
    await expect(loadOrigins()).resolves.toEqual({ panel: P, executor: E });
    expect(f).toHaveBeenCalledWith("/origins.json", { cache: "no-store", credentials: "omit" });
  });

  it("fails on an HTTP error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 404 })));
    await expect(loadOrigins()).rejects.toThrow();
  });
});
