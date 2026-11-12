import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "./i18n";
import { App } from "./App";
import type { ExecutorBridge } from "./bridge";
import { createPoster } from "./client";

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
const SID = "3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c";

beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
  vi.stubGlobal("fetch", vi.fn(async () => json({ enabled: true, frozen: false })));
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
});

const bridge = () => {
  const b = { session: vi.fn(), expand: vi.fn(), ready: vi.fn(), requestTicket: vi.fn(), close: vi.fn(), dropped: 0 };
  return { b, p: Promise.resolve(b as unknown as ExecutorBridge) };
};
const poster = () => createPoster({ requestTicket: () => Promise.resolve("t") });

describe("App", () => {
  it("opens on the session view and tells the panel nothing while no session is open", async () => {
    const { b, p } = bridge();
    window.location.hash = "#device=12,14";
    render(<App poster={poster()} bridge={p} />);
    expect(await screen.findByTestId("enabled")).toHaveTextContent("Включён");
    expect(screen.getByTestId("nav-session")).toHaveAttribute("aria-selected", "true");
    expect(document.getElementById("ss-devices")).toHaveValue("12, 14");
    await p;
    expect(b.session).not.toHaveBeenCalled();
  });

  it("opens the player of the session the panel names", async () => {
    window.location.hash = `#replay=${SID}&device=12`;
    render(<App poster={poster()} bridge={bridge().p} />);
    expect(await screen.findByTestId("play-initial")).toHaveTextContent("3f2a9c1e");
    expect(screen.getByTestId("nav-recordings")).toHaveAttribute("aria-selected", "true");
  });

  it("opens «Изменения» on the changeset or restore the panel names", async () => {
    window.location.hash = "#restore=12:345";
    render(<App poster={poster()} bridge={bridge().p} />);
    expect(await screen.findByTestId("cs-open")).toBeVisible();
    expect(screen.getByTestId("nav-changesets")).toHaveAttribute("aria-selected", "true");
  });
});
