import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { logout } from "@/features/auth/useSession";
import { notifyUnauthorized, setUnauthorizedHandler } from "@/lib/api";
import { buildRouter } from "@/router";
import { StepUpDialog } from "./StepUpDialog";
import { ApiError, StepUpCancelled, stepUpStore, withStepUp } from "./stepup";

let calls = 0;
const server = setupServer(http.post("*/api/auth/logout", () => new HttpResponse(null, { status: 204 })));
server.listen({ onUnhandledFrame: "error" });

/* input-otp probes the pointer position, which jsdom lacks */
beforeAll(() => {
  document.elementFromPoint ??= () => null;
});
afterEach(() => {
  cleanup();
  stepUpStore.settle(false);
  setUnauthorizedHandler(undefined);
  calls = 0;
});

/* a mutation that demands a step-up on its first call */
const mutate = () =>
  withStepUp(async () => {
    calls++;
    throw new ApiError("stepup_required", 403);
  });

async function pendingPrompt() {
  const p = mutate();
  const outcome = p.then(
    () => "resolved",
    (e) => e,
  );
  await screen.findByText(ru.stepup.title);
  return outcome;
}

describe("step-up prompt vs session loss", () => {
  it("is cancelled by the global unauthorized handler without replaying the request", async () => {
    buildRouter();
    render(<StepUpDialog />);
    const outcome = pendingPrompt();
    await screen.findByText(ru.stepup.title);
    act(() => notifyUnauthorized());
    expect(await outcome).toBeInstanceOf(StepUpCancelled);
    expect(calls).toBe(1);
    expect(stepUpStore.isOpen()).toBe(false);
    await waitFor(() => expect(screen.queryByText(ru.stepup.title)).not.toBeInTheDocument());
  });

  it("is cancelled by logout", async () => {
    render(<StepUpDialog />);
    const outcome = pendingPrompt();
    await screen.findByText(ru.stepup.title);
    await act(() => logout());
    expect(await outcome).toBeInstanceOf(StepUpCancelled);
    expect(calls).toBe(1);
    expect(stepUpStore.isOpen()).toBe(false);
  });

  it("is cancelled when the dialog host unmounts", async () => {
    const { unmount } = render(<StepUpDialog />);
    const outcome = pendingPrompt();
    await screen.findByText(ru.stepup.title);
    unmount();
    expect(await outcome).toBeInstanceOf(StepUpCancelled);
    expect(calls).toBe(1);
    expect(stepUpStore.isOpen()).toBe(false);
    /* a later mount shows nothing */
    render(<StepUpDialog />);
    expect(screen.queryByText(ru.stepup.title)).not.toBeInTheDocument();
  });
});
