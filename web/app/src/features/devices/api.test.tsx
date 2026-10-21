import { readFileSync } from "node:fs";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { setUnauthorizedHandler } from "@/lib/api";
import { errorKey } from "@/features/auth/errors";
import { StateBadge } from "@/features/common/StateBadge";
import { StepUpDialog } from "@/features/common/StepUpDialog";
import { ApiError, StepUpCancelled, stepUpStore, withStepUp } from "@/features/common/stepup";
import { useDeleteDevice, useDevice, useDevices } from "./api";

const err = (status: number, code: string) => HttpResponse.json({ error: { code, message: "RAW SERVER MESSAGE" } }, { status });
const device = (id: number, name: string, state = "up") => ({
  id,
  name,
  address: `10.0.0.${id}`,
  group_id: 1,
  driver: "x",
  model: "",
  firmware: "",
  insecure_protocols: false,
  state,
  state_since: null,
});

let hits = { delete: 0, device: 0, stepup: 0 };
let deleteFn: () => Response;
let stepupFn: () => Response;

const server = setupServer(
  http.delete("*/api/devices/:id", () => {
    hits.delete++;
    return deleteFn();
  }),
  http.get("*/api/devices/:id", ({ params }) => {
    hits.device++;
    return params.id === "404" ? err(404, "not_found") : HttpResponse.json(device(Number(params.id), "sw"));
  }),
  http.get("*/api/devices", () => HttpResponse.json([device(1, "core"), device(2, "edge", "down")])),
  http.post("*/api/auth/stepup", () => {
    hits.stepup++;
    return stepupFn();
  }),
);

beforeAll(() => {
  /* index.html carries this marker so input-otp does not inject a runtime <style> */
  const marker = document.createElement("meta");
  marker.id = "input-otp-style";
  document.head.append(marker);
  document.elementFromPoint ??= () => null; /* used by input-otp password-manager detection */
  server.listen({ onUnhandledFrame: "error" });
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  hits = { delete: 0, device: 0, stepup: 0 };
  stepUpStore.settle(false);
});
afterAll(() => server.close());

const wrapper = ({ children }: { children: ReactNode }) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
};

const useDel = () => useDeleteDevice();

describe("data hooks", () => {
  it("useDevice resolves to null on 404 without retries", async () => {
    const { result } = renderHook(() => useDevice(404), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toBeNull();
    expect(hits.device).toBe(1);
  });

  it("useDevice returns the device", async () => {
    const { result } = renderHook(() => useDevice(7), { wrapper });
    await waitFor(() => expect(result.current.data?.id).toBe(7));
  });

  it("useDevices filters client-side", async () => {
    const { result } = renderHook(() => useDevices({ state: "down" }), { wrapper });
    await waitFor(() => expect(result.current.data).toHaveLength(1));
    expect(result.current.data?.[0]?.name).toBe("edge");
  });
});

describe("step-up", () => {
  const open = () => render(<StepUpDialog />, { wrapper });

  it("asks for a code and repeats the mutation exactly once", async () => {
    let n = 0;
    deleteFn = () => (n++ === 0 ? err(403, "stepup_required") : new HttpResponse(null, { status: 204 }));
    stepupFn = () => new HttpResponse(null, { status: 204 });
    open();
    const { result } = renderHook(useDel, { wrapper });
    const done = result.current.mutateAsync(5);
    await screen.findByText(ru.stepup.title);
    await userEvent.type(screen.getByLabelText(ru.stepup.label), "123456");
    await done;
    expect(hits).toMatchObject({ delete: 2, stepup: 1 });
    await waitFor(() => expect(screen.queryByText(ru.stepup.title)).toBeNull());
  });

  it("does not repeat when the dialog is cancelled", async () => {
    deleteFn = () => err(403, "stepup_required");
    open();
    const { result } = renderHook(useDel, { wrapper });
    const done = result.current.mutateAsync(5);
    const rejected = expect(done).rejects.toBeInstanceOf(StepUpCancelled);
    await userEvent.click(await screen.findByText(ru.stepup.cancel));
    await rejected;
    expect(hits).toMatchObject({ delete: 1, stepup: 0 });
  });

  it("keeps the dialog open on a wrong code and shows a localized error", async () => {
    deleteFn = () => err(403, "stepup_required");
    stepupFn = () => err(401, "invalid_credentials");
    open();
    withStepUp(async () => {
      throw new ApiError("stepup_required", 403);
    }).catch(() => undefined);
    await userEvent.type(await screen.findByLabelText(ru.stepup.label), "000000");
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.invalid_credentials);
    expect(screen.queryByText("RAW SERVER MESSAGE")).toBeNull();
  });

  it("a wrong code (401) does not trigger the global unauthorized handler; a lost session does", async () => {
    const spy = vi.fn();
    setUnauthorizedHandler(spy);
    try {
      stepupFn = () => err(401, "invalid_credentials");
      open();
      withStepUp(async () => {
        throw new ApiError("stepup_required", 403);
      }).catch(() => undefined);
      const input = await screen.findByLabelText(ru.stepup.label);
      await userEvent.type(input, "000000");
      expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.invalid_credentials);
      expect(spy).not.toHaveBeenCalled();
      expect(screen.getByText(ru.stepup.title)).toBeInTheDocument();
      await waitFor(() => expect(screen.getByLabelText(ru.stepup.label)).toHaveFocus());

      stepupFn = () => err(401, "session_expired");
      await userEvent.type(screen.getByLabelText(ru.stepup.label), "111111");
      await waitFor(() => expect(spy).toHaveBeenCalledTimes(1));
      await waitFor(() => expect(screen.queryByText(ru.stepup.title)).toBeNull());
    } finally {
      setUnauthorizedHandler(undefined);
    }
  });

  it("does not retry a second stepup_required", async () => {
    deleteFn = () => err(403, "stepup_required");
    stepupFn = () => new HttpResponse(null, { status: 204 });
    open();
    const { result } = renderHook(useDel, { wrapper });
    const done = result.current.mutateAsync(5);
    const rejected = expect(done).rejects.toMatchObject({ code: "stepup_required" });
    await userEvent.type(await screen.findByLabelText(ru.stepup.label), "123456");
    await rejected;
    expect(hits.delete).toBe(2);
  });
});

describe("error codes", () => {
  it("every API error code has a translation", () => {
    const yaml = readFileSync(path.resolve(__dirname, "../../../../../api/openapi.yaml"), "utf8");
    const block = yaml.slice(yaml.indexOf("- bad_request"), yaml.indexOf("message: { type: string, description: \"Human-readable"));
    const codes = [...block.matchAll(/^\s+- (\w+)/gm)].map((m) => m[1]);
    expect(codes.length).toBeGreaterThan(25);
    for (const code of codes) {
      const key = errorKey({ error: { code } });
      expect(key).toBe(`errors.${code}`);
      expect(ru.errors[code as keyof typeof ru.errors]).toBeTruthy();
    }
    expect(errorKey({ error: { code: "nope" } })).toBe("errors.unknown");
  });
});

describe("StateBadge", () => {
  it("renders the localized label and the since tooltip", () => {
    render(<StateBadge state="down" since="2026-01-02T03:04:05Z" />);
    const el = screen.getByText(ru.state.down);
    expect(el).toHaveAttribute("data-state", "down");
    expect(el.title).toMatch(/^с /);
  });
});
