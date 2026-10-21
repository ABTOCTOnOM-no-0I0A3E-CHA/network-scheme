import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { IfChart, buildOptions } from "./IfChart";

/* uPlot draws with Path2D, which jsdom lacks */
vi.hoisted(() => {
  (globalThis as { Path2D?: unknown }).Path2D = class {
    moveTo() {}
    lineTo() {}
    closePath() {}
    rect() {}
    arc() {}
    bezierCurveTo() {}
    addPath() {}
  };
});

/* jsdom has no canvas: a no-op 2D context lets the real uPlot run */
const ctx = new Proxy(
  {},
  {
    get: (_t, p) => (p === "measureText" ? () => ({ width: 10 }) : p === "canvas" ? document.createElement("canvas") : () => ({ addColorStop() {} })),
    set: () => true,
  },
);

const pt = (ts: string, over: Record<string, unknown> = {}) => ({
  ts,
  in_bps: 1000,
  in_bps_max: 1000,
  out_bps: 2000,
  out_bps_max: 2000,
  in_err_ps: null,
  out_err_ps: null,
  in_disc_ps: null,
  out_disc_ps: null,
  oper_up: true,
  speed_bps: 1e9,
  ...over,
});

const range = { from: new Date("2026-10-21T10:00:00Z"), to: new Date("2026-10-21T11:00:00Z") };
const steps: (string | null)[] = [];
let handler: (n: number) => Response;
const server = setupServer(
  http.get("*/api/devices/7/metrics/if", ({ request }) => {
    steps.push(new URL(request.url).searchParams.get("step"));
    return handler(steps.length);
  }),
);
const tooMany = () => HttpResponse.json({ error: { code: "too_many_points", message: "RAW SERVER MESSAGE" } }, { status: 400 });

function renderChart() {
  const qc = new QueryClient({ defaultOptions: { queries: { gcTime: 0 } } });
  return render(
    <QueryClientProvider client={qc}>
      <IfChart deviceId={7} ifIndex={3} range={range} />
    </QueryClientProvider>,
  );
}

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterAll(() => server.close());
beforeEach(() => {
  steps.length = 0;
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(ctx as unknown as CanvasRenderingContext2D);
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  vi.restoreAllMocks();
});

describe("IfChart", () => {
  it("sends a step, renders with the real uPlot and injects no style element", async () => {
    const before = document.querySelectorAll("style").length;
    handler = () => HttpResponse.json({ step_s: 10, points: [pt("2026-10-21T10:00:00Z"), pt("2026-10-21T10:00:10Z", { in_err_ps: 1 })] });
    const { container } = renderChart();
    await waitFor(() => expect(container.querySelector(".uplot")).not.toBeNull());
    expect(container.querySelectorAll(".uplot")).toHaveLength(2);
    expect(document.querySelectorAll("style")).toHaveLength(before);
    expect(steps).toEqual(["10"]);
  });

  it("repeats once with a coarser step on too_many_points", async () => {
    handler = (n) => (n === 1 ? tooMany() : HttpResponse.json({ step_s: 20, points: [pt("2026-10-21T10:00:00Z")] }));
    const { container } = renderChart();
    await waitFor(() => expect(container.querySelector(".uplot")).not.toBeNull());
    expect(steps).toEqual(["10", "20"]);
  });

  it("shows a translated message, not the server text, when the retry fails too", async () => {
    handler = () => tooMany();
    renderChart();
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.too_many_points);
    expect(screen.queryByText(/RAW SERVER MESSAGE/)).toBeNull();
    expect(steps).toHaveLength(2);
  });

  it("shows an empty state for no points", async () => {
    handler = () => HttpResponse.json({ step_s: 10, points: [] });
    renderChart();
    expect(await screen.findByText(ru.chart.empty)).toBeInTheDocument();
  });

  it("omits the error chart when every error value is NULL", async () => {
    handler = () => HttpResponse.json({ step_s: 10, points: [pt("2026-10-21T10:00:00Z")] });
    const { container } = renderChart();
    expect(await screen.findByText(ru.chart.noErrors)).toBeInTheDocument();
    expect(container.querySelectorAll(".uplot")).toHaveLength(1);
  });
});

describe("buildOptions", () => {
  it("uses local time, no gap bridging and formatted axis values", () => {
    const o = buildOptions(600, [{ label: "a", fmt: (v) => `${v}!` }], (v) => `${v}u`);
    const ts = Date.UTC(2026, 9, 21, 12, 0, 0) / 1000;
    expect(o.tzDate!(ts).getTime()).toBe(ts * 1000);
    expect(o.scales!.x!.time).toBe(true);
    expect((o.series![1] as { spanGaps: boolean }).spanGaps).toBe(false);
    expect((o.axes![1] as { values: (u: unknown, s: number[]) => string[] }).values(null, [1, 2])).toEqual(["1u", "2u"]);
    const val = (o.series![1] as { value: (u: unknown, v: number | null) => string }).value;
    expect(val(null, null)).toBe("-");
    expect(val(null, 5)).toBe("5!");
  });
});
