import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import "@/i18n";
import i18n from "@/i18n";
import "./builtin";
import { mergeChanges } from "./recentChanges";
import { getWidget, listWidgets } from "./registry";
import { formatUptime } from "./topDevices";

vi.mock("@tanstack/react-router", async (orig) => ({ ...(await orig<typeof import("@tanstack/react-router")>()), useNavigate: () => vi.fn() }));
afterEach(cleanup);

/* the closed set of internal/httpapi/dashboards_handlers.go */
const SERVER_TYPES = ["device_status", "problems", "top_devices", "log_stream", "metric_chart", "top_interfaces", "recent_changes", "mini_map"];

describe("built-in widgets", () => {
  it("register exactly the types the server accepts, each with a valid default config, size and translated texts", () => {
    expect(listWidgets().map((w) => w.type)).toEqual(SERVER_TYPES);
    for (const w of listWidgets()) {
      /* the metric chart starts without a device; the user picks one before saving */
      const config = w.type === "metric_chart" ? { ...w.defaultConfig, device_id: 1 } : w.defaultConfig;
      expect(w.configSchema.safeParse(config).success, w.type).toBe(true);
      expect(w.size.w).toBeLessThanOrEqual(12);
      expect(i18n.exists(w.title) && i18n.exists(w.description), w.type).toBe(true);
      for (const f of w.fields ?? []) expect(i18n.exists(f.label), `${w.type}.${f.key}`).toBe(true);
    }
  });

  it("refuse what the server refuses: unknown fields, long or control-character titles, bounds, enum values", () => {
    const bad: [string, unknown][] = [
      ["device_status", { group_id: 1 }],
      ["device_status", { title: "я".repeat(101) }],
      ["device_status", { title: "a\nb" }],
      ["problems", { limit: 0 }],
      ["problems", { limit: 51 }],
      ["problems", { limit: 1.5 }],
      ["problems", { severity_min: "critical" }],
      ["top_devices", {}],
      ["top_devices", { metric: "disk" }],
      ["log_stream", { kind: "storm" }],
      ["log_stream", { limit: 101 }],
      ["metric_chart", { metric: "cpu" }],
      ["metric_chart", { device_id: 1, metric: "traffic" }],
      ["metric_chart", { device_id: 1, metric: "cpu", if_index: 1 }],
      ["metric_chart", { device_id: 1, metric: "cpu", range: "2h" }],
      ["mini_map", { view_id: 0 }],
    ];
    for (const [type, config] of bad) expect(getWidget(type)?.configSchema.safeParse(config).success, `${type} ${JSON.stringify(config)}`).toBe(false);
    expect(getWidget("metric_chart")?.configSchema.safeParse({ device_id: 3, metric: "traffic", if_index: 2, range: "7d" }).success).toBe(true);
    expect(getWidget("device_status")?.configSchema.safeParse({ title: "я".repeat(100) }).success).toBe(true);
  });

  it("render device text from the log stream as text only", () => {
    const hostile = '<img src=x onerror="alert(1)"><b>bold</b>';
    const def = getWidget("log_stream")!;
    const { container } = render(
      <>
        {def.render(
          [{ ts: new Date().toISOString(), kind: "syslog", device_id: 1, device_name: "<script>x</script>", severity: "high", app: "sshd", text: `${hostile}‮`, identified: true }],
          {},
        )}
      </>,
    );
    expect(container.querySelector("img, b, script")).toBeNull();
    expect(screen.getByTestId("log-stream").textContent).toContain(hostile);
    expect(screen.getByTestId("log-stream").textContent).not.toContain("‮");
  });
});

describe("widget helpers", () => {
  it("formats uptime with its two largest units", () => {
    const t = i18n.t.bind(i18n);
    expect(formatUptime(t, 3 * 86400 + 4 * 3600 + 59)).toBe("3 д 4 ч");
    expect(formatUptime(t, 5 * 3600 + 12 * 60)).toBe("5 ч 12 мин");
    expect(formatUptime(t, 40 * 60)).toBe("40 мин");
  });

  it("merges drift and topology changes newest first, keeping n", () => {
    const link = (id: number, at: string) =>
      ({ id, at, change: "appeared", source: "lldp", link_id: null, a_device_id: 1, a_device_name: "a", a_if_index: null, a_port_name: "", b_device_id: 2, b_device_name: "b", b_if_index: null, b_port_name: "" }) as const;
    const got = mergeChanges(
      [{ version_id: 9, device_id: 1, device_name: "a", taken_at: "2026-10-01T10:00:00Z" }],
      [link(1, "2026-10-01T11:00:00Z"), link(2, "2026-10-01T09:00:00Z")],
      2,
    );
    expect(got.map((c) => c.key)).toEqual(["l1", "d9"]);
  });
});
