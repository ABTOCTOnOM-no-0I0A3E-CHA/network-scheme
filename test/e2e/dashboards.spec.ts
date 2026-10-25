import { writeFileSync } from "node:fs";
import type { APIRequestContext } from "@playwright/test";
import sodium from "libsodium-wrappers";
import { stepUp } from "./auth";
import { expect, test } from "./guard";

/*
 * Dashboards end to end: a new personal dashboard gets every FR-DASH-3 widget from the catalog, each one is configured in
 * its settings dialog, the dashboard is saved, and after a reload every widget renders again with its stored settings and
 * shows real data.
 *
 * The data comes from the device of problems.spec.ts (NMS_E2E_EVENT_PROBE, see .github/workflows/ci.yml): an snmpsim
 * container answering SNMPv2c with COMMUNITY (CPU, memory and interface counters; ifIndex 2 down) whose sender sends syslog
 * every few seconds and the trap named in the control file CONTROL. The test registers it with fast metric polls, opens an
 * interface problem with a linkDown trap and draws a manual link to a second device (a documentation address that is never
 * routed), which is a topology change. Everything it adds is deleted at the end; the dashboard itself stays (map.spec.ts
 * checks the mini map on the home page), dashboards of earlier runs are deleted first.
 */
type Widget = { type: string; name: string; config: Record<string, unknown>; fill: Record<string, string> };
const GROUP = "dashboards-e2e";
const PROBE = { name: "e2e-dashboard-probe", address: process.env.NMS_E2E_EVENT_PROBE ?? "" };
/* The link peer: an unused address of the devices subnet (as NMS_E2E_PROBE_DEAD, which ends in .250), so its pings stay off the egress check. */
const PEER = { name: "e2e-dashboard", address: PROBE.address.replace(/\.\d+$/, ".251") };
const COMMUNITY = "e2e-events-community-01";
const CONTROL = ".auth/trap-control";
const MARKER = "e2eprob"; /* the probe sender's syslog marker: its messages read e2eprobudp and e2eprobtcp (event search matches whole words) */
const PREFIX = "e2e-dashboard-";

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

/** Seals a read credential as the browser does: payload v1 (internal/creds), crypto_box_seal to the read key. */
async function seal(readKey: string, owner: string, kind: string, secret: object): Promise<string> {
  await sodium.ready;
  const payload = JSON.stringify({
    v: 1,
    owner,
    kind,
    created_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    nonce: b64(sodium.randombytes_buf(16)),
    secret,
  });
  return b64(sodium.crypto_box_seal(sodium.from_string(payload), Buffer.from(readKey, "base64")));
}

/** What the probe sends from now on: a linkDown trap for ifIndex 2 every round, or nothing. */
const sendTrap = (on: boolean) => writeFileSync(CONTROL, on ? "linkDown" : "");

const csrf = async (api: APIRequestContext) => ({ "X-CSRF-Token": ((await (await api.get("/api/auth/me")).json()) as { csrf_token: string }).csrf_token });
const getJSON = async <T>(api: APIRequestContext, path: string): Promise<T> => {
  const r = await api.get(path);
  expect(r.status(), path).toBe(200);
  return (await r.json()) as T;
};

test("dashboard with every widget is saved, restored and shows data", async ({ page }) => {
  test.setTimeout(10 * 60_000);
  expect(PROBE.address, "NMS_E2E_EVENT_PROBE (device container with a trap control file)").not.toBe("");
  sendTrap(false);
  const api = page.request;
  const title = (type: string) => `e2e ${type}`;
  type Device = { id: number; name: string; address: string };

  /* Credentials need a step-up (the cleanup takes another). */
  await stepUp(page);
  for (const d of (await getJSON<Device[]>(api, "/api/devices")).filter((x) => x.address === PROBE.address || x.address === PEER.address)) {
    expect((await api.delete(`/api/devices/${d.id}`, { headers: await csrf(api) })).status()).toBe(204);
  }
  for (const d of (await getJSON<{ id: number; name: string }[]>(api, "/api/dashboards")).filter((x) => x.name.startsWith(PREFIX))) {
    expect((await api.delete(`/api/dashboards/${d.id}`, { headers: await csrf(api) })).status()).toBe(204);
  }
  let group = (await getJSON<{ id: number; name: string }[]>(api, "/api/groups")).find((g) => g.name === GROUP)?.id;
  if (group === undefined) {
    const r = await api.post("/api/groups", { headers: await csrf(api), data: { name: GROUP } });
    expect(r.status()).toBe(201);
    group = ((await r.json()) as { id: number }).id;
  }
  const ids: number[] = [];
  const addDevice = async (d: { name: string; address: string }): Promise<number> => {
    const r = await api.post("/api/devices", { headers: await csrf(api), data: { ...d, group_id: group } });
    expect(r.status()).toBe(201);
    const id = ((await r.json()) as { id: number }).id;
    ids.push(id);
    return id;
  };

  try {
    const probe = await addDevice(PROBE);
    const peer = await addDevice(PEER);
    /* metrics every 10 s: the interface load needs two samples */
    expect((await api.patch(`/api/devices/${probe}`, { headers: await csrf(api), data: { interval_metrics_s: 10 } })).status()).toBe(204);
    const read = (await getJSON<{ domains: { read: { public_key: string; key_version: number } } }>(api, "/keys.json")).domains.read;
    const ciphertext = await seal(read.public_key, `device:${probe}`, "snmp2c", { community: COMMUNITY });
    expect((await api.put(`/api/devices/${probe}/profiles/snmp2c`, { headers: await csrf(api), data: { ciphertext, key_version: read.key_version } })).status()).toBe(204);
    expect((await api.post(`/api/devices/${probe}/poll`, { headers: await csrf(api) })).status()).toBe(202);
    /* The default templates are bound to the driver, which the first inventory poll sets. */
    await expect
      .poll(
        async () => {
          const dev = await getJSON<{ state: string; driver: string }>(api, `/api/devices/${probe}`);
          return { state: dev.state, driver: dev.driver !== "" };
        },
        { timeout: 90_000, intervals: [2_000], message: "probe polled" },
      )
      .toEqual({ state: "up", driver: true });

    /* A problem: linkDown for ifIndex 2, which the polls agree with (it stays open after the trap stops). */
    sendTrap(true);
    await expect
      .poll(async () => (await getJSON<{ items: { state: string }[] }>(api, `/api/problems?device_id=${probe}&state=problem`)).items.length, {
        timeout: 60_000,
        intervals: [1_000],
        message: "problem of the trap",
      })
      .toBeGreaterThan(0);
    sendTrap(false);

    /* A topology change: a manual link appears in the change history at once. */
    const link = await api.post("/api/links", { headers: await csrf(api), data: { a_device_id: probe, b_device_id: peer } });
    expect(link.status()).toBe(201);

    /* Syslog of the probe, its CPU and memory, and the load of its interfaces are stored. */
    const has = async (path: string) => (await getJSON<{ items: { device_id: number }[] }>(api, path)).items.some((i) => i.device_id === probe);
    for (const path of [`/api/events?kind=syslog&device_id=${probe}&q=${MARKER}udp`, "/api/stats/top-devices?metric=cpu&limit=50", "/api/stats/top-devices?metric=mem&limit=50", "/api/stats/top-interfaces?limit=50"]) {
      await expect.poll(() => has(path), { timeout: 3 * 60_000, intervals: [3_000], message: path }).toBe(true);
    }

    /* Catalog name, the settings the test sets (field label -> value) and the config the server must store. */
    const widgets: Widget[] = [
      { type: "device_status", name: "Устройства по статусу", fill: {}, config: {} },
      { type: "problems", name: "Проблемы", fill: { "Важность не ниже": "warning", "Количество строк": "5" }, config: { severity_min: "warning", limit: 5 } },
      { type: "top_devices", name: "Топ устройств", fill: { Показатель: "mem", "Количество строк": "5" }, config: { metric: "mem", limit: 5 } },
      { type: "log_stream", name: "Поток логов", fill: { "Тип событий": "syslog", "Количество строк": "10" }, config: { kind: "syslog", limit: 10 } },
      {
        type: "metric_chart",
        name: "График метрики",
        fill: { Устройство: String(probe), Показатель: "cpu", Период: "1h" },
        config: { device_id: probe, metric: "cpu", range: "1h" },
      },
      { type: "top_interfaces", name: "Загруженные интерфейсы", fill: { "Количество строк": "5" }, config: { limit: 5 } },
      { type: "recent_changes", name: "Последние изменения", fill: { "Количество строк": "5" }, config: { limit: 5 } },
      { type: "mini_map", name: "Мини-карта", fill: {}, config: {} },
    ];

    await page.goto("/");
    await page.getByRole("button", { name: "Новый дашборд" }).click();
    const create = page.getByRole("dialog");
    const name = `${PREFIX}${Date.now()}`;
    await create.getByLabel("Название").fill(name);
    await create.getByRole("button", { name: "Создать" }).click();
    await expect(create).toBeHidden();
    await expect(page.getByText("На этом дашборде нет виджетов. Нажмите «Изменить», чтобы добавить их из каталога.")).toBeVisible();
    const id = Number(new URL(page.url()).searchParams.get("d"));
    expect(id).toBeGreaterThan(0);

    /* Edit mode: add each widget, open its settings, set a title and its own fields. */
    await page.getByRole("button", { name: "Изменить" }).click();
    for (const w of widgets) {
      await page.getByRole("button", { name: `Добавить виджет «${w.name}»` }).click();
      await page.getByRole("button", { name: `Настройки виджета «${w.name}»` }).click();
      const dialog = page.getByRole("dialog");
      await expect(dialog.getByRole("heading", { name: `Настройки: ${w.name}` })).toBeVisible();
      await dialog.getByLabel("Заголовок").fill(title(w.type));
      for (const [label, value] of Object.entries(w.fill)) {
        const field = dialog.getByLabel(label, { exact: true });
        if ((await field.evaluate((e) => e.tagName)) === "SELECT") await field.selectOption(value);
        else await field.fill(value);
      }
      await dialog.getByRole("button", { name: "Применить" }).click();
      await expect(dialog).toBeHidden();
      await expect(page.locator(`section[data-widget="${w.type}"]`)).toHaveAttribute("aria-label", title(w.type));
    }
    await page.getByRole("button", { name: "Сохранить" }).click();
    await expect(page.getByRole("button", { name: "Изменить" })).toBeVisible();

    /* The server stored every widget with its settings. */
    const stored = await getJSON<{ name: string; widgets: { type: string; config: Record<string, unknown> }[] }>(api, `/api/dashboards/${id}`);
    expect(stored.name).toBe(name);
    const byType = (a: { type: string }, b: { type: string }) => a.type.localeCompare(b.type);
    expect(stored.widgets.map((w) => ({ type: w.type, config: w.config })).sort(byType)).toEqual(
      widgets.map((w) => ({ type: w.type, config: { title: title(w.type), ...w.config } })).sort(byType),
    );

    /*
     * After a reload the dashboard is restored and every widget renders without errors: first every widget has finished
     * loading (no skeleton, no "loading" text), then none shows an alert, then each one shows data of the probe.
     */
    const devices = await getJSON<Device[]>(api, "/api/devices");
    await page.reload();
    await expect(page.getByLabel("Дашборд", { exact: true })).toHaveValue(String(id));
    const widget = (type: string) => page.locator(`section[data-widget="${type}"]`);
    for (const w of widgets) {
      await expect(widget(w.type)).toHaveAttribute("aria-label", title(w.type));
      if (w.type !== "mini_map") await expect(widget(w.type).locator('[data-slot="skeleton"]')).toHaveCount(0, { timeout: 30_000 });
      await expect(widget(w.type).getByText(/^Загрузка( графика| списка)?…$/)).toHaveCount(0, { timeout: 30_000 });
    }
    for (const w of widgets) await expect(widget(w.type).getByRole("alert"), w.type).toHaveCount(0);

    await expect(widget("device_status").getByTestId("device-total")).toHaveText(`${devices.length} всего`);
    expect(Number(await widget("device_status").getByTestId("device-count-up").textContent())).toBeGreaterThan(0);
    /* a row naming the probe in every list widget; the log line is its sender's message */
    for (const type of ["problems", "top_devices", "top_interfaces", "log_stream", "recent_changes"]) {
      await expect(widget(type).getByRole("button", { name: PROBE.name, exact: true }).first(), type).toBeVisible();
    }
    await expect(widget("log_stream").getByTestId("log-stream")).toContainText(MARKER);
    await expect(widget("recent_changes").getByRole("button", { name: PEER.name, exact: true }).first()).toBeVisible();
    await expect(widget("metric_chart").locator("canvas").first()).toBeVisible();
    await expect(widget("metric_chart").getByText("За период данных нет")).toHaveCount(0);
    await expect(widget("mini_map").getByRole("button", { name: "Открыть" })).toBeVisible();
    await expect(widget("mini_map").getByTestId("mini-map-box")).toBeVisible();
    const nodes = () =>
      widget("mini_map")
        .getByTestId("map-canvas")
        .evaluate((e) => (e as unknown as { _cyreg?: { cy: { nodes(): { length: number } } } })._cyreg?.cy.nodes().length ?? 0);
    await expect.poll(nodes, { timeout: 30_000, message: "mini map nodes" }).toBeGreaterThanOrEqual(2);
  } finally {
    /* Leave a clean stack: no trap, the test's devices (their link, problems and metrics go with them) and group. */
    sendTrap(false);
    await stepUp(page);
    for (const d of ids) expect((await api.delete(`/api/devices/${d}`, { headers: await csrf(api) })).status()).toBe(204);
    await api.delete(`/api/groups/${group}`, { headers: await csrf(api) });
  }
});
