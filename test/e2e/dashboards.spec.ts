import { expect, test } from "./guard";

/*
 * Dashboards end to end: a new personal dashboard gets every FR-DASH-3 widget from the catalog, each one is configured in
 * its settings dialog, the dashboard is saved, and after a reload every widget renders again with its stored settings.
 * The metric chart needs a device: backups.spec.ts (run before, in file order) leaves its devices in place.
 */
type Widget = { type: string; name: string; config: Record<string, unknown>; fill: Record<string, string> };

test("dashboard with every widget is saved and restored", async ({ page }) => {
  test.setTimeout(5 * 60_000);
  const api = page.request;
  const devices = (await (await api.get("/api/devices")).json()) as { id: number; name: string }[];
  expect(devices.length, "a device for the metric chart").toBeGreaterThan(0);
  const device = devices[0];
  const title = (type: string) => `e2e ${type}`;

  /* Catalog name, the settings the test sets (field label -> value) and the config the server must store. */
  const widgets: Widget[] = [
    { type: "device_status", name: "Устройства по статусу", fill: {}, config: {} },
    { type: "problems", name: "Проблемы", fill: { "Важность не ниже": "warning", "Количество строк": "5" }, config: { severity_min: "warning", limit: 5 } },
    { type: "top_devices", name: "Топ устройств", fill: { Показатель: "mem", "Количество строк": "5" }, config: { metric: "mem", limit: 5 } },
    { type: "log_stream", name: "Поток логов", fill: { "Тип событий": "syslog", "Количество строк": "10" }, config: { kind: "syslog", limit: 10 } },
    {
      type: "metric_chart",
      name: "График метрики",
      fill: { Устройство: String(device.id), Показатель: "cpu", Период: "1h" },
      config: { device_id: device.id, metric: "cpu", range: "1h" },
    },
    { type: "top_interfaces", name: "Загруженные интерфейсы", fill: { "Количество строк": "5" }, config: { limit: 5 } },
    { type: "recent_changes", name: "Последние изменения", fill: { "Количество строк": "5" }, config: { limit: 5 } },
    { type: "mini_map", name: "Мини-карта", fill: {}, config: {} },
  ];

  await page.goto("/");
  await page.getByRole("button", { name: "Новый дашборд" }).click();
  const create = page.getByRole("dialog");
  const name = `e2e-dashboard-${Date.now()}`;
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
  const stored = (await (await api.get(`/api/dashboards/${id}`)).json()) as { name: string; widgets: { type: string; config: Record<string, unknown> }[] };
  expect(stored.name).toBe(name);
  const byType = (a: { type: string }, b: { type: string }) => a.type.localeCompare(b.type);
  expect(stored.widgets.map((w) => ({ type: w.type, config: w.config })).sort(byType)).toEqual(
    widgets.map((w) => ({ type: w.type, config: { title: title(w.type), ...w.config } })).sort(byType),
  );

  /* After a reload the dashboard is restored and every widget renders its data (or its empty state), without errors. */
  await page.reload();
  await expect(page.getByLabel("Дашборд", { exact: true })).toHaveValue(String(id));
  for (const w of widgets) {
    const section = page.locator(`section[data-widget="${w.type}"]`);
    await expect(section).toHaveAttribute("aria-label", title(w.type));
    await expect(section.getByRole("alert")).toHaveCount(0);
    if (w.type !== "mini_map") await expect(section.locator('[data-slot="skeleton"]')).toHaveCount(0, { timeout: 30_000 });
  }
  const widget = (type: string) => page.locator(`section[data-widget="${type}"]`);
  await expect(widget("device_status").getByTestId("device-total")).toHaveText(`${devices.length} всего`);
  await expect(widget("metric_chart").locator("canvas").or(widget("metric_chart").getByText("За период данных нет")).first()).toBeVisible();
  await expect(widget("mini_map").getByRole("button", { name: "Открыть" })).toBeVisible();
  await expect(widget("mini_map").locator('[data-testid="mini-map-box"]')).toBeVisible();
});
