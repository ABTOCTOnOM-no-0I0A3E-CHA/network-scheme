import { stepUp } from "./auth";
import { expect, test } from "./guard";

/*
 * The simulator the CI job attaches to the devices network and its synthetic
 * SNMPv3 user (as in poll.spec.ts). The credential is typed into the browser
 * form, so the sealing under test happens in the browser.
 */
const SIM_ADDRESS = process.env.NMS_E2E_SNMPSIM ?? "";
const SIM_V3 = { user: "simuser", authKey: "sim-auth-key-0123456789", privKey: "sim-priv-key-0123456789" };
/* a scan target inside the management subnet with no hosts: nothing leaves the devices network */
const SCAN_CIDR = process.env.NMS_E2E_SCAN_CIDR ?? "172.30.1.240/29";
const GROUP = "ui-e2e";

type Csrf = Record<string, string>;

test("device added through the UI is polled, charted and a scan is scheduled", async ({ page }) => {
  test.setTimeout(10 * 60_000);
  expect(SIM_ADDRESS, "NMS_E2E_SNMPSIM (simulator address on the devices network)").not.toBe("");
  const api = page.request;
  const csrf = async (): Promise<Csrf> => ({ "X-CSRF-Token": ((await (await api.get("/api/auth/me")).json()) as { csrf_token: string }).csrf_token });

  /* One step-up covers every change below (valid for 5 minutes), so the dialog never interrupts the flow. */
  await stepUp(page);

  /* The address is unique and poll.spec.ts leaves a device on it: free it. */
  const existing = (await (await api.get("/api/devices")).json()) as { id: number; address: string }[];
  for (const d of existing.filter((x) => x.address === SIM_ADDRESS)) {
    expect((await api.delete(`/api/devices/${d.id}`, { headers: await csrf() })).status()).toBe(204);
  }
  const groups = (await (await api.get("/api/groups")).json()) as { id: number; name: string }[];
  if (!groups.some((g) => g.name === GROUP)) {
    expect((await api.post("/api/groups", { headers: await csrf(), data: { name: GROUP } })).status()).toBe(201);
  }

  /* Add the device in the UI and give it an SNMPv3 credential. */
  await page.goto("/");
  await page.getByRole("link", { name: "Устройства" }).click();
  await expect(page.getByRole("heading", { name: "Устройства" })).toBeVisible();
  await page.getByRole("button", { name: "Добавить устройство" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Имя", { exact: true }).fill("ui-sim");
  await dialog.getByLabel("Адрес", { exact: true }).fill(SIM_ADDRESS);
  await dialog.getByLabel("Группа", { exact: true }).selectOption({ label: GROUP });
  await dialog.getByRole("button", { name: "Создать" }).click();
  await expect(dialog.getByText("Учётка устройства")).toBeVisible();
  await dialog.getByLabel("Тип учётки").selectOption({ label: "SNMPv3" });
  await dialog.getByLabel("Пользователь", { exact: true }).fill(SIM_V3.user);
  await dialog.getByLabel("Протокол аутентификации").selectOption("SHA256");
  await dialog.getByLabel("Ключ аутентификации").fill(SIM_V3.authKey);
  await dialog.getByLabel("Протокол шифрования").selectOption("AES");
  await dialog.getByLabel("Ключ шифрования", { exact: true }).fill(SIM_V3.privKey);
  await dialog.getByRole("button", { name: "Сохранить" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("button", { name: "ui-sim" })).toBeVisible();

  const device = ((await (await api.get("/api/devices")).json()) as { id: number; name: string }[]).find((d) => d.name === "ui-sim");
  expect(device, "device created through the UI").toBeDefined();
  const id = device!.id;
  const profiles = (await (await api.get(`/api/devices/${id}/profiles`)).json()) as { kind: string }[];
  expect(profiles.map((p) => p.kind)).toEqual(["snmp3"]);

  /* Discovery: the API errors for a too wide and a reserved prefix are explained, a valid scan gets its own credential. */
  await page.getByRole("link", { name: "Обнаружение" }).click();
  await expect(page.getByRole("heading", { name: "Обнаружение" })).toBeVisible();
  const scan = async (cidr: string) => {
    await page.getByLabel("Подсеть (CIDR)").fill(cidr);
    await page.getByLabel("Интервал, с").fill("3600");
    await page.getByRole("button", { name: "Запланировать" }).click();
  };
  await scan("10.0.0.0/8");
  await expect(page.getByRole("alert").filter({ hasText: "шире /16" })).toBeVisible();
  await scan("127.0.0.0/24");
  await expect(page.getByRole("alert").filter({ hasText: "Недопустимая подсеть" })).toBeVisible();
  await scan(SCAN_CIDR);
  const credDialog = page.getByRole("dialog");
  await expect(credDialog.getByText("Учётка сканирования")).toBeVisible();
  await credDialog.getByLabel("Тип учётки").selectOption({ label: "SNMPv3" });
  await credDialog.getByLabel("Пользователь", { exact: true }).fill(SIM_V3.user);
  await credDialog.getByLabel("Протокол аутентификации").selectOption("SHA256");
  await credDialog.getByLabel("Ключ аутентификации").fill(SIM_V3.authKey);
  await credDialog.getByLabel("Протокол шифрования").selectOption("AES");
  await credDialog.getByLabel("Ключ шифрования", { exact: true }).fill(SIM_V3.privKey);
  await credDialog.getByRole("button", { name: "Сохранить" }).click();
  await expect(credDialog).toBeHidden();
  await expect(page.getByRole("cell", { name: SCAN_CIDR })).toBeVisible();
  await expect(page.getByText("Новых находок нет")).toBeVisible();

  /* Device card: poll now, wait for up and interfaces. */
  await page.goto(`/devices/${id}`);
  await expect(page.getByRole("heading", { name: "ui-sim" })).toBeVisible();
  await page.getByRole("button", { name: "Опросить сейчас" }).click();
  await expect(page.getByText("Опрос поставлен в очередь")).toBeVisible();
  await expect
    .poll(
      async () => {
        const dev = (await (await api.get(`/api/devices/${id}`)).json()) as { state: string };
        const ifs = (await (await api.get(`/api/devices/${id}/interfaces`)).json()) as { items: unknown[] };
        return { state: dev.state, interfaces: ifs.items.length > 0 };
      },
      { timeout: 90_000, intervals: [2_000] },
    )
    .toEqual({ state: "up", interfaces: true });

  await page.reload();
  await expect(page.getByText("Доступно", { exact: true })).toBeVisible();
  await expect(page.getByRole("tabpanel").getByRole("row").nth(1)).toBeVisible();

  /* Charts: rates need two metric samples (the default interval is a minute); give them time, then open the chart. */
  const to = new Date();
  const from = new Date(to.getTime() - 3600_000);
  const ifIndex = ((await (await api.get(`/api/devices/${id}/interfaces`)).json()) as { items: { if_index: number }[] }).items[0].if_index;
  await expect
    .poll(
      async () => {
        const r = await api.get(`/api/devices/${id}/metrics/if`, { params: { if_index: ifIndex, from: from.toISOString(), to: new Date().toISOString() } });
        return r.ok() ? ((await r.json()) as { points: unknown[] }).points.length > 0 : false;
      },
      { timeout: 180_000, intervals: [5_000] },
    )
    .toBe(true);
  await page.getByRole("tab", { name: "Графики" }).click();
  await page.locator('[data-slot="device-charts"] select').selectOption(String(ifIndex));
  await page.getByRole("button", { name: "Обновить" }).click();
  await expect(page.locator('[data-slot="if-chart"] canvas').first()).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});
