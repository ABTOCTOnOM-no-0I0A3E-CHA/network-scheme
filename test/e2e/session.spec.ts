import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { FrameLocator, Page } from "@playwright/test";
import { generate } from "otplib";
import { expect, ORIGIN, testWith } from "./guard";

/*
 * The change session end to end (Task 4c.6): the panel's device window opens the executor in the shell's dock, the
 * session runs on a write emulator of each line (mes6, esr) and every step goes through the real executor: open →
 * safe line → dangerous line (exact device name + new code) → form with its equivalent commands → diff → save (MES) /
 * commit + confirm (ESR) → rollback (confirm(H)) → end → replay of the recording. Navigation in the panel must not
 * tear the session down; both origins must stay free of CSP violations (guard.ts watches every frame); device text
 * is only ever text.
 *
 * Preconditions (CI job e2e, after "The executor is off after install (C1), then enable, enroll and grant"):
 *   - a write emulator per line in the devices subnet, registered on the host: nmsctl executor device add (+
 *     accept-hostkey, writes on, model-verify for its profile) with a write credential, and the panel device of
 *     the same address;
 *   - the admin has the change TOTP of change-totp-secret (enroll) and the grants write (the devices' write
 *     groups) and audit-read;
 *   - NMS_E2E_SESSION_DEVICES names the panel devices: "mes6=<id>,esr=<id>".
 * Without NMS_E2E_SESSION_DEVICES the specs are skipped (the CI wiring of the write emulators is an open item).
 */
const EXECUTOR = process.env.NMS_E2E_EXECUTOR_ORIGIN ?? "https://localhost:8443";
const test = testWith([ORIGIN, EXECUTOR]);
const DEVICES = Object.fromEntries(
  (process.env.NMS_E2E_SESSION_DEVICES ?? "")
    .split(",")
    .map((p) => p.split("="))
    .filter((p) => p.length === 2 && /^\d+$/.test(p[1]))
    .map(([line, id]) => [line, Number(id)]),
) as Record<string, number>;
const dir = process.env.NMS_E2E_DIR ?? "/tmp/nms-e2e";

/*
 * Change TOTP codes: the executor takes a code only once and a confirmation only with a step above the last one
 * used, so every code here waits for a step after the previous one (one worker, in order).
 */
const PERIOD = 30;
let lastStep = 0;
async function changeCode(): Promise<string> {
  const now = () => Math.floor(Date.now() / 1000 / PERIOD);
  while (now() <= lastStep) await new Promise((r) => setTimeout(r, 1000));
  lastStep = now();
  return generate({ secret: readFileSync(join(dir, "change-totp-secret"), "utf8").trim(), epoch: lastStep * PERIOD });
}

/* per line: a dangerous config line harmless to the emulator, the prompt of its config mode and the save step */
const LINES = {
  mes6: { danger: "snmp-server community e2e-ro ro", config: "configure", vlan: 3077 },
  esr: { danger: "snmp-server community e2e-ro ro", config: "configure", vlan: 3078 },
} as const;

const frame = (page: Page) => page.frameLocator('iframe[title="Сессия изменений"]');
const term = (f: FrameLocator, device: number) => f.getByTestId(`device-term-${device}`).getByTestId("terminal");

async function typeLine(page: Page, f: FrameLocator, device: number, line: string) {
  await term(f, device).click();
  await page.keyboard.type(line);
  await page.keyboard.press("Enter");
}

/* Device text is a text node only: the terminal holds no element but the caret. */
async function textOnly(f: FrameLocator, device: number) {
  await expect(term(f, device).locator("*:not([data-testid=caret])")).toHaveCount(0);
}

async function openSession(page: Page, device: number): Promise<FrameLocator> {
  await page.goto(`/devices/${device}?tab=session`);
  await page.getByRole("button", { name: "Открыть сессию для этого устройства" }).click();
  const f = frame(page);
  await expect(f.locator("#ss-devices")).toHaveValue(String(device));
  await f.locator("#ss-code").fill(await changeCode());
  await f.getByRole("button", { name: "Открыть сессию" }).click();
  await expect(f.getByTestId("session-view")).toBeVisible();
  await expect(f.getByTestId("timer")).toContainText("Осталось");
  return f;
}

for (const line of ["mes6", "esr"] as const) {
  test.describe(`change session on ${line}`, () => {
    test.skip(!DEVICES[line], `NMS_E2E_SESSION_DEVICES names no ${line} device (the write emulators are not wired into this run)`);
    test.setTimeout(10 * 60_000);

    test("open, dangerous line, form, diff, save, rollback, end and replay; navigation keeps the session", async ({ page }) => {
      const id = DEVICES[line];
      const L = LINES[line];
      const f = await openSession(page, id);

      /* a safe line goes; its output is text */
      await typeLine(page, f, id, "show version");
      await expect(term(f, id)).toContainText("show version");
      await textOnly(f, id);

      /* navigation in the panel does not tear the session down (FR-CHG-7) */
      const sessionId = await f.getByTestId("session-id").textContent();
      await page.getByRole("link", { name: "Проблемы" }).click();
      await expect(page).toHaveURL(/\/problems/);
      await page.goBack();
      await expect(f.getByTestId("session-id")).toHaveText(sessionId ?? "");
      await expect(f.getByTestId("session-view")).toBeVisible();

      /* a dangerous line: the challenge shows the registry's address and H; the exact name and a new code send it */
      await typeLine(page, f, id, L.config);
      await typeLine(page, f, id, L.danger);
      const dlg = f.getByTestId("dangerous-dialog");
      await expect(dlg.getByTestId("dangerous-line")).toHaveText(L.danger);
      await dlg.getByRole("button", { name: "Запросить подтверждение" }).click();
      await expect(dlg.getByTestId("h")).toContainText(/H: [0-9a-f]{64}/);
      await expect(dlg.getByTestId("field-address")).toHaveText(/^\d+\.\d+\.\d+\.\d+:\d+$/);
      const name = (await dlg.getByTestId("field-device").textContent()) ?? "";
      await dlg.locator("#dg-name").fill(`${name}x`);
      await dlg.locator("#cp-code").fill(await changeCode());
      await expect(dlg.getByRole("button", { name: "Отправить команду" })).toBeDisabled();
      await dlg.locator("#dg-name").fill(name);
      await dlg.getByRole("button", { name: "Отправить команду" }).click();
      await expect(dlg).toHaveCount(0);
      await expect(term(f, id)).toContainText(L.danger);
      await textOnly(f, id);
      await typeLine(page, f, id, "end");

      /* a form: the equivalent commands are shown exactly and applied as shown */
      await f.locator(`#fm-kind-${id}`).selectOption("vlan-create");
      await f.locator(`#fm-vlan-${id}`).fill(String(L.vlan));
      await f.getByRole("button", { name: "Показать команды" }).click();
      const lines = f.getByTestId("equivalent-line");
      await expect(lines.filter({ hasText: String(L.vlan) })).not.toHaveCount(0);
      await f.getByRole("button", { name: /Применить/ }).click();
      await expect(f.getByText(/Отправлено строк: \d+/)).toBeVisible();

      /* the diff shows both changes */
      await f.getByRole("button", { name: "Diff", exact: true }).first().click();
      const diff = f.getByTestId("diff-dialog");
      await expect(diff).toContainText("e2e-ro");
      await expect(diff).toContainText(String(L.vlan));
      await diff.getByRole("button", { name: "Закрыть" }).click();

      if (line === "esr") {
        /* ESR: commit (confirm timer of the policy), the banner counts down, then the confirm */
        await f.getByRole("button", { name: "Commit" }).click();
        const banner = f.getByTestId(`esr-banner-${id}`);
        await expect(banner).toContainText(/не подтверждена, автооткат через \d+ с/);
        await banner.getByRole("button", { name: "Подтвердить" }).click();
        await f.getByTestId("save-dialog").getByRole("button", { name: "Подтвердить конфигурацию" }).click();
        await expect(banner).toHaveCount(0);
      } else {
        await f.getByTestId("save-button").click();
        await f.getByTestId("save-dialog").getByRole("button", { name: "Сохранить в startup-config" }).click();
        await expect(f.getByText(`Конфигурация устройства ${id} сохранена в startup-config.`)).toBeVisible();
      }

      /* the whole session rolls back under confirm(H): every field shown, the registry address of the device */
      await f.getByRole("button", { name: "Откатить" }).first().click();
      const rb = f.getByTestId("rollback-dialog");
      await rb.getByRole("button", { name: "Показать описание отката" }).click();
      await expect(rb.getByTestId(`field-address_${id}`)).toHaveText(/^\d+\.\d+\.\d+\.\d+:\d+$/);
      await expect(rb.getByTestId("h")).toContainText(/H: [0-9a-f]{64}/);
      await rb.locator("#cp-code").fill(await changeCode());
      await rb.getByRole("button", { name: "Откатить" }).click();
      await expect(rb.getByTestId("rollback-result")).toContainText("совпадает со снимком");
      await rb.getByRole("button", { name: "Закрыть" }).click();
      await f.getByRole("button", { name: "Diff", exact: true }).first().click();
      await expect(f.getByTestId("diff-dialog")).toContainText("Изменений нет");
      await f.getByTestId("diff-dialog").getByRole("button", { name: "Закрыть" }).click();

      /* end, then the recording of this device in the executor's player */
      await f.getByRole("button", { name: "Завершить" }).first().click();
      await f.getByTestId("end-dialog").getByRole("button", { name: "Завершить сессию" }).click();
      await expect(f.getByTestId("session-ended")).toBeVisible();
      await page.getByRole("button", { name: "Свернуть" }).click();
      await page.goto(`/devices/${id}?tab=journal`);
      const row = page.getByTestId(`session-${sessionId}`);
      await row.getByRole("button", { name: "Воспроизвести" }).click();
      const g = frame(page);
      await g.locator("input[name=rec-code]").fill(await changeCode());
      await g.getByTestId("play-initial").click();
      await g.getByRole("button", { name: "Показать всё" }).click();
      const player = g.getByTestId("player").getByTestId("terminal");
      await expect(player).toContainText(L.danger);
      await expect(player).toContainText("dangerous line confirmed");
      await expect(player.locator("*")).toHaveCount(0);
    });
  });
}
