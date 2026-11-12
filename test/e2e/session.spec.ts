import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { FrameLocator, Locator, Page } from "@playwright/test";
import { generate } from "otplib";
import { clickGated, confirmCode } from "./gated";
import { expect, ORIGIN, testWith } from "./guard";

/*
 * The change session end to end (Task 4c.6): the panel's device window opens the executor in the shell's dock, the
 * session runs on a write emulator of each line (mes6, esr) and every step goes through the real executor: open →
 * safe line → dangerous line (exact device name + new code) → form with its equivalent commands → diff → save (MES) /
 * commit + confirm (ESR) → rollback (confirm(H)) → end → replay of the recording. Navigation in the panel must not
 * tear the session down; both origins must stay free of CSP violations (guard.ts watches every frame); device text
 * is only ever text. Before the session the write credential goes in through the executor's page (write-admin +
 * confirm(H)); after it, the pre-session configuration is shown unmasked (unmask + confirm(H)) and the executor's
 * audit shows that view.
 *
 * Preconditions (CI job e2e, "Register the write emulators with the executor (session e2e)"):
 *   - a write emulator per line in the devices subnet (sshemud -profile, account WRITE below), registered on the
 *     host: the panel device of the same address, nmsctl executor device add with the logged host key, writes on,
 *     model-verify for its profile;
 *   - the admin has the change TOTP of change-totp-secret (enroll) and the grants write-admin, write (the devices'
 *     write group), audit-read and unmask;
 *   - NMS_E2E_SESSION_DEVICES names the panel devices: "mes6=<id>,esr=<id>".
 * Without NMS_E2E_SESSION_DEVICES the specs are skipped (a run without the write emulators).
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
/* the last step used, in a file: Playwright restarts the worker after a failed test, and a step used before the
   restart must not be sent again (the executor refuses a replayed code and counts it as a failure) */
const STEP_FILE = "/tmp/nms-e2e-change-totp-step";
async function changeCode(): Promise<string> {
  const now = () => Math.floor(Date.now() / 1000 / PERIOD);
  let lastStep = 0;
  try {
    lastStep = Number(readFileSync(STEP_FILE, "utf8")) || 0;
  } catch {
    /* first code of the run */
  }
  while (now() <= lastStep) await new Promise((r) => setTimeout(r, 1000));
  lastStep = now();
  writeFileSync(STEP_FILE, String(lastStep));
  return generate({ secret: readFileSync(join(dir, "change-totp-secret"), "utf8").trim(), epoch: lastStep * PERIOD });
}

/*
 * per line: a dangerous config line harmless to the emulator, the same line as the diff and the recording show it (the
 * community is a secret: masked there, its value only through the unmask grant), the command of its config mode, a VLAN
 * for the form and a line of its configuration
 */
const LINES = {
  mes6: { danger: "snmp-server community e2e-ro ro", masked: "snmp-server ***", config: "configure", vlan: 3077, iface: "interface vlan 99" },
  esr: { danger: "snmp-server community e2e-ro ro", masked: "snmp-server ***", config: "configure", vlan: 3078, iface: "interface gigabitethernet 1/0/1" },
} as const;

/* test values of the emulators' write account, the same as in the CI step that starts them */
const WRITE = { username: "e2e-write", password: "e2e-write-session-pw" };

const frame = (page: Page) => page.frameLocator('iframe[title="Сессия изменений"]');
const term = (f: FrameLocator, device: number) => f.getByTestId(`device-term-${device}`).getByTestId("terminal");

/* the device's write credential, sealed by the executor's page to its write key and stored under confirm(H) */
async function storeCredential(page: Page, device: number) {
  /* what the executor page asked for and got, for the error below (a refusal or a hang shows up here) */
  const net: string[] = [];
  page.on("request", (r) => {
    if (/\/x\/|\/api\/executor\/ticket/.test(r.url())) net.push(`-> ${r.method()} ${new URL(r.url()).pathname}`);
  });
  page.on("response", (r) => {
    if (/\/x\/|\/api\/executor\/ticket/.test(r.url())) net.push(`<- ${r.status()} ${new URL(r.url()).pathname}`);
  });
  page.on("requestfailed", (r) => net.push(`xx ${r.method()} ${r.url()} ${r.failure()?.errorText ?? ""}`));
  page.on("console", (m) => net.push(`console.${m.type()}: ${m.text().slice(0, 300)}`));
  await page.goto(`/devices/${device}?tab=session`);
  await page.getByRole("button", { name: "Открыть сессию для этого устройства" }).click();
  const f = frame(page);
  await f.getByTestId("nav-devices").click();
  await expect(f.getByTestId("write-key")).toBeVisible();
  await f.locator("#wc-device").fill(String(device));
  await f.locator("#wc-account").fill(WRITE.username);
  await f.locator("#wc-secret").fill(WRITE.password);
  await f.getByRole("button", { name: "Зашифровать и проверить" }).click();
  await f.locator("#cp-code").fill(await changeCode());
  await confirmCode(f, "Сохранить");
  /* either outcome is shown; a refusal fails with the executor's own words instead of a bare timeout */
  try {
    await expect(f.getByTestId("done").or(f.getByTestId("failure"))).toBeVisible({ timeout: 20_000 });
  } catch (e) {
    /* neither outcome: show what the executor page says instead (the step it is waiting on) */
    throw new Error(`write credential of device ${device}: no outcome; requests:
${net.join(String.fromCharCode(10))}
the page shows:
${(await f.locator("body").innerText()).slice(0, 2000)}`, { cause: e });
  }
  const failure = f.getByTestId("failure");
  if (await failure.isVisible()) throw new Error(`write credential of device ${device}: ${await failure.innerText()}`);
  await expect(f.getByTestId("done")).toContainText(`Учётка устройства ${device} сохранена`);
}

async function typeLine(page: Page, f: FrameLocator, device: number, line: string) {
  mark(`typing ${JSON.stringify(line)} into device ${device}`);
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
  try {
    await expect(f.getByTestId("session-view")).toBeVisible({ timeout: 30_000 });
  } catch (e) {
    /* the refusal the start screen shows (or the step it waits on), instead of a bare timeout */
    throw new Error(`open session on device ${device}: the page shows:${String.fromCharCode(10)}${(await f.locator("body").innerText()).slice(0, 2000)}`, { cause: e });
  }
  await expect(f.getByTestId("timer")).toContainText("Осталось");
  /* the devices the session is on, as the registry and the device name them: acknowledged before the terminal is usable */
  await expect(f.getByTestId(`opened-${device}`)).toBeVisible();
  await f.getByTestId("opened-on").getByRole("button", { name: "Всё верно" }).click();
  await expect(f.getByTestId("opened-on")).toHaveCount(0);
  return f;
}

const t0 = Date.now();
const at = () => `+${((Date.now() - t0) / 1000).toFixed(1)}s`;
/* where the scenario is, in the same list (typing, waiting) */
let mark: (s: string) => void = () => {};
function watch(page: Page, diag: string[]) {
  mark = (s) => diag.push(`${at()} -- ${s}`);
  page.on("websocket", (ws) => {
    diag.push(`${at()} ws open ${ws.url()}`);
    ws.on("framereceived", (f) => diag.push(`${at()} ws <- ${String(f.payload).slice(0, 160)}`));
    ws.on("framesent", (f) => diag.push(`${at()} ws -> ${String(f.payload).slice(0, 80)}`));
    ws.on("socketerror", (e) => diag.push(`${at()} ws error ${e}`));
    ws.on("close", () => diag.push(`${at()} ws closed ${ws.url()}`));
  });
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") diag.push(`${at()} console.${m.type()}: ${m.text().slice(0, 300)}`);
  });
  page.on("pageerror", (e) => diag.push(`${at()} pageerror: ${String(e).slice(0, 300)}`));
  /* every executor POST with its status; a refusal with its body (the executor's error code) */
  page.on("response", async (r) => {
    if (!r.url().includes("/x/") || r.request().method() !== "POST") return;
    const body = r.status() >= 400 ? ` ${(await r.text().catch(() => "")).slice(0, 300)}` : "";
    diag.push(`${at()} ${r.status()} POST ${new URL(r.url()).pathname}${body}`);
  });
}

for (const line of ["mes6", "esr"] as const) {
  test.describe(`change session on ${line}`, () => {
    test.skip(!DEVICES[line], `NMS_E2E_SESSION_DEVICES names no ${line} device (the write emulators are not wired into this run)`);
    /* a desktop-sized window: a confirmation is accepted only when its whole panel is in view (IntersectionObserver v2, threshold 1) */
    test.use({ viewport: { width: 1440, height: 1000 } });
    /* nine change TOTP codes, each waiting for a new 30 s step */
    test.setTimeout(15 * 60_000);
    /* the terminal's WebSocket and the page's errors, printed when the test fails (CI keeps no browser trace) */
    const diag: string[] = [];
    test.beforeEach(({ page }) => {
      diag.length = 0;
      watch(page, diag);
    });
    test.afterEach(({}, info) => {
      if (info.status !== info.expectedStatus) {
        console.log(`--- ${line} diagnostics (last 120 of ${diag.length}) ---${String.fromCharCode(10)}${diag.slice(-120).join(String.fromCharCode(10))}`);
      }
    });

    test("credential, open, dangerous line, form, diff, save, rollback, end, replay, unmasked config and audit; navigation keeps the session", async ({ page }) => {
      const id = DEVICES[line];
      const L = LINES[line];
      await storeCredential(page, id);
      const f = await openSession(page, id);

      /* a safe line goes; its output is text */
      await typeLine(page, f, id, "show version");
      await expect(term(f, id)).toContainText("show version");
      await textOnly(f, id);

      /* navigation in the panel does not tear the session down (FR-CHG-7) */
      const sessionId = await f.getByTestId("session-id").textContent();
      /* the expanded dock covers the lower part of the page: collapse it first, as an operator would to use the panel */
      await page.getByTestId("session-dock").getByRole("button", { name: "Свернуть" }).click();
      /* the sidebar remembers its collapsed state in a cookie; open it if an earlier step left it collapsed */
      const problems = page.getByRole("link", { name: "Проблемы" });
      if (!(await problems.isVisible())) await page.getByRole("button", { name: "Показать или скрыть меню" }).first().click();
      await problems.click();
      await expect(page).toHaveURL(/\/problems/);
      /* back through the app's own history: a page-level back waits for a load that the open session's beforeunload guard cancels */
      await page.evaluate(() => history.back());
      await expect(page).toHaveURL(/\/devices\//);
      await page.getByRole("button", { name: "Развернуть окно сессии" }).click();
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
      await confirmCode(dlg, "Отправить команду");
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
      await clickGated(f.getByRole("button", { name: /Применить/ }), f.getByText(/Отправлено строк: \d+/), "Применить");

      /* the diff shows both changes, the community masked (ESR: once committed, the candidate is not the running configuration) */
      const showsBoth = async () => {
        await f.getByRole("button", { name: "Diff", exact: true }).first().click();
        const diff = f.getByTestId("diff-dialog");
        await expect(diff).toContainText(L.masked);
        await expect(diff).not.toContainText("e2e-ro");
        await expect(diff).toContainText(String(L.vlan));
        await diff.getByRole("button", { name: "Закрыть" }).click();
      };

      if (line === "esr") {
        /* ESR: commit (confirm timer of the policy), the banner counts down, then the confirm */
        await f.getByRole("button", { name: "Commit", exact: true }).click();
        const banner = f.getByTestId(`esr-banner-${id}`);
        await clickGated(f.getByTestId("commit-dialog").getByRole("button", { name: "Выполнить commit" }), banner, "Выполнить commit");
        await expect(banner).toContainText(/не подтверждена, автооткат через \d+ с/);
        await showsBoth();
        await banner.getByRole("button", { name: "Подтвердить" }).click();
        await clickGated(f.getByTestId("save-dialog").getByRole("button", { name: "Подтвердить конфигурацию" }),
          f.getByText(`Конфигурация устройства ${id} подтверждена.`), "Подтвердить конфигурацию");
        await expect(banner).toHaveCount(0);
      } else {
        await showsBoth();
        await f.getByTestId("save-button").click();
        await clickGated(f.getByTestId("save-dialog").getByRole("button", { name: "Сохранить в startup-config" }),
          f.getByText(`Конфигурация устройства ${id} сохранена в startup-config.`), "Сохранить в startup-config");
      }

      /* the whole session rolls back under confirm(H): every field shown, the registry address of the device */
      await f.getByRole("button", { name: "Откатить" }).first().click();
      const rb = f.getByTestId("rollback-dialog");
      await rb.getByRole("button", { name: "Показать описание отката" }).click();
      await expect(rb.getByTestId(`field-address_${id}`)).toHaveText(/^\d+\.\d+\.\d+\.\d+:\d+$/);
      await expect(rb.getByTestId("h")).toContainText(/H: [0-9a-f]{64}/);
      await rb.locator("#cp-code").fill(await changeCode());
      await confirmCode(rb, "Откатить");
      await expect(rb.getByTestId("rollback-result")).toContainText("совпадает со снимком");
      await rb.getByRole("button", { name: "Закрыть" }).click();
      await f.getByRole("button", { name: "Diff", exact: true }).first().click();
      await expect(f.getByTestId("diff-dialog")).toContainText("Изменений нет");
      await f.getByTestId("diff-dialog").getByRole("button", { name: "Закрыть" }).click();

      /* end, then the recording of this device in the executor's player */
      await f.getByRole("button", { name: "Завершить" }).first().click();
      /* the end button is gated like a confirm: a click right after the frame moved is dropped, so click until it ends */
      await clickGated(f.getByTestId("end-dialog").getByRole("button", { name: "Завершить сессию" }), f.getByTestId("session-ended"), "Завершить сессию");
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
      await expect(player).toContainText(L.masked);
      await expect(player).toContainText("dangerous line confirmed");
      await expect(player.locator("*")).toHaveCount(0);

      /* the pre-session configuration unmasked: the list costs a code, the view a confirm(H) with the next one; text only */
      await g.getByTestId("nav-configs").click();
      await g.locator("input[name=cfg-device]").fill(String(id));
      await g.locator("input[name=cfg-code]").fill(await changeCode());
      await g.getByRole("button", { name: "Показать версии" }).click();
      await g.locator('[data-testid^="version-"]').first().getByRole("button", { name: "Показать", exact: true }).click();
      await expect(g.getByTestId("field-device_id")).toHaveText(String(id));
      await g.locator("#cp-code").fill(await changeCode());
      await confirmCode(g, "Подтвердить");
      const config = g.getByTestId("config-text");
      await expect(config).toContainText(L.iface);
      await expect(config.locator("*")).toHaveCount(0);

      /* the executor's audit shows that view (its own view is audited too) */
      await g.getByTestId("nav-audit").click();
      await g.locator("input[name=aud-action]").fill("config.view");
      await g.locator("input[name=aud-device]").fill(String(id));
      await g.locator("input[name=aud-code]").fill(await changeCode());
      await g.getByRole("button", { name: "Показать", exact: true }).click();
      const audit = g.getByTestId("audit-table");
      await expect(audit).toContainText("config.view");
      await expect(audit.locator("td *")).toHaveCount(0);
    });
  });
}
