import type { FrameLocator, Page } from "@playwright/test";
import { changeCode } from "./change-totp";
import { expect, ORIGIN, testWith } from "./guard";

/*
 * Changesets end to end (Task 5.9): the panel's «Изменения» opens the executor's section in the shell's dock; a
 * changeset over the write emulators of both lines (mes6 is the canary, then esr) goes draft → dry-run (read only) →
 * approval (H, the typed device count, the next change TOTP code) → run (canary, batch, MES saved, ESR committed and
 * confirmed) → done, and the panel lists it from execpub. A second changeset is stopped after its canary: the canary
 * is rolled back, the next device never touched (D6). Both origins stay free of CSP violations (guard.ts); device text
 * is only ever text.
 *
 * Preconditions: those of session.spec.ts (CI job e2e, "Register the write emulators with the executor (session
 * e2e)": NMS_E2E_SESSION_DEVICES, the admin's change TOTP and the grants write-admin and write on the devices' group).
 * The write credentials are stored here too (this file runs before session.spec.ts; storing again replaces them).
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

/* test values of the emulators' write account, the same as in the CI step that starts them */
const WRITE = { username: "e2e-write", password: "e2e-write-session-pw" };
/* a spare port of each line's fixture (not the management interface), named in full as the emulator wants it */
const PORT = { mes6: "gigabitethernet1/0/2", esr: "gigabitethernet 1/0/2" } as const;

const frame = (page: Page) => page.frameLocator('iframe[title="Сессия изменений"]');

async function storeCredential(page: Page, device: number) {
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
  await f.getByRole("button", { name: "Сохранить", exact: true }).click();
  await expect(f.getByTestId("done")).toContainText(`Учётка устройства ${device} сохранена`);
}

/* a lines changeset over mes6 (canary) and esr, saved and dry-run; returns at the passed dry-run */
async function draft(f: FrameLocator, title: string, description: string, settle: number) {
  const mes6 = DEVICES.mes6;
  const esr = DEVICES.esr;
  await f.getByTestId("cs-new").click();
  await f.locator("#cs-title").fill(title);
  await f.getByTestId(`pick-${mes6}`).check();
  await f.getByTestId(`pick-${esr}`).check();
  await expect(f.getByTestId("cs-order").getByRole("listitem").first()).toContainText(`Устройство ${mes6}`);
  await f.getByRole("button", { name: "Вставить несколько строк" }).click();
  await f.locator("textarea[name=cs-bulk]").fill(`configure\ninterface {{port}}\ndescription ${description}\nend`);
  await f.getByRole("button", { name: "Добавить строки" }).click();
  await f.locator(`input[name=cs-var-${mes6}-port]`).fill(PORT.mes6);
  await f.locator(`input[name=cs-var-${esr}-port]`).fill(PORT.esr);
  await f.locator("#cs-batch").fill("1");
  await f.locator("#cs-settle").fill(String(settle));
  await f.getByTestId("cs-save").click();
  await expect(f.getByTestId("cs-detail")).toBeVisible();
  await expect(f.getByTestId("cs-status")).toHaveAttribute("data-status", "draft");

  /* the dry-run reads both devices (read only) and shows the lines each one will get, as text */
  await f.getByTestId("cs-dry-run-button").click();
  await expect(f.getByTestId("dry-run-outcome")).toContainText("Все устройства готовы", { timeout: 120_000 });
  await expect(f.getByTestId("cs-status")).toHaveAttribute("data-status", "dry_run_ok");
  const lines = f.getByTestId("equivalent-line");
  await expect(lines.filter({ hasText: `description ${description}` })).toHaveCount(2);
  await expect(f.getByTestId("cs-dry-run").locator("pre *:not([data-testid=equivalent-line])")).toHaveCount(0);
}

/* the author's approval: every field and H shown, the typed device count, the next code; the run starts */
async function approve(f: FrameLocator) {
  await f.getByTestId("cs-approve").click();
  const dlg = f.getByTestId("approve-dialog");
  await dlg.getByTestId("approve-issue").click();
  await expect(dlg.getByTestId("h")).toContainText(/H: [0-9a-f]{64}/);
  await expect(dlg.getByTestId("field-plan_sha256")).toHaveText(/^[0-9a-f]{64}$/);
  await expect(dlg.getByTestId("field-canary")).toHaveText(String(DEVICES.mes6));
  await dlg.locator("#cs-count").fill("2");
  await dlg.locator("#cp-code").fill(await changeCode());
  await dlg.getByRole("button", { name: "Подтвердить changeset" }).click();
  await expect(dlg).toHaveCount(0);
}

test.describe("changesets on the write emulators", () => {
  test.skip(!DEVICES.mes6 || !DEVICES.esr, "NMS_E2E_SESSION_DEVICES names no mes6 and esr devices (the write emulators are not wired into this run)");
  /* five change TOTP codes, each waiting for a new 30 s step, and two runs */
  test.setTimeout(15 * 60_000);

  test("draft → dry-run → approval with the device count → canary and batch → done; a stopped run rolls back its canary", async ({ page }) => {
    await storeCredential(page, DEVICES.mes6);
    await storeCredential(page, DEVICES.esr);

    /* «Изменения» of the panel opens the executor's section in the dock; the workspace costs one code */
    await page.goto("/changes");
    await page.getByTestId("changes-create").click();
    const f = frame(page);
    await expect(f.getByTestId("nav-changesets")).toHaveAttribute("aria-selected", "true");
    await f.locator("#cs-code").fill(await changeCode());
    await f.getByRole("button", { name: "Открыть раздел" }).click();
    await expect(f.getByTestId("cs-list")).toBeVisible();

    /* K1: canary (mes6) → batch (esr) → done; MES saved at the end, ESR committed and confirmed */
    await draft(f, "e2e: description on both lines", "nms-e2e-cs", 0);
    await approve(f);
    await expect(f.getByTestId("cs-status")).toHaveAttribute("data-status", "done", { timeout: 300_000 });
    await expect(f.getByTestId("run-outcome")).toContainText("Выполнен");
    await expect(f.getByTestId(`run-${DEVICES.mes6}`)).toHaveAttribute("data-state", "saved");
    await expect(f.getByTestId(`run-${DEVICES.esr}`)).toHaveAttribute("data-state", "applied");
    await expect(f.getByTestId("cs-history")).toContainText("Исполнение начато");
    const doneId = ((await f.getByTestId("cs-id").textContent()) ?? "").trim();
    expect(doneId).toMatch(/^[0-9a-f-]{36}$/);

    /* «Стоп» after the canary (during its settle): no line goes to esr, the canary is rolled back */
    await f.getByRole("button", { name: "← К списку" }).click();
    await draft(f, "e2e: stopped after the canary", "nms-e2e-stop", 45);
    await approve(f);
    await expect(f.getByTestId(`run-${DEVICES.mes6}`)).toHaveAttribute("data-state", "applied", { timeout: 180_000 });
    await f.getByTestId("cs-stop").click();
    await expect(f.getByTestId("stop-dialog")).toContainText("будут откачены к конфигурации до changeset'а");
    await f.getByTestId("cs-stop-confirm").click();
    await expect(f.getByTestId("cs-status")).toHaveAttribute("data-status", "rolled_back", { timeout: 300_000 });
    await expect(f.getByTestId("run-outcome")).toContainText("Остановлен пользователем");
    await expect(f.getByTestId(`run-${DEVICES.mes6}`)).toHaveAttribute("data-state", "rolled_back");
    await expect(f.getByTestId(`run-${DEVICES.esr}`)).toHaveAttribute("data-state", "not_started");

    /* the panel lists both from execpub: metadata only, the lines stay in the executor */
    await page.goto("/changes");
    const row = page.getByTestId(`change-${doneId}`);
    await expect(row).toContainText("Выполнен");
    await expect(row).toContainText("e2e: description on both lines");
    await expect(page.getByText("e2e: stopped after the canary")).toBeVisible();
    await expect(page.locator("body")).not.toContainText("nms-e2e-cs");
  });
});
