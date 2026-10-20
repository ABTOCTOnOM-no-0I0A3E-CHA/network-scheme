import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page } from "@playwright/test";
import { generate } from "otplib";

/*
 * Credentials of the installed admin. NMS_E2E_DIR holds the files given to
 * "nmsctl install --admin-password-file / --totp-secret-out"; both are
 * throwaway CI values and are never committed.
 */
const dir = process.env.NMS_E2E_DIR ?? "/tmp/nms-e2e";
const read = (name: string) => readFileSync(join(dir, name), "utf8").trim();

export const ADMIN_USER = process.env.NMS_E2E_USER ?? "admin";
export const adminPassword = () => read("admin-password");

/** Storage state written by global setup and reused by every test. */
export const STATE_FILE = ".auth/state.json";
/** TOTP time step consumed by global setup (a step is accepted once per user). */
export const STEP_FILE = ".auth/totp-step";

const PERIOD = 30;
export const currentStep = () => Math.floor(Date.now() / 1000 / PERIOD);

/** TOTP code of the admin for the given time step. */
export async function totpCode(step: number): Promise<string> {
  return generate({ secret: read("totp-secret"), epoch: step * PERIOD });
}

/** Submits the credentials form; the page is then on the TOTP step. */
export async function submitPassword(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Логин").fill(ADMIN_USER);
  await page.getByLabel("Пароль").fill(adminPassword());
  await page.getByRole("button", { name: "Войти" }).click();
  await expect(page.getByText("Введите 6-значный код из приложения-аутентификатора.")).toBeVisible();
}

/** Types the 6-digit code into the TOTP step (input-otp completes on the 6th digit). */
export async function submitCode(page: Page, code: string): Promise<void> {
  await page.getByLabel("Код подтверждения").pressSequentially(code);
}

/** The authenticated shell is visible. */
export async function expectShell(page: Page): Promise<void> {
  await expect(page.getByRole("button", { name: "Переключить тему" })).toBeVisible();
}
