import { mkdirSync, writeFileSync } from "node:fs";
import { chromium, type FullConfig } from "@playwright/test";
import { currentStep, expectShell, STATE_FILE, STEP_FILE, submitCode, submitPassword, totpCode } from "./auth";
import { watch } from "./guard";

/*
 * Logs the admin in once (password + TOTP) and saves the session for all
 * tests: the auth endpoints allow 10 requests per minute per IP. The login
 * and TOTP pages are checked for CSP violations and external requests here.
 */
export default async function globalSetup(config: FullConfig): Promise<void> {
  const { baseURL, ignoreHTTPSErrors } = config.projects[0].use;
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ baseURL, ignoreHTTPSErrors });
    const w = await watch(context);
    const page = await context.newPage();
    await submitPassword(page);
    const step = currentStep();
    await submitCode(page, await totpCode(step));
    await expectShell(page);
    if (w.problems.length > 0) throw new Error(`login pages:\n${w.problems.join("\n")}`);
    mkdirSync(".auth", { recursive: true, mode: 0o700 });
    await context.storageState({ path: STATE_FILE });
    writeFileSync(STEP_FILE, String(step));
  } finally {
    await browser.close();
  }
}
