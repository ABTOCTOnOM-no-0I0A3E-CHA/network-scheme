import { defineConfig, devices } from "@playwright/test";
import { STATE_FILE } from "./auth";

/*
 * Runs against a real "nmsctl install --public-host localhost" (CI job e2e).
 * One worker, in order: the stack is shared and the auth endpoints are
 * rate-limited. The web certificate is self-signed by the internal CA.
 */
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  globalSetup: "./global-setup.ts",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  forbidOnly: true,
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "https://localhost",
    ignoreHTTPSErrors: true,
    storageState: STATE_FILE,
    locale: "ru-RU",
    /* a stuck click or navigation fails within a minute and prints its diagnostics, not at the test's own timeout */
    actionTimeout: 60_000,
    navigationTimeout: 60_000,
  },
});
