import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generate } from "otplib";

/*
 * Change TOTP codes of the admin (CI: change-totp-secret of nmsctl executor enroll). The executor takes a code only
 * once and a confirmation only with a step above the last one used, so every code waits for a step after the previous
 * one. The last step is kept in a file, not in a module: the specs share one user across files and worker restarts
 * (session.spec.ts keeps its step in the same file).
 */
const PERIOD = 30;
const dir = process.env.NMS_E2E_DIR ?? "/tmp/nms-e2e";
const stepFile = "/tmp/nms-e2e-change-totp-step";

function lastStep(): number {
  try {
    return Number(readFileSync(stepFile, "utf8")) || 0;
  } catch {
    return 0;
  }
}

export async function changeCode(): Promise<string> {
  const now = () => Math.floor(Date.now() / 1000 / PERIOD);
  const last = lastStep();
  while (now() <= last) await new Promise((r) => setTimeout(r, 1000));
  const step = now();
  writeFileSync(stepFile, String(step));
  return generate({ secret: readFileSync(join(dir, "change-totp-secret"), "utf8").trim(), epoch: step * PERIOD });
}
