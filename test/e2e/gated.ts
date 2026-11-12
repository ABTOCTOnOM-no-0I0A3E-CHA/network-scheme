import type { FrameLocator, Locator } from "@playwright/test";
import { expect } from "./guard";

/*
 * Clicks the confirm of a ConfirmPanel in scope until the panel takes the code. Its gate follows IntersectionObserver
 * v2: the button is enabled only once the panel is fully in view and uncovered. Chrome also discards input to a
 * cross-origin frame that moved in the last ~500 ms (the dock resizing, the panel scrolled into view), so the click
 * waits for the frame to settle. The panel clears its code field when it sends, so a field that still holds the code
 * means nothing was sent and the click may be repeated; a sent code is never sent again.
 */
export async function confirmCode(scope: FrameLocator | Locator, name: string) {
  const button = scope.getByRole("button", { name, exact: true });
  const held = () => scope.locator("#cp-code").evaluateAll((els) => els.some((e) => (e as HTMLInputElement).value !== ""));
  for (let i = 0; i < 5; i++) {
    await expect(button).toBeEnabled({ timeout: 10_000 });
    await new Promise((r) => setTimeout(r, 1_000));
    await button.click();
    if (await expect.poll(held, { timeout: 2_000 }).toBe(false).then(() => true, () => false)) return;
    console.log(`"${name}" did not take the code (attempt ${i + 1}), clicking again`);
  }
  throw new Error(`"${name}" never took the code`);
}

/*
 * Clicks a gated button (useConfirmGate: the form's apply, commit, save) until done is visible, for the same reasons as
 * confirmCode. A click that went through disables the button at once (busy) and then removes it, so a button still
 * enabled after the click was dropped and nothing was sent: only then is it clicked again.
 */
export async function clickGated(button: Locator, done: Locator, name: string) {
  for (let i = 0; i < 5; i++) {
    await expect(button).toBeEnabled({ timeout: 10_000 });
    await new Promise((r) => setTimeout(r, 1_000));
    await button.click();
    const dropped = () => button.isEnabled({ timeout: 500 }).catch(() => false);
    if (await expect.poll(async () => (await done.isVisible()) || !(await dropped()), { timeout: 3_000 }).toBe(true).then(() => true, () => false)) {
      await expect(done).toBeVisible({ timeout: 60_000 });
      return;
    }
    console.log(`"${name}" was not taken (attempt ${i + 1}), clicking again`);
  }
  throw new Error(`"${name}" was never taken`);
}
