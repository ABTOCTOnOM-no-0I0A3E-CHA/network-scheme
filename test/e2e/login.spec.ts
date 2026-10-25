import { readFileSync } from "node:fs";
import { currentStep, expectShell, STEP_FILE, submitCode, submitPassword, totpCode } from "./auth";
import { expect, ORIGIN, test, watch } from "./guard";

/* Sidebar sections that are still placeholders (web/app/src/routes/index.tsx). */
const SECTIONS = ["Бэкапы", "Изменения", "Аудит", "Настройки"];
/* Sections with real screens (see ui.spec.ts, events.spec.ts): visited for the CSP and external request check only. */
const SCREENS: [string, string][] = [
  ["Карта", "/map"],
  ["Устройства", "/devices"],
  ["Обнаружение", "/discovery"],
  ["Проблемы", "/problems"],
  ["Шаблоны", "/templates"],
  ["Обслуживание", "/maintenance"],
  ["Логи", "/logs"],
  ["Состояние системы", "/health"],
];

test("admin logs in with password + TOTP and sees shell", async ({ page, context }) => {
  /* The login itself ran in global setup (one login per run: auth is rate-limited). */
  await page.goto("/");
  await expectShell(page);
  await expect(page).toHaveURL(`${ORIGIN}/`);
  await expect(page.getByRole("heading", { name: "Дашборды", level: 1 })).toBeVisible();
  const cookie = (await context.cookies()).find((c) => c.name === "__Host-nms_session");
  expect(cookie).toMatchObject({ secure: true, httpOnly: true, sameSite: "Strict", path: "/" });
});

test("no CSP violations and no external requests", async ({ page, browser }) => {
  /* The default context is watched by the fixture; the logged-out one here. */
  const anon = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const w = await watch(anon);
  const login = await anon.newPage();
  await login.goto("/");
  await expect(login).toHaveURL(`${ORIGIN}/login`);
  await expect(login.getByRole("button", { name: "Войти" })).toBeVisible();
  await anon.close();
  expect(w.problems, "logged-out pages").toEqual([]);

  await page.goto("/");
  await expectShell(page);
  for (const name of SECTIONS) {
    await page.getByRole("link", { name }).click();
    await expect(page.getByText("Будет в следующих версиях")).toBeVisible();
  }
  for (const [name, path] of SCREENS) {
    await page.getByRole("link", { name }).click();
    await expect(page).toHaveURL((u) => u.origin === ORIGIN && u.pathname === path);
    await expect(page.getByText("Будет в следующих версиях")).toHaveCount(0);
  }
  await page.keyboard.press("Control+k");
  await expect(page.getByText("Ничего не найдено")).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Переключить тему" }).click();
  await page.reload();
  await expectShell(page);
});

test("command palette: Ctrl+K focuses input, Escape and backdrop close it", async ({ page }) => {
  await page.goto("/");
  await expectShell(page);
  const dialog = page.getByRole("dialog", { name: "Палитра команд" });
  const input = page.getByPlaceholder("Введите команду или запрос…");

  await page.keyboard.press("Control+k");
  await expect(dialog).toBeVisible();
  await expect(input).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  await page.keyboard.press("Control+k");
  await expect(input).toBeFocused();
  /* A click outside the dialog box lands on the dialog element (its ::backdrop). */
  await page.mouse.click(5, 5);
  await expect(dialog).toBeHidden();
});

test("theme toggle persists across reload", async ({ page }) => {
  await page.goto("/");
  await expectShell(page);
  const html = page.locator("html");
  const dark = /(^|\s)dark(\s|$)/;
  const wasDark = dark.test((await html.getAttribute("class")) ?? "");
  const expectToggled = () => (wasDark ? expect(html).not.toHaveClass(dark) : expect(html).toHaveClass(dark));
  await page.getByRole("button", { name: "Переключить тему" }).click();
  await expectToggled();
  await page.reload();
  await expectShell(page);
  await expectToggled();
});

test("/api/evil-like paths are served as JSON", async ({ page }) => {
  const res = await page.goto("/api/does-not-exist");
  expect(res).not.toBeNull();
  expect(res!.status()).toBe(404);
  expect(res!.headers()["content-type"]).toBe("application/json; charset=utf-8");
  expect(await page.locator("script").count()).toBe(0);
  JSON.parse(await res!.text());
});

/* Last: it logs in twice more (global setup + these two stay under the auth rate limit). */
test("same TOTP code cannot be reused", async ({ browser }) => {
  /* A time step is accepted once per user: start after the one global setup used. */
  const used = Number(readFileSync(STEP_FILE, "utf8"));
  while (currentStep() <= used) await new Promise((r) => setTimeout(r, 1000));
  const fresh = { storageState: { cookies: [], origins: [] } };

  const first = await browser.newContext(fresh);
  const w1 = await watch(first);
  const p1 = await first.newPage();
  await submitPassword(p1);
  const code = await totpCode(currentStep());
  await submitCode(p1, code);
  await expectShell(p1);
  await first.close();

  const second = await browser.newContext(fresh);
  const w2 = await watch(second);
  const p2 = await second.newPage();
  await submitPassword(p2);
  await submitCode(p2, code);
  await expect(p2.getByRole("alert")).toHaveText("Неверные учётные данные");
  await expect(p2).toHaveURL(`${ORIGIN}/login`);
  await expect(p2.getByRole("button", { name: "Переключить тему" })).toHaveCount(0);
  await second.close();
  expect([...w1.problems, ...w2.problems], "login pages").toEqual([]);
});
