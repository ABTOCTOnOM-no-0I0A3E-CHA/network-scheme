import type { Page, Request } from "@playwright/test";
import { expect, ORIGIN, testWith } from "./guard";

/*
 * The executor UI on its own origin (:8443 on the host), as the panel embeds it. Every test is watched by guard.ts:
 * a CSP violation or a request to an origin outside the allowed set fails it. The ticket exchange itself needs a
 * panel page that mounts ExecutorFrame (the device window, Phase 4c); here the panel is only the embedder.
 */
const EXECUTOR = process.env.NMS_E2E_EXECUTOR_ORIGIN ?? "https://localhost:8443";
const test = testWith([ORIGIN, EXECUTOR]);

const TITLE = "Изменение конфигураций";
/* the CI step before Playwright proves the executor off after nmsctl install (C1), then turns it on */
const ENABLED = /^Включён$/;

type Seen = { origin: string; data: unknown };
type Probe = Window & { __seen: Seen[] };

/* Embeds the executor like ExecutorFrame does (same sandbox) in the logged-in panel page and records messages from it. */
async function embed(page: Page, name = "exec"): Promise<void> {
  await page.goto("/");
  await page.evaluate(({ src, name }) => {
    const w = window as unknown as Probe;
    w.__seen = [];
    window.addEventListener("message", (e) => w.__seen.push({ origin: e.origin, data: e.data }));
    const f = document.createElement("iframe");
    f.id = name;
    f.name = name;
    f.title = "executor";
    f.setAttribute("sandbox", "allow-scripts allow-same-origin");
    f.referrerPolicy = "no-referrer";
    /* a frame this small would be the dock's compact strip (header and status hidden); the panel gives it a full page */
    f.width = "1100";
    f.height = "700";
    f.src = `${src}/`;
    document.body.append(f);
  }, { src: EXECUTOR, name });
}
const seen = (page: Page) => page.evaluate(() => (window as unknown as Probe).__seen);

test("the executor UI loads on its own origin with a strict CSP, local assets only and no cookies", async ({ page }) => {
  expect((await page.context().cookies()).length, "the panel session cookie is in the jar (cookies ignore ports)").toBeGreaterThan(0);
  const requests: Request[] = [];
  page.on("request", (r) => requests.push(r));
  const res = await page.goto(`${EXECUTOR}/`);
  expect(res?.status()).toBe(200);
  const csp = res?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain(`script-src ${EXECUTOR}/assets/`);
  expect(csp).toContain("style-src 'self'");
  expect(csp).toContain(`frame-ancestors ${ORIGIN}`);
  expect(csp).not.toMatch(/unsafe-(inline|eval)/);

  await expect(page.getByRole("heading", { name: TITLE })).toBeVisible();
  await expect(page.getByTestId("enabled")).toHaveText(ENABLED);
  await expect(page.getByTestId("frozen")).toBeVisible();
  await expect(page.getByTestId("failure")).toHaveCount(0);

  /* every request stayed on the executor origin; the status request carried no cookie */
  expect(requests.filter((r) => !r.url().startsWith(`${EXECUTOR}/`) && !r.url().startsWith("data:")).map((r) => r.url())).toEqual([]);
  const status = requests.find((r) => r.url() === `${EXECUTOR}/x/status`);
  expect(status, "GET /x/status").toBeDefined();
  expect(await status!.allHeaders()).not.toHaveProperty("cookie");
  /* the bundle is hashed static files under /assets/ with integrity hashes */
  const html = await (await page.request.get(`${EXECUTOR}/`)).text();
  expect(html.match(/<script[^>]*src="\/assets\/[^"]+"[^>]*integrity="sha384-[^"]+"/g)).toHaveLength(1);
  expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>|<style|\sstyle=/i);
});

test("the gateway publishes the same origins on both origins", async ({ page }) => {
  const want = { panel: ORIGIN, executor: EXECUTOR };
  expect(await (await page.request.get(`${ORIGIN}/origins.json`)).json()).toEqual(want);
  expect(await (await page.request.get(`${EXECUTOR}/origins.json`)).json()).toEqual(want);
});

test("the panel frames it: the page renders in the sandboxed iframe and tells the panel it is ready", async ({ page }) => {
  await embed(page);
  const frame = page.frameLocator("#exec");
  await expect(frame.getByRole("heading", { name: TITLE })).toBeVisible();
  await expect(frame.getByTestId("enabled")).toHaveText(ENABLED);
  await expect.poll(() => seen(page)).toEqual([{ origin: EXECUTOR, data: { v: 1, type: "status", state: "ready" } }]);
});

test("messages from another origin or of the wrong shape are ignored without a reply", async ({ page }) => {
  await embed(page);
  const frame = page.frameLocator("#exec");
  await expect(frame.getByTestId("enabled")).toBeVisible();
  await expect.poll(() => seen(page)).toHaveLength(1); /* ready */
  /* a second executor frame: same origin as the first, but not the panel, so its messages are from another origin */
  await page.evaluate((src) => {
    const f = document.createElement("iframe");
    f.id = f.name = "other";
    f.setAttribute("sandbox", "allow-scripts allow-same-origin");
    f.src = `${src}/`;
    document.body.append(f);
  }, EXECUTOR);
  await expect(page.frameLocator("#other").getByTestId("enabled")).toBeVisible();
  const other = page.frames().find((f) => f.name() === "other")!;
  await expect.poll(async () => (await seen(page)).length).toBe(2); /* the second frame is ready too */

  const posts: string[] = [];
  page.on("request", (r) => r.method() === "POST" && posts.push(r.url()));
  /* forged from the executor origin (not the panel): a ticket the first frame never asked for */
  await other.evaluate(() => {
    parent.frames["exec" as unknown as number].postMessage({ v: 1, type: "ticket", id: "0123456789abcdef0123456789abcdef", ticket: "forged.ticket" }, "*");
  });
  /* the panel itself, the legitimate origin, sends an unsolicited ticket and malformed messages */
  await page.evaluate((target) => {
    const exec = (document.getElementById("exec") as HTMLIFrameElement).contentWindow!;
    exec.postMessage({ v: 1, type: "ticket", id: "0123456789abcdef0123456789abcdef", ticket: "not.asked" }, target);
    exec.postMessage({ v: 1, type: "ticket", id: "x", ticket: "a b", extra: true }, target);
    exec.postMessage("ticket", target);
  }, EXECUTOR);
  await page.waitForTimeout(1000);
  /*
   * This proves only that the page keeps working and replies to none of it: the panel sees just the two "ready"
   * messages, no request left the page. That the forged ticket is never used is the bridge's unit test (bridge.test.ts).
   */
  const readyMessages = (await seen(page)).filter((m) => (m.data as { state?: string }).state === "ready");
  expect(readyMessages).toHaveLength(2);
  expect(await seen(page)).toHaveLength(2);
  expect(posts).toEqual([]);
  await expect(frame.getByRole("heading", { name: TITLE })).toBeVisible();
});

/*
 * C1, the enabled half: the CI step "The executor is off after install (C1)" saw every /x/* but the status answer 503
 * executor_disabled, then ran nmsctl executor enable. Now the same requests go down the check chain: authz refuses
 * a forged ticket and an unknown challenge for a real one (403 denied, audited by the executor), an action the
 * table does not have answers unknown_action, and POST /x/sessions without devices is refused (422 bad_devices).
 */
test("C1: after nmsctl executor enable requests go past the policy gate to the route table and authz", async ({ page }) => {
  await page.goto("/");
  const csrf = ((await (await page.request.get("/api/auth/me")).json()) as { csrf_token: string }).csrf_token;
  const res = await page.request.post("/api/executor/ticket", { headers: { "X-CSRF-Token": csrf } });
  expect(res.status()).toBe(200);
  const { ticket } = (await res.json()) as { ticket: string };
  const x = async (path: string, data: unknown) => {
    const r = await page.request.post(`${EXECUTOR}${path}`, { headers: { Origin: EXECUTOR }, data });
    return { status: r.status(), code: ((await r.json().catch(() => ({}))) as { error?: { code?: string } }).error?.code };
  };
  expect(await (await page.request.get(`${EXECUTOR}/x/status`)).json()).toEqual({ enabled: true, frozen: false });
  const h = "00".repeat(32);
  expect(await x("/x/confirm", { ticket: "forged.ticket", challenge_id: "c", h, code: "000000" })).toEqual({ status: 403, code: "denied" });
  expect(await x("/x/confirm", { ticket, challenge_id: "c", h, code: "000000" })).toEqual({ status: 403, code: "denied" });
  expect(await x("/x/confirm/issue", { ticket, action: "session.open", params: {} })).toEqual({ status: 404, code: "unknown_action" });
  /* the session route exists since 4c.2: a request without devices is refused before authz (no code is spent) */
  expect(await x("/x/sessions", { ticket })).toEqual({ status: 422, code: "bad_devices" });
});
