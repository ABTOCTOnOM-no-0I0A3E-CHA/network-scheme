import { writeFileSync } from "node:fs";
import sodium from "libsodium-wrappers";
import { stepUp } from "./auth";
import { expect, test } from "./guard";

/*
 * Containers the CI job attaches to the devices network (see .github/workflows/ci.yml):
 *  - NMS_E2E_EVENT_PROBE: the device. It answers SNMPv2c and sends the trap named in the control file CONTROL (linkDown,
 *    linkUp or none) for ifIndex 2 every few seconds, all from its own address. Two snmpsim data files by community:
 *    COMMUNITY has ifIndex 2 down (the polls after linkDown agree and cannot close the problem before the ack), COMMUNITY_UP
 *    has it up (the test switches the device's profile to it before linkUp, so polls never reopen the closed problem).
 *  - NMS_E2E_PROBE_DEAD: an address of the devices subnet nothing listens on: the parent whose outage suppresses the device.
 * The test drives the device by writing the control file (test/e2e/.auth, mounted into the sender) and watches the problems
 * through the API and the UI, including the notification center (a WebSocket through the gateway).
 */
const PROBE = process.env.NMS_E2E_EVENT_PROBE ?? "";
const DEAD = process.env.NMS_E2E_PROBE_DEAD ?? "";
const COMMUNITY = "e2e-events-community-01";
const COMMUNITY_UP = "e2e-events-community-02";
const CONTROL = ".auth/trap-control";
const GROUP = "problems-e2e";
const CHILD = "prob-child";
const PARENT = "prob-parent";

type Problem = { id: number; device_id: number | null; state: string; suppressed: boolean; object: string; resolve_reason: string | null; last_value: string | null };

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

/** Seals a read credential as the browser does: payload v1 (internal/creds), crypto_box_seal to the read key. */
async function seal(readKey: string, owner: string, kind: string, secret: object): Promise<string> {
  await sodium.ready;
  const payload = JSON.stringify({
    v: 1,
    owner,
    kind,
    created_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    nonce: b64(sodium.randombytes_buf(16)),
    secret,
  });
  return b64(sodium.crypto_box_seal(sodium.from_string(payload), Buffer.from(readKey, "base64")));
}

/** What the device sends from now on: "linkDown", "linkUp" or nothing. */
const sendTrap = (name: "linkDown" | "linkUp" | "") => writeFileSync(CONTROL, name);

test("problems: a trap opens one, an ack and linkUp close it, a down parent suppresses the next", async ({ page }) => {
  test.setTimeout(10 * 60_000);
  expect(PROBE, "NMS_E2E_EVENT_PROBE (device container with a trap control file)").not.toBe("");
  expect(DEAD, "NMS_E2E_PROBE_DEAD (unused address of the devices subnet)").not.toBe("");
  sendTrap("");
  const api = page.request;
  const csrf = async () => ({ "X-CSRF-Token": ((await (await api.get("/api/auth/me")).json()) as { csrf_token: string }).csrf_token });
  const problems = async (query: string) => ((await (await api.get(`/api/problems?${query}`)).json()) as { items: Problem[] }).items;

  /* Credentials need a step-up. It rotates the session, which would close an open socket: do it before the page loads. */
  await stepUp(page);
  let res = await api.post("/api/groups", { headers: await csrf(), data: { name: GROUP } });
  expect(res.status()).toBe(201);
  const group = (await res.json()).id as number;
  const addDevice = async (name: string, address: string): Promise<number> => {
    const created = await api.post("/api/devices", { headers: await csrf(), data: { name, address, group_id: group } });
    expect(created.status()).toBe(201);
    return (await created.json()).id as number;
  };
  const child = await addDevice(CHILD, PROBE);
  const parent = await addDevice(PARENT, DEAD);
  const read = (await (await api.get("/keys.json")).json()).domains.read as { public_key: string; key_version: number };
  const setCommunity = async (community: string) => {
    const ciphertext = await seal(read.public_key, `device:${child}`, "snmp2c", { community });
    const put = await api.put(`/api/devices/${child}/profiles/snmp2c`, { headers: await csrf(), data: { ciphertext, key_version: read.key_version } });
    expect(put.status()).toBe(204);
  };
  await setCommunity(COMMUNITY); /* ifIndex 2 is down for the device until the test switches it */
  /* The parent has nothing to answer: its poll finds it down, and its availability problem opens after the trigger's duration. */
  for (const id of [child, parent]) expect((await api.post(`/api/devices/${id}/poll`, { headers: await csrf() })).status()).toBe(202);
  /* The default templates are bound to the driver, which the first inventory poll sets. */
  await expect
    .poll(
      async () => {
        const dev = (await (await api.get(`/api/devices/${child}`)).json()) as { state: string; driver: string };
        return { state: dev.state, driver: dev.driver !== "" };
      },
      { timeout: 90_000, intervals: [2_000] },
    )
    .toEqual({ state: "up", driver: true });

  /* The panel is open (and its socket connected) before anything happens, so the notification is not missed. */
  await page.addInitScript(() => localStorage.setItem("nms.notify.v1", JSON.stringify({ sound: false, severityMin: "average", groups: [] })));
  const socket = page.waitForEvent("websocket", { timeout: 15_000 });
  await page.goto("/problems");
  const ws = await socket;
  expect(ws.url()).toContain("/api/ws");
  /* ids of the problems announced through the socket */
  const announced = new Set<number>();
  const onFrame = (f: { payload: string | Buffer }) => {
    try {
      const m = JSON.parse(String(f.payload)) as { problem?: { id: number } };
      if (m.problem) announced.add(m.problem.id);
    } catch {
      /* not a problem frame */
    }
  };
  ws.on("framereceived", onFrame);
  const table = page.getByRole("table", { name: "Проблемы" });
  await expect(table).toBeVisible();
  const bell = page.getByRole("button", { name: /^Уведомления:/ });
  const badge = page.getByTestId("notify-badge");

  /* linkDown: the default "interface down" trigger opens a problem for the port, in the list and in the notification center. */
  const sentAt = Date.now();
  sendTrap("linkDown");
  let first: Problem | undefined;
  await expect
    .poll(async () => (first = (await problems(`device_id=${child}`)).find((p) => p.state === "problem")), { timeout: 45_000, intervals: [1_000], message: "problem of the trap" })
    .toBeDefined();
  const problem = first!;
  console.log(`linkDown trap -> problem in the API after ${Date.now() - sentAt} ms`);
  sendTrap(""); /* one trap is enough; no further polls are caused */
  expect(problem.suppressed).toBe(false);
  expect(problem.object).toBe("if:2");
  const row = page.locator(`tr[data-problem-id="${problem.id}"]`);
  await expect(row).toBeVisible();
  await expect(row).toContainText(CHILD);
  await expect(badge).toBeVisible();
  await bell.click();
  await expect(page.getByRole("dialog")).toContainText(CHILD);
  await page.keyboard.press("Escape");
  await expect(badge).toHaveCount(0);

  /* Acknowledge with a comment in the UI. */
  const comment = "e2e: port checked by the duty engineer";
  await row.getByRole("button", { name: /^Подробности:/ }).click();
  await row.getByLabel("Комментарий (обязателен)").fill(comment);
  await row.getByRole("button", { name: "Подтвердить проблему" }).click();
  await expect(row).toContainText(comment);
  await expect(row).toContainText("Подтверждена");
  const acked = (await (await api.get(`/api/problems/${problem.id}`)).json()) as { state: string; acks: { comment: string }[] };
  expect(acked.state).toBe("acknowledged");
  expect(acked.acks.map((a) => a.comment)).toEqual([comment]);

  /* The port comes up: the device now answers with ifIndex 2 up (a new step-up rotates the session, so the socket is reopened), then linkUp resolves it. */
  await stepUp(page);
  await setCommunity(COMMUNITY_UP);
  const reopened = page.waitForEvent("websocket", { timeout: 15_000 });
  await page.reload();
  (await reopened).on("framereceived", onFrame);
  await expect(row).toBeVisible();
  sendTrap("linkUp");
  await expect
    .poll(async () => (await problems(`device_id=${child}&state=resolved`)).find((p) => p.id === problem.id)?.resolve_reason, { timeout: 45_000, intervals: [1_000], message: "linkUp" })
    .toBe("recovered");
  sendTrap("");
  /* closed by the trap itself, not by a poll that saw the port up */
  const closed = (await problems(`device_id=${child}&state=resolved`)).find((p) => p.id === problem.id);
  expect(closed?.last_value ?? "").toContain("linkUp");
  await expect(row).toContainText("Закрыта");

  /* The parent is down: once its problem is open, a new problem of the child opens suppressed. */
  await expect
    .poll(async () => (await problems(`device_id=${parent}&state=problem`)).length, { timeout: 4 * 60_000, intervals: [3_000], message: "problem of the dead parent" })
    .toBeGreaterThan(0);
  res = await api.patch(`/api/devices/${child}`, { headers: await csrf(), data: { parent_id: parent } });
  expect(res.status()).toBe(204);
  /* Reading what has arrived (the parent's own problem) resets the badge: nothing may raise it for the suppressed problem. */
  await bell.click();
  await page.keyboard.press("Escape");
  await expect(badge).toHaveCount(0);

  /* Nothing of the port is open now (the polls agree with linkUp), so what appears next is a NEW problem, opened suppressed. */
  expect((await problems(`device_id=${child}`)).filter((p) => p.state !== "resolved")).toEqual([]);
  sendTrap("linkDown");
  let second: Problem | undefined;
  await expect
    .poll(async () => (second = (await problems(`device_id=${child}&suppressed=true&state=problem`)).find((p) => p.id !== problem.id)), {
      timeout: 45_000,
      intervals: [1_000],
      message: "suppressed problem of the child",
    })
    .toBeDefined();
  sendTrap("");
  expect(second!.suppressed).toBe(true);
  expect(second!.object).toBe("if:2");
  /* The engine publishes right after it stores a problem; a suppressed one is never announced. */
  await page.waitForTimeout(3_000);
  await expect(badge).toHaveCount(0);
  expect(announced.has(second!.id), "suppressed problem announced through the socket").toBe(false);
  expect(announced.has(problem.id), "the first problem was announced").toBe(true);
  await page.reload();
  await page.getByLabel("Подавленные").selectOption("true");
  const suppressedRow = page.locator(`tr[data-problem-id="${second!.id}"]`);
  await expect(suppressedRow).toBeVisible();
  await expect(suppressedRow).toContainText("подавлена");

  /* The other new screens load with their requests and the socket inside the CSP (the fixture checks the whole test). */
  for (const [path, name] of [
    ["/templates", "Шаблоны"],
    ["/maintenance", "Обслуживание"],
    ["/problems", "Проблемы"],
  ] as const) {
    await page.goto(path);
    await expect(page.getByRole("heading", { name }).first()).toBeVisible();
  }

  /* Leave a clean stack for the specs that follow (deleting devices needs a fresh step-up). */
  await stepUp(page);
  for (const id of [child, parent]) expect((await api.delete(`/api/devices/${id}`, { headers: await csrf() })).status()).toBe(204);
});
