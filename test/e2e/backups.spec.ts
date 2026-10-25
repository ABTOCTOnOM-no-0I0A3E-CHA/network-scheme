import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { APIResponse, Page, Response } from "@playwright/test";
import sodium from "libsodium-wrappers";
import { stepUp } from "./auth";
import { expect, test } from "./guard";

/*
 * Configuration backups, the device window and its CLI end to end. CI starts one container per Eltex model on the devices
 * network ("Start the backup devices"): snmpsim answers SNMPv2c with the community below, sshemud serves the CLI on port 22
 * with the read account below. sshemud reads every command output from .auth/sshemu-<model>/<command line> at each
 * command; "show running-config" starts as test/fixtures/configs/<model>-secrets.txt, whose known secrets are listed in
 * <model>-secrets.secrets, and the test rewrites it to change the configuration.
 *
 * The poller keeps at least 5 minutes between two backups of a device (whoever asks) and schedules every 1 h at the
 * fastest; a new device is backed up by the schedule within seconds. So: both devices get their scheduled baseline, the
 * window, CLI and secret checks run during the 5 minutes, then one manual backup each: MES unchanged (no new version),
 * ESR after a configuration change (a second version, drift, the expected diff).
 */
const CONFIGS = process.env.NMS_E2E_CONFIGS ?? "../fixtures/configs";
const SSH = { username: "e2e-backup", password: "e2e-backup-read-pw" };
const MODELS = {
  mes: { address: process.env.NMS_E2E_MES ?? "", community: "e2e-backup-community-mes", driver: "eltex-mes" },
  esr: { address: process.env.NMS_E2E_ESR ?? "", community: "e2e-backup-community-esr", driver: "eltex-esr" },
} as const;
type Model = keyof typeof MODELS;
const GROUP = "backups-e2e";
const BACKUP_GAP_MS = 5 * 60_000;
/* how often the window re-reads the backup state while it waits for a manual backup (web/app backups.ts) */
const BACKUP_POLL_MS = 3_000;
/* the line the test changes in the ESR configuration */
const BEFORE = "  description uplink";
const AFTER = "  description uplink-e2e";

type Version = { id: number; taken_at: string; source: string; drift: boolean };
type State = { last_ok_at: string | null; last_error: string | null; latest_version: Version | null };

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const secrets = (Object.keys(MODELS) as Model[]).flatMap((m) =>
  readFileSync(join(CONFIGS, `${m}-secrets.secrets`), "utf8")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean),
);
const runningConfig = (m: Model) => join(".auth", `sshemu-${m}`, "show running-config");

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

/**
 * Every text the test saw: JSON and text responses of the page and of the API client, and the visible page text. Page
 * bodies are read as soon as each response arrives and settled before every navigation (a navigation discards them).
 * Only a redirect or an aborted request (the browser never got a body either) is skipped; any other unreadable body is
 * counted and fails the test.
 */
class Seen {
  readonly texts: { where: string; text: string }[] = [];
  readonly unread: string[] = [];
  private pending: Promise<void>[] = [];
  private requests = 0;

  watch(page: Page) {
    page.on("request", () => this.requests++);
    page.on("response", (r) => {
      if (r.status() >= 300 && r.status() < 400) return;
      this.pending.push(this.keep(r));
    });
  }

  async keep(r: Response | APIResponse): Promise<void> {
    if (!/json|text\/(plain|html)/.test(r.headers()["content-type"] ?? "")) return;
    try {
      this.texts.push({ where: r.url(), text: await r.text() });
    } catch (err) {
      if ("finished" in r && (await r.finished()) !== null) return; /* aborted: no body reached the page */
      this.unread.push(`${r.url()}: ${String(err)}`);
    }
  }

  /** Waits for every body read started so far, including reads started while waiting. */
  async settle(): Promise<void> {
    for (let n = 0; n !== this.pending.length; ) {
      n = this.pending.length;
      await Promise.all(this.pending);
    }
  }

  /** Settles, then waits until the page sent no request for `ms` (its polls stopped), so a navigation cuts no body short. */
  async quiet(ms: number): Promise<void> {
    for (let n = -1; n !== this.requests; ) {
      n = this.requests;
      await this.settle();
      await sleep(ms);
    }
    await this.settle();
  }

  async page(page: Page, where: string): Promise<void> {
    this.texts.push({ where: `page ${where}`, text: await page.locator("body").innerText() });
  }

  async leaks(): Promise<string[]> {
    await this.settle();
    expect(this.unread, "response bodies the secret scan could not read").toEqual([]);
    return this.texts.flatMap(({ where, text }) => secrets.filter((s) => text.includes(s)).map((s) => `${s} in ${where}`));
  }
}

test("backups, the device window and the CLI end to end", async ({ page }) => {
  test.setTimeout(16 * 60_000);
  for (const m of Object.values(MODELS)) expect(m.address, "NMS_E2E_MES / NMS_E2E_ESR (backup device addresses)").not.toBe("");
  expect(secrets.length).toBeGreaterThan(20);
  const seen = new Seen();
  seen.watch(page);
  const api = page.request;
  const call = async (method: "get" | "post" | "put" | "delete", path: string, data?: object): Promise<APIResponse> => {
    const headers: Record<string, string> = method === "get" ? {} : { "X-CSRF-Token": ((await (await api.get("/api/auth/me")).json()) as { csrf_token: string }).csrf_token };
    const r = await api[method](path, { headers, data });
    await seen.keep(r);
    return r;
  };
  const json = async <T>(path: string): Promise<T> => {
    const r = await call("get", path);
    expect(r.status(), path).toBe(200);
    return (await r.json()) as T;
  };
  /* a navigation discards the bodies of the old page: read them all first */
  const goto = async (url: string) => {
    await seen.settle();
    await page.goto(url);
  };
  const versions = async (id: number) => (await json<{ items: Version[] }>(`/api/devices/${id}/backups`)).items;
  const state = (id: number) => json<State>(`/api/devices/${id}/backup-state`);

  /* Credentials need a step-up; it rotates the session, so take it before any page is open. */
  await stepUp(page);
  const devices = await json<{ id: number; address: string }[]>("/api/devices");
  for (const d of devices.filter((x) => Object.values(MODELS).some((m) => m.address === x.address))) {
    expect((await call("delete", `/api/devices/${d.id}`)).status()).toBe(204);
  }
  const groups = await json<{ id: number; name: string }[]>("/api/groups");
  let group = groups.find((g) => g.name === GROUP)?.id;
  if (group === undefined) {
    const r = await call("post", "/api/groups", { name: GROUP });
    expect(r.status()).toBe(201);
    group = ((await r.json()) as { id: number }).id;
  }
  const read = (await json<{ domains: { read: { public_key: string; key_version: number } } }>("/keys.json")).domains.read;
  const ids = {} as Record<Model, number>;
  for (const m of Object.keys(MODELS) as Model[]) {
    const r = await call("post", "/api/devices", { name: `e2e-${m}`, address: MODELS[m].address, group_id: group });
    expect(r.status()).toBe(201);
    const id = ((await r.json()) as { id: number }).id;
    ids[m] = id;
    /* SSH first: the schedule backs a new device up within seconds, and it needs both */
    for (const [kind, secret] of [
      ["ssh_read", SSH],
      ["snmp2c", { community: MODELS[m].community }],
    ] as const) {
      const ciphertext = await seal(read.public_key, `device:${id}`, kind, secret);
      expect((await call("put", `/api/devices/${id}/profiles/${kind}`, { ciphertext, key_version: read.key_version })).status()).toBe(204);
    }
    /* the inventory (Физика) comes from the poll; do not wait for its interval */
    expect((await call("post", `/api/devices/${id}/poll`)).status()).toBe(202);
  }

  /* The schedule takes the baseline of both devices: one version each, not drift. */
  const baseline = {} as Record<Model, State>;
  for (const m of Object.keys(MODELS) as Model[]) {
    await expect
      .poll(async () => (await versions(ids[m])).map((v) => `${v.source} drift=${v.drift}`), { timeout: 3 * 60_000, intervals: [3_000], message: `${m} baseline` })
      .toEqual(["schedule drift=false"]);
    baseline[m] = await state(ids[m]);
    expect(baseline[m].last_error).toBeNull();
    const dev = await json<{ driver: string; state: string }>(`/api/devices/${ids[m]}`);
    expect(dev.driver).toBe(MODELS[m].driver);
  }
  const gapOver = Math.max(...Object.values(baseline).map((s) => Date.parse(s.last_ok_at!))) + BACKUP_GAP_MS + 20_000;

  /* The masked copies hold the configuration without its secrets; so does the download. */
  for (const m of Object.keys(MODELS) as Model[]) {
    const [v] = await versions(ids[m]);
    const masked = await json<{ text: string }>(`/api/devices/${ids[m]}/backups/${v.id}`);
    expect(masked.text).toContain("description uplink");
    expect((await call("get", `/api/devices/${ids[m]}/backups/${v.id}/download`)).status()).toBe(200);
  }

  /* Физика: the front panel of the MES from its inventory (gi1/0/1 RJ-45, te1/0/1 SFP). */
  const mes = ids.mes;
  await expect
    .poll(async () => (await json<{ items: { name: string; port_kind: string }[] }>(`/api/devices/${mes}/interfaces`)).items.map((i) => `${i.name} ${i.port_kind}`).sort(), {
      timeout: 2 * 60_000,
      intervals: [3_000],
    })
    .toEqual(["gi1/0/1 rj45", "te1/0/1 sfp"]);
  await goto(`/devices/${mes}`);
  await expect(page.getByRole("heading", { name: "e2e-mes" })).toBeVisible();
  await page.getByRole("tab", { name: "Физика" }).click();
  await expect(page.getByRole("group", { name: "RJ-45: 1" }).getByRole("button", { name: /^Порт gi1\/0\/1:/ })).toBeVisible();
  await expect(page.getByRole("group", { name: "SFP: 1" }).getByRole("button", { name: /^Порт te1\/0\/1:/ })).toBeVisible();
  await seen.page(page, "physical");

  /* Конфиг: the masked copy split into sections. */
  await page.getByRole("tab", { name: "Конфиг" }).click();
  await expect(page.getByRole("tree")).toBeVisible();
  for (const item of await page.getByRole("treeitem").all()) {
    await item.click();
    await seen.page(page, "config section");
  }

  /* CLI: an allowlisted show runs on the device and its output is shown. */
  await page.getByRole("tab", { name: "CLI" }).click();
  await page.getByLabel("Команда").selectOption("version");
  await page.getByRole("button", { name: "Выполнить" }).click();
  const panel = page.getByRole("tabpanel");
  await expect(panel.getByRole("status")).toHaveText("Готово", { timeout: 60_000 });
  await expect(page.getByTestId("cli-output")).toContainText("e2e-show-version-output");
  await seen.page(page, "cli");

  /* Бэкапы: the scheduled version is listed. */
  await page.getByRole("tab", { name: "Бэкапы" }).click();
  const table = page.getByRole("table", { name: "Версии конфигурации" });
  await expect(table.getByRole("row")).toHaveCount(2);
  await expect(table).toContainText("по расписанию");
  await seen.page(page, "backups");

  /* The poller refuses a second backup within 5 minutes of the last one; wait the gap out. */
  while (Date.now() < gapOver) await sleep(5_000);

  /* ESR: the configuration changes on the device. Written next to the file and renamed, so a read never sees half of it. */
  const esrConfig = readFileSync(runningConfig("esr"), "utf8");
  expect(esrConfig.split("\n").filter((l) => l === BEFORE)).toHaveLength(1);
  const next = join(".auth", "sshemu-esr", ".next"); /* sshemud serves no name starting with "." */
  writeFileSync(next, esrConfig.replace(`\n${BEFORE}\n`, `\n${AFTER}\n`));
  renameSync(next, runningConfig("esr"));

  /*
   * Manual backups through the window. The window polls the backup state until the backup is done: wait for that and
   * for its polls to stop before leaving, so no poll response is cut short by the navigation.
   */
  for (const m of Object.keys(MODELS) as Model[]) {
    await goto(`/devices/${ids[m]}?tab=backups`);
    await page.getByRole("button", { name: "Снять бэкап" }).click();
    await expect(panel.getByRole("status")).toHaveText("Бэкап поставлен в очередь");
    await expect
      .poll(async () => (await state(ids[m])).last_ok_at !== baseline[m].last_ok_at, { timeout: 2 * 60_000, intervals: [2_000], message: `${m} manual backup` })
      .toBe(true);
    await seen.quiet(BACKUP_POLL_MS + 2_000);
  }

  /* MES, unchanged: the backup ran (last_ok_at moved) and stored nothing new. */
  await expect
    .poll(async () => (await state(mes)).last_ok_at !== baseline.mes.last_ok_at, { timeout: 2 * 60_000, intervals: [2_000], message: "MES manual backup" })
    .toBe(true);
  expect((await state(mes)).last_error).toBeNull();
  expect((await versions(mes)).length).toBe(1);

  /* ESR, changed: a second version, manual and drift. */
  const esr = ids.esr;
  await expect
    .poll(async () => (await versions(esr)).map((v) => `${v.source} drift=${v.drift}`), { timeout: 2 * 60_000, intervals: [2_000], message: "ESR second version" })
    .toEqual(["manual drift=true", "schedule drift=false"]);
  const [v2, v1] = await versions(esr);
  const diff = await json<{ diff: string }>(`/api/devices/${esr}/backups/diff?a=${v1.id}&b=${v2.id}`);
  const changed = diff.diff.split("\n").filter((l) => /^[+-]/.test(l) && !/^(\+\+\+|---) /.test(l));
  expect(changed).toEqual([`-${BEFORE}`, `+${AFTER}`]);
  expect((await json<{ text: string }>(`/api/devices/${esr}/backups/${v2.id}`)).text).toContain(AFTER.trim());

  /* The same diff in the window: A the baseline, B the new version. */
  await seen.quiet(BACKUP_POLL_MS + 2_000);
  await page.reload();
  await expect(table.getByRole("row")).toHaveCount(3);
  await expect(table).toContainText("вручную");
  await expect(table.getByText("дрейф")).toHaveCount(1);
  await table.getByRole("radio", { name: /^Сторона A/ }).nth(1).check();
  await table.getByRole("radio", { name: /^Сторона B/ }).nth(0).check();
  await page.getByRole("button", { name: "Сравнить A и B" }).click();
  const shown = page.getByTestId("backup-diff");
  await expect(shown.locator("div").filter({ hasText: /^\+\s+description uplink-e2e$/ })).toHaveCount(1);
  await expect(shown.locator("div").filter({ hasText: /^-\s+description uplink$/ })).toHaveCount(1);
  await seen.page(page, "diff");
  await page.getByRole("tab", { name: "Журнал" }).click();
  await expect(page.getByText("Конфигурация изменена вне панели (вручную)")).toBeVisible();
  await seen.page(page, "journal");

  /* Not one known secret anywhere the test looked. */
  expect(await seen.leaks()).toEqual([]);

  /* The devices are the test's own (dashboards.spec.ts adds its own device). */
  for (const id of Object.values(ids)) expect((await call("delete", `/api/devices/${id}`)).status()).toBe(204);
});
