import { writeFileSync } from "node:fs";
import sodium from "libsodium-wrappers";
import { stepUp } from "./auth";
import { expect, test } from "./guard";

/*
 * Containers the CI job attaches to the devices network (see .github/workflows/ci.yml):
 *  - NMS_E2E_EVENT_SRC: the device. It answers SNMPv2c (community COMMUNITY, served by an snmpsim
 *    data file) and sends syslog over UDP and TCP and a linkDown trap, all from its own address.
 *  - NMS_E2E_EVENT_ROGUE: no device has this address; it sends syslog and a trap with the same community.
 *  - NMS_E2E_EVENT_NETNS: the address of a sender in a network namespace joined to the runner by a veth
 *    pair, inside a configured management subnet. It sends syslog to the PUBLISHED ports (514 UDP and TCP,
 *    6514 TLS) of the runner, so its packets pass DNAT and FORWARD like a device's on another network. The
 *    event is attributed to the device registered with that address only if eventd sees the sender's own
 *    address as the source: that is the proof that docker's NAT preserves it. With the userland proxy on,
 *    the proxy would terminate the connection and open its own, the source would be the bridge gateway,
 *    no device would match and this test would fail.
 *  - A second namespace outside every management subnet sends to 514 as well: the DOCKER-USER ingress
 *    rules drop it (a later CI step reads their counters) and nothing of it may be stored.
 * All run test/e2e/send_events.py every few seconds; the messages carry the markers below.
 */
const SRC = process.env.NMS_E2E_EVENT_SRC ?? "";
const ROGUE = process.env.NMS_E2E_EVENT_ROGUE ?? "";
const NETNS = process.env.NMS_E2E_EVENT_NETNS ?? "";
const COMMUNITY = "e2e-events-community-01";
const GROUP = "events-e2e";
const MARK_UDP = "e2eknownudp";
const MARK_TCP = "e2eknowntcp";
const MARK_TLS = "e2eknowntls";
const MARKS_ROGUE = ["e2erogueudp", "e2eroguetcp", "e2enegudp", "e2enegtcp"];
const MARKS_NETNS = ["e2enetnsudp", "e2enetnstcp", "e2enetnstls"];
const DAY_S = 86400;

type EventItem = { kind: "syslog" | "trap"; device_id: number; name?: string; text: string };

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

test("events from a known device arrive and a stranger's do not", async ({ page }) => {
  test.setTimeout(5 * 60_000);
  expect(SRC, "NMS_E2E_EVENT_SRC (event source container on the devices network)").not.toBe("");
  expect(ROGUE, "NMS_E2E_EVENT_ROGUE (second container, no device)").not.toBe("");
  expect(NETNS, "NMS_E2E_EVENT_NETNS (namespace sender address, published ports)").not.toBe("");
  expect(ROGUE).not.toBe(SRC);
  const api = page.request;
  const csrf = async () => ({ "X-CSRF-Token": ((await (await api.get("/api/auth/me")).json()) as { csrf_token: string }).csrf_token });
  const events = async (query: string) =>
    ((await (await api.get(`/api/events?${query}`)).json()) as { items: EventItem[] }).items;

  await stepUp(page);

  /* The device. Its polls are pushed a day away, so only the trap can cause one within this test. */
  const groups = (await (await api.get("/api/groups")).json()) as { id: number; name: string }[];
  let group = groups.find((g) => g.name === GROUP)?.id;
  if (group === undefined) {
    const res = await api.post("/api/groups", { headers: await csrf(), data: { name: GROUP } });
    expect(res.status()).toBe(201);
    group = (await res.json()).id as number;
  }
  /* Polls are pushed a day away right away: nothing but an event may cause one, and the poller does not probe the namespace address more than needed. */
  const addDevice = async (name: string, address: string): Promise<number> => {
    const created = await api.post("/api/devices", { headers: await csrf(), data: { name, address, group_id: group } });
    expect(created.status()).toBe(201);
    const devId = (await created.json()).id as number;
    return devId;
  };
  const slowPolls = async (devId: number) => {
    const patched = await api.patch(`/api/devices/${devId}`, {
      headers: await csrf(),
      data: { interval_avail_s: DAY_S, interval_metrics_s: DAY_S, interval_inventory_s: DAY_S },
    });
    expect(patched.status()).toBe(204);
  };
  const id = await addDevice("events-src", SRC);
  const netnsId = await addDevice("events-netns", NETNS);
  await slowPolls(netnsId);
  /* Recorded for the CI step that looks for the poll_now job eventd queued. */
  writeFileSync(".auth/events-device-id", String(id));

  const read = (await (await api.get("/keys.json")).json()).domains.read as { public_key: string; key_version: number };
  const ciphertext = await seal(read.public_key, `device:${id}`, "snmp2c", { community: COMMUNITY });
  let res = await api.put(`/api/devices/${id}/profiles/snmp2c`, { headers: await csrf(), data: { ciphertext, key_version: read.key_version } });
  expect(res.status()).toBe(204);
  /* A profile change sends no notification to eventd, a device change does: this one makes it reread the profile now. */
  await slowPolls(id);

  /* Syslog over UDP and TCP, attributed to the device by the packet's source address. */
  for (const mark of [MARK_UDP, MARK_TCP, MARK_TLS]) {
    await expect
      .poll(async () => (await events(`kind=syslog&device_id=${id}&q=${mark}`)).length > 0, { timeout: 30_000, intervals: [1_000], message: mark })
      .toBe(true);
  }
  /* Through the published ports of the host (docker NAT, FORWARD), attributed to the device with the sender's own address. */
  for (const mark of MARKS_NETNS) {
    await expect
      .poll(async () => (await events(`kind=syslog&device_id=${netnsId}&q=${mark}`)).length > 0, { timeout: 30_000, intervals: [1_000], message: mark })
      .toBe(true);
  }
  /* Nothing more is needed from this device. */
  expect((await api.delete(`/api/devices/${netnsId}`, { headers: await csrf() })).status()).toBe(204);
  /* The trap: linkDown is a standard trap, named without a rule. */
  await expect
    .poll(async () => (await events(`kind=trap&device_id=${id}`)).some((e) => e.name === "linkDown"), { timeout: 30_000, intervals: [1_000] })
    .toBe(true);

  /* The trap made the poller poll now: the device is up and its interfaces are stored. (That eventd, and nobody else, queued the
     poll_now job is checked from the database by the CI step that follows.) */
  await expect
    .poll(
      async () => {
        const dev = (await (await api.get(`/api/devices/${id}`)).json()) as { state: string };
        const ifs = (await (await api.get(`/api/devices/${id}/interfaces`)).json()) as { items: unknown[] };
        return { state: dev.state, interfaces: ifs.items.length > 0 };
      },
      { timeout: 90_000, intervals: [2_000] },
    )
    .toEqual({ state: "up", interfaces: true });

  /* The stranger has been sending all along: nothing of it is stored, anywhere. */
  for (const mark of MARKS_ROGUE) expect(await events(`q=${mark}`), mark).toEqual([]);

  /* Logs page: the device's messages are listed. */
  await page.goto("/");
  await page.getByRole("link", { name: "Логи" }).click();
  await expect(page.getByText(/e2eknown(udp|tcp)/).first()).toBeVisible();
  await expect(page.getByText("linkDown").first()).toBeVisible();

  /* System status: eventd counted the stranger's packets. */
  await page.getByRole("link", { name: "Состояние системы" }).click();
  await expect(page.getByRole("table", { name: "Приём событий (eventd)" })).toBeVisible();
  await expect
    .poll(
      async () => {
        const s = (await (await api.get("/api/system/status")).json()) as { eventd: { unknown_source: number; accepted: number }[] };
        return s.eventd.some((e) => e.unknown_source > 0 && e.accepted > 0);
      },
      { timeout: 60_000, intervals: [2_000] },
    )
    .toBe(true);
  await page.reload();
  await expect(page.getByRole("table", { name: "Приём событий (eventd)" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Неизвестный источник" })).toBeVisible();
});
