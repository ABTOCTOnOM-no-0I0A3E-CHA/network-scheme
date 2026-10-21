import { readFileSync, writeFileSync } from "node:fs";
import sodium from "libsodium-wrappers";
import { currentStep, STATE_FILE, STEP_FILE, totpCode } from "./auth";
import { expect, test } from "./guard";

/*
 * The snmpsim container the CI job attaches to the devices network, and its
 * synthetic SNMPv3 user (the same values as test/sim/snmpsim/simtest).
 */
const SIM_ADDRESS = process.env.NMS_E2E_SNMPSIM ?? "";
const SIM_V3 = {
  user: "simuser",
  auth_proto: "SHA256",
  auth_key: "sim-auth-key-0123456789",
  priv_proto: "AES",
  priv_key: "sim-priv-key-0123456789",
};

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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

test("device polled end to end", async ({ page, context }) => {
  test.setTimeout(4 * 60_000);
  expect(SIM_ADDRESS, "NMS_E2E_SNMPSIM (simulator address on the devices network)").not.toBe("");
  const api = page.request;
  const csrf = async () => ({ "X-CSRF-Token": (await (await api.get("/api/auth/me")).json()).csrf_token as string });

  /* Credentials need a step-up. A TOTP step is accepted once per user: take one after every step used so far. */
  const used = Math.max(Number(readFileSync(STEP_FILE, "utf8")), currentStep());
  while (currentStep() <= used) await sleep(1000);
  const step = currentStep();
  let res = await api.post("/api/auth/stepup", { headers: await csrf(), data: { code: await totpCode(step) } });
  expect(res.status()).toBe(204);
  writeFileSync(STEP_FILE, String(step));
  await context.storageState({ path: STATE_FILE }); /* step-up rotated the session token */
  const headers = await csrf();

  res = await api.post("/api/groups", { headers, data: { name: "e2e" } });
  expect(res.status()).toBe(201);
  const group = (await res.json()).id as number;
  res = await api.post("/api/devices", { headers, data: { name: "snmpsim", address: SIM_ADDRESS, group_id: group } });
  expect(res.status()).toBe(201);
  const id = (await res.json()).id as number;

  const read = (await (await api.get("/keys.json")).json()).domains.read as { public_key: string; key_version: number };
  const ciphertext = await seal(read.public_key, `device:${id}`, "snmp3", SIM_V3);
  res = await api.put(`/api/devices/${id}/profiles/snmp3`, { headers, data: { ciphertext, key_version: read.key_version } });
  expect(res.status()).toBe(204);
  res = await api.post(`/api/devices/${id}/poll`, { headers });
  expect(res.status()).toBe(202);

  /* Within 90 s the poller has opened the credential, the device is up and its interfaces are stored. */
  await expect
    .poll(
      async () => {
        const dev = await (await api.get(`/api/devices/${id}`)).json();
        const ifs = await (await api.get(`/api/devices/${id}/interfaces`)).json();
        return { state: dev.state, interfaces: ifs.items.length > 0 };
      },
      { timeout: 90_000, intervals: [2_000] },
    )
    .toEqual({ state: "up", interfaces: true });
  const profiles = await (await api.get(`/api/devices/${id}/profiles`)).json();
  expect(profiles).toEqual([expect.objectContaining({ kind: "snmp3", status: "ok" })]);
});
