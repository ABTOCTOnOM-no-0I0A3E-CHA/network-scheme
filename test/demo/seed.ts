/*
 * Demo only: fills the stand started by up.sh through the public API, as the browser would. Logs the admin in
 * (password, TOTP), takes a step-up, then adds a group, every device of devices.txt with its read credentials sealed to
 * the read key (as test/e2e does), and a shared dashboard with every widget that is the admin role's default.
 * Credentials come from .run/creds (written by up.sh, never committed); TLS is verified against the stand's CA.
 */
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import sodium from "libsodium-wrappers";

const RUN = join(import.meta.dir, ".run");
const BASE = "https://localhost";
const GROUP = "Демо-стенд";
const DASHBOARD = "Демо";
/* the read account of the simulated CLI: test values, the same in devices.sh */
const SSH = { username: "demo-read", password: "demo-read-pw" };

const ca = readFileSync(join(RUN, "ca.crt"), "utf8");
const cred = (name: string) => readFileSync(join(RUN, "creds", name), "utf8").trim();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

type Device = { name: string; address: string; fixture: string; community: string; ssh: string };
const devices: Device[] = readFileSync(join(import.meta.dir, "devices.txt"), "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l !== "" && !l.startsWith("#"))
  .map((l) => {
    const [name, address, fixture, community, ssh] = l.split(/\s+/);
    return { name, address, fixture, community, ssh };
  });

/* RFC 6238 TOTP (SHA-1, 6 digits, 30 s) of the base32 secret for the given time step. */
function totp(secret: string, step: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.toUpperCase().replace(/[=\s]/g, "")) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", key).update(msg).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
const step = () => Math.floor(Date.now() / 30_000);

let cookie = "";
let csrf = "";
async function call<T = unknown>(method: string, path: string, body?: unknown): Promise<{ status: number; data: T }> {
  const headers: Record<string, string> = {};
  if (cookie) headers.Cookie = cookie;
  if (csrf && method !== "GET") headers["X-CSRF-Token"] = csrf;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), tls: { ca } });
  for (const c of r.headers.getSetCookie()) if (c.startsWith("__Host-nms_session=")) cookie = c.split(";")[0];
  const text = await r.text();
  return { status: r.status, data: (text ? JSON.parse(text) : undefined) as T };
}
async function must<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await call<T>(method, path, body);
  if (r.status >= 300) throw new Error(`${method} ${path}: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}
const refreshCSRF = async () => (csrf = (await must<{ csrf_token: string }>("GET", "/api/auth/me")).csrf_token);

/* Login: password, then the TOTP of the current step. A step is accepted once per user, so the step-up waits for the next one. */
const secret = cred("totp-secret");
const login = await must<{ stage: string; challenge: string }>("POST", "/api/auth/login", { username: "admin", password: cred("admin-password") });
if (login.stage !== "totp") throw new Error(`login stage ${login.stage}, expected totp`);
const used = step();
await must("POST", "/api/auth/totp", { challenge: login.challenge, code: totp(secret, used) });
await refreshCSRF();
console.log("  logged in; waiting for the next TOTP step for the step-up (up to 30 s)");
while (step() <= used) await sleep(1000);
await must("POST", "/api/auth/stepup", { code: totp(secret, step()) });
await refreshCSRF();

const group = (await must<{ id: number }>("POST", "/api/groups", { name: GROUP })).id;
const read = (await must<{ domains: { read: { public_key: string; key_version: number } } }>("GET", "/keys.json")).domains.read;
await sodium.ready;
/* Seals a read credential as the browser does: payload v1 (internal/creds), crypto_box_seal to the read key. */
const seal = (owner: string, kind: string, s: object) =>
  b64(
    sodium.crypto_box_seal(
      sodium.from_string(
        JSON.stringify({ v: 1, owner, kind, created_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), nonce: b64(sodium.randombytes_buf(16)), secret: s }),
      ),
      Buffer.from(read.public_key, "base64"),
    ),
  );

const ids: Record<string, number> = {};
for (const d of devices) {
  const id = (await must<{ id: number }>("POST", "/api/devices", { name: d.name, address: d.address, group_id: group })).id;
  ids[d.name] = id;
  /* metrics every 30 s, so charts and the interface load fill within minutes */
  await must("PATCH", `/api/devices/${id}`, { interval_metrics_s: 30 });
  /* SSH first: the schedule backs a new device up within seconds, and it needs both */
  const profiles: [string, object][] = [];
  if (d.ssh !== "-") profiles.push(["ssh_read", SSH]);
  if (d.community !== "-") profiles.push(["snmp2c", { community: d.community }]);
  for (const [kind, s] of profiles) {
    await must("PUT", `/api/devices/${id}/profiles/${kind}`, { ciphertext: seal(`device:${id}`, kind, s), key_version: read.key_version });
  }
  await must("POST", `/api/devices/${id}/poll`);
  console.log(`  device ${d.name} (${d.address}) id ${id}`);
}

/* A shared dashboard with all 8 widgets, the default of the admin role (12-column grid). */
const chartDevice = ids["sw-floor-2"] ?? Object.values(ids)[0];
const dash = (await must<{ id: number }>("POST", "/api/dashboards", { name: DASHBOARD, shared: true, default_for_role: "admin" })).id;
await must("PUT", `/api/dashboards/${dash}/widgets`, {
  widgets: [
    { type: "device_status", x: 0, y: 0, w: 3, h: 6, config: {} },
    { type: "problems", x: 3, y: 0, w: 5, h: 6, config: { limit: 10 } },
    { type: "top_devices", x: 8, y: 0, w: 4, h: 6, config: { metric: "cpu", limit: 10 } },
    { type: "metric_chart", x: 0, y: 6, w: 6, h: 6, config: { device_id: chartDevice, metric: "cpu", range: "1h" } },
    { type: "top_interfaces", x: 6, y: 6, w: 6, h: 6, config: { limit: 10 } },
    { type: "log_stream", x: 0, y: 12, w: 6, h: 8, config: { limit: 20 } },
    { type: "mini_map", x: 6, y: 12, w: 6, h: 8, config: {} },
    { type: "recent_changes", x: 0, y: 20, w: 12, h: 6, config: { limit: 10 } },
  ],
});
console.log(`  dashboard «${DASHBOARD}» id ${dash} with 8 widgets`);

/* Wait for the first polls: every device with a fixture up. */
const expected = devices.filter((d) => d.fixture !== "-").map((d) => d.name);
for (let i = 0; ; i++) {
  const list = await must<{ name: string; state: string }[]>("GET", "/api/devices");
  const up = list.filter((d) => d.state === "up").map((d) => d.name);
  if (expected.every((n) => up.includes(n))) break;
  if (i >= 60) {
    console.log(`  not up yet after 3 min: ${expected.filter((n) => !up.includes(n)).join(", ")}`);
    break;
  }
  await sleep(3000);
}
console.log(`  devices up: ${expected.length} of ${devices.length} (offline-1 stays down on purpose)`);
