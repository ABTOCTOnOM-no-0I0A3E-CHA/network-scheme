import { readFileSync } from "node:fs";
import { join } from "node:path";
import sodium from "libsodium-wrappers";
import { stepUp } from "./auth";
import { expect, ORIGIN, test } from "./guard";

/*
 * Topology and map end to end. CI starts one snmpsim container per test/fixtures/snmp/topology-*.snmprec at the fixed
 * addresses of test/lab/topology.yaml (the LLDP management addresses of the fixtures), answering SNMPv2c with the community
 * of the same list. The test registers the four devices, waits for the builder and compares the automatic links with the
 * reference list (internal/topology TestReferenceTopology checks the same list without timing); then a manual link and a
 * pinned position must survive a rebuild, an SVG with active content is uploaded as a background and shown only through <img>,
 * and the mini map on the home page is checked (bubble effect, "Открыть", reduced motion).
 */
const LAB = process.env.NMS_E2E_LAB ?? "../lab";
const GROUP = "topology-e2e";
const VIEW = "topology-e2e";

type Item = Record<string, string>;
type Reference = { devices: Item[]; links: Item[] };

/* Reads the restricted layout of topology.yaml: "section:" lines, "  - key: value" item starts and "    key: value" lines. */
function reference(): Reference {
  const out: Reference = { devices: [], links: [] };
  let list: Item[] | undefined;
  for (const raw of readFileSync(join(LAB, "topology.yaml"), "utf8").split("\n")) {
    const line = raw.trimEnd();
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const section = /^(devices|links):$/.exec(line);
    if (section) {
      list = out[section[1] as keyof Reference];
      continue;
    }
    const start = /^\s+- (\w+): (.*)$/.exec(line);
    const more = /^\s+(\w+): (.*)$/.exec(line);
    if (start && list) list.push({ [start[1]]: start[2] });
    else if (more && list && list.length > 0) list[list.length - 1][more[1]] = more[2];
    else throw new Error(`topology.yaml: unexpected line "${line}"`);
  }
  return out;
}

/* "end end <-> ... source confidence", independent of the order of the ends (the same text as the Go test). */
function linkText(a: string, aPort: string, b: string, bPort: string, source: string, confidence: number): string {
  const [x, y] = [`${a} ${aPort}`, `${b} ${bPort}`].sort();
  return `${x} <-> ${y} ${source} ${confidence.toFixed(2)}`;
}

type Topology = {
  nodes: { device_id: number; name: string; pinned: boolean; x?: number; y?: number }[];
  links: { a: number; b: number; a_port_name: string; b_port_name: string; source: string; confidence: number; manual: boolean }[];
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

/* An SVG with every kind of active content the sanitizer must remove, and a rectangle it must keep. */
const EVIL_SVG = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="120" onload="alert(1)">
  <script>alert(1)</script>
  <rect width="200" height="120" fill="#336699" onclick="alert(2)"/>
  <foreignObject width="100" height="100"><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(3)</script></div></foreignObject>
  <a xlink:href="javascript:alert(4)"><circle cx="50" cy="50" r="20" fill="#ffffff"/></a>
</svg>`;

test("topology and map end to end", async ({ page }) => {
  test.setTimeout(20 * 60_000);
  const ref = reference();
  expect(ref.devices.length).toBeGreaterThanOrEqual(3);
  const api = page.request;
  const csrf = async () => ({ "X-CSRF-Token": ((await (await api.get("/api/auth/me")).json()) as { csrf_token: string }).csrf_token });

  const dialogs: string[] = [];
  const errors: string[] = [];
  page.on("dialog", (d) => {
    dialogs.push(`${d.type()}: ${d.message()}`);
    void d.dismiss();
  });
  page.on("pageerror", (e) => errors.push(e.message));

  await stepUp(page); /* credentials need a step-up (the cleanup takes another) */
  let res = await api.post("/api/groups", { headers: await csrf(), data: { name: GROUP } });
  expect(res.status()).toBe(201);
  const group = (await res.json()).id as number;
  const ids = new Map<string, number>(); /* device name -> id */
  const names = new Map<number, string>();
  let view = 0;
  try {
    const read = (await (await api.get("/keys.json")).json()).domains.read as { public_key: string; key_version: number };
    for (const d of ref.devices) {
      res = await api.post("/api/devices", { headers: await csrf(), data: { name: d.name, address: d.address, group_id: group } });
      expect(res.status(), `create ${d.name}`).toBe(201);
      const id = (await res.json()).id as number;
      ids.set(d.name, id);
      names.set(id, d.name);
      const ciphertext = await seal(read.public_key, `device:${id}`, "snmp2c", { community: d.community });
      res = await api.put(`/api/devices/${id}/profiles/snmp2c`, { headers: await csrf(), data: { ciphertext, key_version: read.key_version } });
      expect(res.status()).toBe(204);
      expect((await api.post(`/api/devices/${id}/poll`, { headers: await csrf() })).status()).toBe(202);
    }
    const id = (name: string) => ids.get(name) as number;

    /* Every device is up and its interfaces (and with them the neighbour tables) are stored. */
    await expect
      .poll(
        async () => {
          const out: Record<string, string> = {};
          for (const [name, did] of ids) {
            const dev = await (await api.get(`/api/devices/${did}`)).json();
            const ifs = await (await api.get(`/api/devices/${did}/interfaces`)).json();
            out[name] = `${dev.state} ${ifs.items.length}`;
          }
          return out;
        },
        { timeout: 120_000, intervals: [3_000], message: "devices polled" },
      )
      .toEqual(Object.fromEntries(ref.devices.map((d) => [d.name, "up 4"])));

    const topology = async (query = "") => (await (await api.get(`/api/topology${query}`)).json()) as Topology;
    const mine = (t: Topology, manual: boolean) =>
      t.links.filter((l) => names.has(l.a) && names.has(l.b) && l.manual === manual);
    const auto = async () =>
      mine(await topology(), false)
        .map((l) => linkText(names.get(l.a) as string, l.a_port_name, names.get(l.b) as string, l.b_port_name, l.source, l.confidence))
        .sort();
    const expected = ref.links.map((l) => linkText(l.a, l.a_port, l.b, l.b_port, l.source, Number(l.confidence))).sort();

    /* The builder runs every minute and after device changes: the links of the fixtures appear within a few builds. */
    const started = Date.now();
    await expect.poll(auto, { timeout: 4 * 60_000, intervals: [5_000], message: "automatic links equal test/lab/topology.yaml" }).toEqual(expected);
    console.log(`links built ${Math.round((Date.now() - started) / 1000)} s after the devices were up`);

    /* A view with a pinned device and a manual link. */
    res = await api.post("/api/map/views", { headers: await csrf(), data: { name: VIEW, kind: "logical" } });
    expect(res.status()).toBe(201);
    view = (await res.json()).id as number;
    res = await api.put(`/api/map/views/${view}/positions`, {
      headers: await csrf(),
      data: { items: [{ device_id: id("topo-a"), x: 123, y: 456, pinned: true }] },
    });
    expect(res.status()).toBe(204);
    /* topo-b and topo-c are not linked by any fixture; ifIndex n is Gi1/0/n */
    res = await api.post("/api/links", {
      headers: await csrf(),
      data: { a_device_id: id("topo-b"), a_if_index: 2, b_device_id: id("topo-c"), b_if_index: 2 },
    });
    expect(res.status()).toBe(201);
    const survivors = async () => {
      const t = await topology(`?view_id=${view}`);
      const manual = mine(t, true).map((l) => linkText(names.get(l.a) as string, l.a_port_name, names.get(l.b) as string, l.b_port_name, l.source, l.confidence));
      const a = t.nodes.find((n) => n.device_id === id("topo-a"));
      return { manual, pinned: [a?.pinned, a?.x, a?.y] };
    };
    const kept = { manual: [linkText("topo-b", "Gi1/0/2", "topo-c", "Gi1/0/2", "manual", 1)], pinned: [true, 123, 456] };
    expect(await survivors()).toEqual(kept);

    /* Waiting 70 s guarantees a periodic build (every 60 s) after both writes; the device change below is just another write. */
    res = await api.patch(`/api/devices/${id("topo-d")}`, { headers: await csrf(), data: { snmp_port: 161 } });
    expect(res.status()).toBe(204);
    await sleep(70_000);
    expect(await survivors(), "manual link and pinned position survive the rebuild").toEqual(kept);
    expect(await auto(), "automatic links unchanged by the rebuild").toEqual(expected);

    /* Background: the sanitized SVG is stored and served with the sandbox policy. */
    res = await api.post("/api/map/backgrounds", {
      headers: await csrf(),
      multipart: { file: { name: "evil.svg", mimeType: "image/svg+xml", buffer: Buffer.from(EVIL_SVG) } },
    });
    expect(res.status(), await res.text()).toBe(201);
    const bg = (await res.json()) as { id: number; mime: string };
    expect(bg.mime).toBe("image/svg+xml");
    const src = `/api/map/backgrounds/${bg.id}`;
    const served = await api.get(src);
    expect(served.status()).toBe(200);
    expect(served.headers()["content-type"]).toContain("image/svg+xml");
    expect(served.headers()["content-security-policy"]).toContain("sandbox");
    expect(served.headers()["content-security-policy"]).toContain("default-src 'none'");
    expect(served.headers()["x-content-type-options"]).toBe("nosniff");
    const body = await served.text();
    expect(body).toContain("<rect");
    expect(body).not.toMatch(/<script|alert|on(load|click)|foreignobject|javascript:/i);
    res = await api.patch(`/api/map/views/${view}`, { headers: await csrf(), data: { background_id: bg.id } });
    expect(res.status()).toBe(204);

    /* The map shows it only through <img>; nothing executes. */
    await page.goto(`/map?view=${view}`);
    const map = page.getByTestId("network-map");
    await expect(map).toBeVisible();
    const img = map.locator(`img[src="${src}"]`);
    await expect(img).toHaveCount(1);
    await expect.poll(() => img.evaluate((e) => (e as HTMLImageElement).naturalWidth), { timeout: 15_000 }).toBe(200);
    await expect(page.locator("object, iframe, embed")).toHaveCount(0);
    await expect(page.locator("svg script, svg foreignObject, svg a[href^='javascript']")).toHaveCount(0);
    const nodes = () =>
      page.evaluate(() => (document.querySelector("[data-testid=map-canvas]") as unknown as { _cyreg?: { cy: { nodes(): { length: number } } } })._cyreg?.cy.nodes().length ?? 0);
    await expect.poll(nodes, { timeout: 30_000 }).toBeGreaterThanOrEqual(ref.devices.length);

    /* Mini map on the home page. */
    await page.goto("/");
    const mini = page.getByRole("region", { name: "Карта сети" });
    const box = mini.getByTestId("mini-map-box");
    await expect(box).toBeVisible();
    await expect(mini.locator("[data-testid=map-canvas]")).toBeVisible();
    expect(await box.getAttribute("class")).toContain("hover:scale-[1.04]");
    /* Tailwind v4 scales with the CSS `scale` property, not `transform` */
    const scale = (l: typeof box) => l.evaluate((e) => getComputedStyle(e).scale);
    expect(await scale(box)).toBe("none");
    await box.hover();
    await expect.poll(() => scale(box), { timeout: 5_000 }).toBe("1.04");

    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    const calm = page.getByRole("region", { name: "Карта сети" }).getByTestId("mini-map-box");
    await expect(calm).toBeVisible();
    expect(await calm.getAttribute("class")).not.toContain("hover:scale");
    await calm.hover();
    await sleep(500);
    expect(await calm.evaluate((e) => getComputedStyle(e).scale)).toBe("none");
    await page.emulateMedia({ reducedMotion: null });

    await page.goto("/");
    await page.getByRole("region", { name: "Карта сети" }).getByRole("button", { name: "Открыть" }).click();
    await expect(page).toHaveURL(`${ORIGIN}/map?view=${view}`);
    await expect(page.getByTestId("network-map")).toBeVisible();

    expect(dialogs, "dialogs").toEqual([]);
    expect(errors, "page errors").toEqual([]);
  } finally {
    /* Clean up: the view, then the devices (their links and neighbour data go with them) and the group. */
    if (view !== 0) await api.delete(`/api/map/views/${view}`, { headers: await csrf() });
    await stepUp(page);
    for (const did of ids.values()) await api.delete(`/api/devices/${did}`, { headers: await csrf() });
    await api.delete(`/api/groups/${group}`, { headers: await csrf() });
  }
});
