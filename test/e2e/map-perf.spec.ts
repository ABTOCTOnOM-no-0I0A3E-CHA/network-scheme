import { expect, test } from "./guard";

/*
 * Map performance with 5000 synthetic devices (spec NFR: pan/zoom >= 30 fps on the reference PC). The topology is mocked
 * (page.route), so no devices are needed; the panel, its CSP and the ELK worker are the real ones. CI renders with
 * software GL, so the gate here is 15 fps (ruling R3); 30 fps on the reference PC is a manual check. The measured value is
 * logged. Frames are counted with requestAnimationFrame while a script pans and zooms the map.
 */
const NODES = 5000;
const CI_MIN_FPS = 15;
const MEASURE_MS = 4000;

function synthetic() {
  const cols = 100;
  const states = ["up", "up", "up", "partial", "down", "unknown"] as const;
  const nodes = Array.from({ length: NODES }, (_, i) => ({
    device_id: i + 1,
    name: `sw-${i + 1}`,
    state: states[i % states.length],
    driver: i % 7 === 0 ? "eltex-esr" : "eltex-mes",
    pinned: true,
    x: (i % cols) * 80,
    y: Math.floor(i / cols) * 80,
  }));
  /* a ring-and-ladder mesh: about 1.5 links per device */
  const links = [] as object[];
  for (let i = 0; i < NODES; i++) {
    for (const j of [i + 1, i + cols]) {
      if (j >= NODES || (j === i + 1 && (i + 1) % cols === 0) || (j === i + cols && i % 3 === 0)) continue;
      links.push({
        id: links.length + 1,
        a: i + 1,
        b: j + 1,
        a_if: 1,
        b_if: 2,
        a_port_name: "gi1/0/1",
        b_port_name: "gi1/0/2",
        speed_bps: i % 5 === 0 ? 10e9 : 1e9,
        source: "lldp",
        confidence: i % 4 === 0 ? 0.5 : 1,
        manual: false,
      });
    }
  }
  return { nodes, links, areas: [] };
}

test(`map: ${NODES} devices stay interactive (pan/zoom >= ${CI_MIN_FPS} fps)`, async ({ page }) => {
  test.setTimeout(120_000);
  await page.route("**/api/map/views", (r) => r.fulfill({ json: [] }));
  await page.route("**/api/topology**", (r) => r.fulfill({ json: synthetic() }));
  await page.goto("/map");

  /* Cytoscape keeps its instance on the container element */
  const count = () => page.evaluate(() => (document.querySelector("[data-testid=map-canvas]") as unknown as { _cyreg?: { cy: { nodes(): { length: number } } } })._cyreg?.cy.nodes().length ?? 0);
  await expect.poll(count, { timeout: 60_000 }).toBe(NODES);

  const result = await page.evaluate(async (ms) => {
    const cy = (document.querySelector("[data-testid=map-canvas]") as unknown as { _cyreg: { cy: { zoom(o?: unknown): number; pan(o?: unknown): unknown; width(): number; height(): number; fit(): void } } })._cyreg.cy;
    cy.fit();
    const base = cy.zoom();
    const cx = cy.width() / 2;
    const cyy = cy.height() / 2;
    const stamps: number[] = [];
    const t0 = performance.now();
    await new Promise<void>((done) => {
      const tick = (now: number) => {
        stamps.push(now);
        const t = (now - t0) / 1000;
        cy.zoom({ level: base * (1.5 + Math.sin(t * 2)), renderedPosition: { x: cx, y: cyy } });
        cy.pan({ x: Math.sin(t * 3) * 120, y: Math.cos(t * 3) * 80 });
        if (now - t0 < ms) requestAnimationFrame(tick);
        else done();
      };
      requestAnimationFrame(tick);
    });
    const worst = Math.max(...stamps.slice(1).map((s, i) => s - stamps[i]));
    return { frames: stamps.length, seconds: (stamps[stamps.length - 1] - stamps[0]) / 1000, worstFrameMs: worst };
  }, MEASURE_MS);

  const fps = (result.frames - 1) / result.seconds;
  console.log(`map-perf: ${NODES} devices, ${fps.toFixed(1)} fps over ${result.seconds.toFixed(1)} s, worst frame ${result.worstFrameMs.toFixed(0)} ms`);
  expect(fps).toBeGreaterThanOrEqual(CI_MIN_FPS);
});

test("map: ELK runs in a worker from /assets/ without CSP violations", async ({ page }) => {
  /* devices without positions force an automatic layout in the worker; the guard fixture fails the test on any CSP violation */
  const nodes = Array.from({ length: 30 }, (_, i) => ({ device_id: i + 1, name: `n${i + 1}`, state: "up", driver: "eltex-mes", pinned: false }));
  const links = Array.from({ length: 29 }, (_, i) => ({ id: i + 1, a: i + 1, b: i + 2, a_if: 1, b_if: 1, a_port_name: "", b_port_name: "", speed_bps: 1e9, source: "lldp", confidence: 1, manual: false }));
  await page.route("**/api/map/views", (r) => r.fulfill({ json: [] }));
  await page.route("**/api/topology**", (r) => r.fulfill({ json: { nodes, links, areas: [] } }));
  const worker = page.waitForEvent("worker");
  await page.goto("/map");
  expect((await worker).url()).toMatch(/^https:\/\/localhost\/assets\/layout\.worker-[\w-]+\.js$/);
  await expect
    .poll(() =>
      page.evaluate(() => {
        const cy = (document.querySelector("[data-testid=map-canvas]") as unknown as { _cyreg: { cy: { nodes(): { map<T>(f: (n: { position(): { x: number; y: number } }) => T): T[] } } } })._cyreg.cy;
        return new Set(cy.nodes().map((n) => Math.round(n.position().x))).size;
      }),
    )
    /* a chain is one layered column; the placeholder grid used before the layout arrives spans several columns */
    .toBe(1);
});
