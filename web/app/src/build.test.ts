// @vitest-environment node
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

const root = path.resolve(__dirname, "..");
const out = path.join(mkdtempSync(path.join(tmpdir(), "nms-dist-")), "dist");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

describe("production build", () => {
  let html = "";
  beforeAll(() => {
    execFileSync("bunx", ["vite", "build", "--outDir", out, "--emptyOutDir"], { cwd: root, shell: true, stdio: "pipe", env: { ...process.env, NODE_ENV: "production" } });
    html = readFileSync(path.join(out, "index.html"), "utf8");
  }, 120000);

  it("index.html has no inline script and no style element", () => {
    const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);
    expect(scripts.length).toBeGreaterThan(0);
    for (const s of scripts) expect(s).toMatch(/\bsrc=/);
    expect(html).not.toMatch(/<script\b[^>]*>\s*(?!<\/script>)\S/i);
    expect(html).not.toMatch(/<style\b/i);
    expect(html).not.toMatch(/\sstyle=/i);
  });

  it("bundles no references to external hosts", () => {
    /*
     * Inert strings only: SVG namespace, URL-parsing base, links inside error
     * messages and a license banner. None of them is ever requested.
     */
    const allowed = [
      "http://www.w3.org/",
      "http://localhost",
      "https://react.dev/errors/",
      "https://react.i18next.com/",
      "https://tailwindcss.com",
    ];
    const offenders: string[] = [];
    for (const f of walk(out)) {
      if (/\.(woff2?|png|ico)$/.test(f)) continue;
      const text = readFileSync(f, "utf8");
      for (const m of text.matchAll(/https?:\/\/[^\s"'`)\\<>]+/g)) {
        if (!allowed.some((a) => m[0].startsWith(a))) offenders.push(`${path.relative(out, f)}: ${m[0]}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("ships no runtime <style> injection paths that the CSP would block", () => {
    /*
     * A literal createElement("style")/insertRule scan cannot be zero: React DOM keeps a
     * <style precedence> path we never use. What matters is that the libraries which inject
     * styles on every use are absent or disarmed:
     *  - react-remove-scroll / react-style-singleton (modal Radix Dialog/Menu/Popover/Select):
     *    absent (vite aliases react-remove-scroll to a no-op), identified by the
     *    __webpack_nonce__ lookup and scroll-lock markers;
     *  - input-otp: skips its injection when an element with id input-otp-style exists.
     */
    const js = walk(out).filter((p) => p.endsWith(".js")).map((f) => readFileSync(f, "utf8"));
    for (const text of js) {
      expect(text).not.toContain("__webpack_nonce__");
      expect(text).not.toContain("data-scroll-locked");
    }
    expect(html).toMatch(/<meta\s+id="input-otp-style"/);
  });

  it("uPlot styles ship in the bundled CSS file, not through script", () => {
    const css = walk(out).filter((p) => p.endsWith(".css")).map((f) => readFileSync(f, "utf8")).join(" ");
    expect(css).toContain(".uplot");
    expect(html).toMatch(/<link[^>]+rel="stylesheet"/);
  });

  it("sealing is pure JS: no WebAssembly and no wasm CSP relaxation", () => {
    for (const f of walk(out).filter((p) => /\.(js|html)$/.test(p))) {
      expect(readFileSync(f, "utf8")).not.toMatch(/WebAssembly|wasm-unsafe-eval/);
    }
  });

  it("fonts are bundled locally", () => {
    expect(walk(out).some((f) => /inter.*\.woff2$/i.test(f))).toBe(true);
  });
});
