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

  it("fonts are bundled locally", () => {
    expect(walk(out).some((f) => /inter.*\.woff2$/i.test(f))).toBe(true);
  });
});
