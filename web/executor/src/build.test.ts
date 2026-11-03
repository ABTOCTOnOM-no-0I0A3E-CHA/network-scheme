// @vitest-environment node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { addSri } from "../../shared/scripts/sri";

const root = path.resolve(__dirname, "..");
const out = path.join(mkdtempSync(path.join(tmpdir(), "nms-exec-dist-")), "dist");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

describe("executor production build", () => {
  let html = "";
  let files: string[] = [];
  beforeAll(() => {
    execFileSync("bunx", ["vite", "build", "--outDir", out, "--emptyOutDir"], { cwd: root, shell: true, stdio: "pipe", env: { ...process.env, NODE_ENV: "production" } });
    /* what `bun run build` does after vite */
    addSri(out);
    html = readFileSync(path.join(out, "index.html"), "utf8");
    files = walk(out);
  }, 120000);

  it("index.html has no inline script, no style element and no style attribute", () => {
    const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);
    expect(scripts.length).toBeGreaterThan(0);
    for (const s of scripts) expect(s).toMatch(/\bsrc=/);
    expect(html).not.toMatch(/<script\b[^>]*>\s*(?!<\/script>)\S/i);
    expect(html).not.toMatch(/<style\b/i);
    expect(html).not.toMatch(/\sstyle=/i);
    expect(html).not.toMatch(/\son\w+=/i);
  });

  it("every script and stylesheet is a hashed file under /assets/ with a correct SRI hash", () => {
    const tags = [...html.matchAll(/<(?:script|link)\b[^>]*>/gi)].map((m) => m[0]).filter((t) => /\bsrc=|rel="stylesheet"/.test(t));
    expect(tags.length).toBeGreaterThanOrEqual(2);
    for (const t of tags) {
      const url = /(?:src|href)="([^"]+)"/.exec(t)![1];
      expect(url).toMatch(/^\/assets\/[\w.-]+-[\w-]{8}\.(js|css)$/);
      const want = "sha384-" + createHash("sha384").update(readFileSync(path.join(out, url))).digest("base64");
      expect(t).toContain(`integrity="${want}"`);
      expect(t).toContain('crossorigin="anonymous"');
    }
  });

  it("the output is index.html and hashed static assets under /assets/, nothing else", () => {
    const rel = files.map((f) => path.relative(out, f).split(path.sep).join("/"));
    expect(rel.filter((r) => !r.startsWith("assets/"))).toEqual(["index.html"]);
    for (const r of rel.filter((r) => r.startsWith("assets/"))) expect(r).toMatch(/^assets\/[\w.-]+-[\w-]{8}\.(js|css|woff2)$/);
    /* no source maps ship */
    for (const f of files.filter((p) => /\.(js|css)$/.test(p))) expect(readFileSync(f, "utf8")).not.toMatch(/sourceMappingURL/);
  });

  it("references no external host: no CDN script, stylesheet or font", () => {
    /* inert strings only: XML namespaces, links inside error messages, a license banner, JSON Schema dialect ids */
    const allowed = [
      "http://www.w3.org/",
      "https://react.dev/errors/",
      "https://react.i18next.com/",
      "https://tailwindcss.com",
      "http://json-schema.org/",
      "https://json-schema.org/",
    ];
    const isAllowed = (u: string) => allowed.some((a) => u.startsWith(a) && (a.endsWith("/") || u.length === a.length || "/:?#".includes(u[a.length])));
    /* zod's IPv6 check parses `http://[${address}]` with URL: exactly that template literal */
    const zodIPv6 = /^http:\/\/\[\$\{[\w$]+\}\]$/;
    const offenders: string[] = [];
    for (const f of files) {
      if (/\.woff2$/.test(f)) continue;
      const text = readFileSync(f, "utf8");
      for (const m of text.matchAll(/(?:https?|wss?):\/\/[^\s"'`)\\<>]+/g)) {
        const i = m.index;
        if (zodIPv6.test(m[0]) && text[i - 1] === "`" && text[i + m[0].length] === "`") continue;
        if (!isAllowed(m[0])) offenders.push(`${path.relative(out, f)}: ${m[0]}`);
      }
      for (const m of text.matchAll(/(?<=["'`(])\/\/[\w-]+(?:\.[\w-]+)+/g)) offenders.push(`${path.relative(out, f)}: ${m[0]}`);
    }
    expect(offenders).toEqual([]);
    /* every CSS url() is a local file */
    for (const f of files.filter((p) => p.endsWith(".css"))) {
      for (const m of readFileSync(f, "utf8").matchAll(/url\(([^)]*)\)/g)) expect(m[1].replace(/["']/g, "")).toMatch(/^(\.\/|\/assets\/)?[\w.-]+\.woff2$/);
    }
  });

  it("fonts are bundled locally", () => {
    expect(files.some((f) => /inter.*\.woff2$/i.test(f))).toBe(true);
  });

  it("creates no <style> at runtime and ships none of the libraries that do", () => {
    /*
     * React DOM keeps one createElement("style") for <style precedence> resources, a path we never use; anything more
     * means a library that injects styles on use (react-remove-scroll, input-otp, Cytoscape, react-draggable, ...).
     */
    let styleElements = 0;
    for (const f of files.filter((p) => p.endsWith(".js"))) {
      const text = readFileSync(f, "utf8");
      styleElements += text.match(/createElement\((?:`style`|"style"|'style')\)/g)?.length ?? 0;
      expect(text, path.basename(f)).not.toMatch(/insertRule|__webpack_nonce__|data-scroll-locked|adoptedStyleSheets|<style/);
    }
    expect(styleElements).toBeLessThanOrEqual(1);
  });

  it("has no eval, new Function or other dynamic code, no blob/worker/wasm", () => {
    /* Bare Function() is eval too. Known inert shapes only: zod's CSP probe Function(``) (never reached: zod runs jitless) and the global-object fallback. */
    const knownFunction = /(?<![\w$.])Function\((?:``|`return this`)\)/g;
    for (const f of files.filter((p) => p.endsWith(".js"))) {
      const text = readFileSync(f, "utf8");
      expect(text, path.basename(f)).not.toMatch(/\bnew Function\s*\(|[^\w.$]eval\s*\(|createObjectURL|importScripts\s*\(|new Worker\(|new SharedWorker\(|WebAssembly|wasm-unsafe-eval|\bimport\s*\(\s*[^`"'\s)]/);
      expect(text.replace(knownFunction, "").match(/(?<![\w$.])Function\s*\(.{0,40}/g) ?? [], path.basename(f)).toEqual([]);
    }
  });
});
