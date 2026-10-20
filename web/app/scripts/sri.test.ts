// @vitest-environment node
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { addSri } from "./sri";

const JS = "console.log('hi');\n";
const CSS = "body{margin:0}\n";
const sha384 = (s: string) => "sha384-" + createHash("sha384").update(s).digest("base64");

function fixture(html: string) {
  const dir = mkdtempSync(path.join(tmpdir(), "sri-"));
  mkdirSync(path.join(dir, "assets"));
  writeFileSync(path.join(dir, "assets", "app.js"), JS);
  writeFileSync(path.join(dir, "assets", "app.css"), CSS);
  writeFileSync(path.join(dir, "index.html"), html);
  return dir;
}

describe("addSri", () => {
  it("adds sha384 integrity and crossorigin to scripts, stylesheets and modulepreload", () => {
    const dir = fixture(
      `<!doctype html><html><head>
<script type="module" crossorigin src="/assets/app.js"></script>
<link rel="modulepreload" crossorigin href="/assets/app.js">
<link rel="stylesheet" crossorigin href="/assets/app.css">
<link rel="icon" href="/favicon.svg">
</head><body></body></html>`,
    );
    addSri(dir);
    const out = readFileSync(path.join(dir, "index.html"), "utf8");
    expect(out).toContain(`src="/assets/app.js" integrity="${sha384(JS)}" crossorigin="anonymous"`);
    expect(out).toContain(`href="/assets/app.css" integrity="${sha384(CSS)}" crossorigin="anonymous"`);
    expect(out.match(/integrity=/g)).toHaveLength(3);
    expect(out.match(/crossorigin/g)).toHaveLength(3);
    expect(out).toContain(`<link rel="icon" href="/favicon.svg">`);
  });

  it("is idempotent", () => {
    const dir = fixture(`<script type="module" src="/assets/app.js"></script>`);
    addSri(dir);
    const once = readFileSync(path.join(dir, "index.html"), "utf8");
    addSri(dir);
    expect(readFileSync(path.join(dir, "index.html"), "utf8")).toBe(once);
  });

  it("rejects external and traversing URLs", () => {
    expect(() => addSri(fixture(`<script src="https://cdn.example/x.js"></script>`))).toThrow();
    expect(() => addSri(fixture(`<script src="/../../etc/passwd"></script>`))).toThrow();
  });

  it("fails when the referenced file is missing", () => {
    expect(() => addSri(fixture(`<script src="/assets/missing.js"></script>`))).toThrow();
  });
});
