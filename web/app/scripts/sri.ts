import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const TAG = /<(script|link)\b[^>]*>/gi;

function attr(tag: string, name: string): string | undefined {
  return new RegExp(`\\s${name}="([^"]*)"`, "i").exec(tag)?.[1];
}

/**
 * Adds `integrity="sha384-..."` and `crossorigin="anonymous"` to every
 * `<script src>` and `<link rel=stylesheet|modulepreload>` in `<dir>/index.html`.
 * Only same-origin absolute paths inside `dir` are accepted. Idempotent.
 */
export function addSri(dir: string): void {
  const file = path.join(dir, "index.html");
  const root = path.resolve(dir);
  const html = readFileSync(file, "utf8").replace(TAG, (tag, name: string) => {
    const isScript = name.toLowerCase() === "script";
    const rel = attr(tag, "rel")?.toLowerCase();
    if (!isScript && rel !== "stylesheet" && rel !== "modulepreload") return tag;
    const url = attr(tag, isScript ? "src" : "href");
    if (url === undefined) return tag;
    if (!url.startsWith("/") || url.startsWith("//")) throw new Error(`sri: non-local URL ${url}`);
    const target = path.resolve(root, "." + url.split(/[?#]/)[0]);
    if (target !== root && !target.startsWith(root + path.sep)) throw new Error(`sri: path escapes dist: ${url}`);
    const digest = createHash("sha384").update(readFileSync(target)).digest("base64");
    const clean = tag
      .replace(/\sintegrity="[^"]*"/gi, "")
      .replace(/\scrossorigin(="[^"]*")?/gi, "")
      .replace(/\s*\/?>$/, "");
    return `${clean} integrity="sha384-${digest}" crossorigin="anonymous">`;
  });
  writeFileSync(file, html);
}

if (import.meta.main) {
  const dir = process.argv[2];
  if (!dir) throw new Error("usage: bun scripts/sri.ts <dist-dir>");
  addSri(dir);
}
