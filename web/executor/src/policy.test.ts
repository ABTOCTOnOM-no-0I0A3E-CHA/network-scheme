// @vitest-environment node
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const web = path.resolve(__dirname, "../..");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    if (statSync(p).isDirectory()) return n === "node_modules" || n === "dist" ? [] : sources(p);
    return /\.(ts|tsx)$/.test(n) && !/\.d\.ts$/.test(n) ? [p] : [];
  });
}
const code = (dir: string) => sources(path.join(web, dir, "src")).filter((f) => !/\.test\.tsx?$/.test(f));
const read = (f: string) => readFileSync(f, "utf8");

describe("source policy", () => {
  it("dangerouslySetInnerHTML appears in no source of web/app, web/executor or web/shared (device data is rendered as text)", () => {
    const offenders = ["app", "executor", "shared"].flatMap((d) => sources(path.join(web, d, "src"))).filter((f) => !f.endsWith("policy.test.ts") && /dangerouslySetInnerHTML/.test(read(f)));
    expect(offenders).toEqual([]);
  });

  it("every fetch of the executor bundle and of the shared package is cookie-less (credentials: 'omit')", () => {
    const withFetch = [...code("executor"), ...code("shared")].filter((f) => /\bfetch\s*\(/.test(read(f)));
    expect(withFetch.map((f) => path.basename(f)).sort()).toEqual(["client.ts", "keys.ts", "origins.ts"]);
    for (const f of withFetch) {
      /* client.ts spells the options once, in the base every request merges */
      expect(read(f), f).toMatch(/credentials:\s*"omit"/);
      expect(read(f), f).not.toMatch(/credentials:\s*"(include|same-origin)"/);
    }
  });

  it("the executor bundle opens no other channel: no XHR, beacon, EventSource, service worker or storage of tickets", () => {
    for (const f of code("executor")) {
      expect(read(f), f).not.toMatch(/XMLHttpRequest|sendBeacon|EventSource|serviceWorker|localStorage|sessionStorage|document\.cookie|indexedDB/);
    }
  });

  it("postMessage is called in exactly one place, the shared channel, which always names the peer origin", () => {
    const panelSide = sources(path.join(web, "app/src/features/executor")).filter((f) => !/\.test\.tsx?$/.test(f));
    const calls = [...code("executor"), ...code("shared"), ...panelSide].filter((f) => /\.postMessage\(/.test(read(f)));
    expect(calls.map((f) => path.relative(web, f).split(path.sep).join("/"))).toEqual(["shared/src/bridge.ts"]);
    expect(read(path.join(web, "shared/src/bridge.ts"))).not.toMatch(/postMessage\([^)]*["']\*["']/);
  });
});
