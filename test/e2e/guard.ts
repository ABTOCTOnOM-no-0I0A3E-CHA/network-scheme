import { test as base, expect, type BrowserContext } from "@playwright/test";

/** The only origin the panel may talk to (NFR-NET-1: no CDN, fonts or telemetry). */
export const ORIGIN = "https://localhost";

/**
 * Records CSP violations (console messages and `securitypolicyviolation`
 * events) and requests to anything but ORIGIN on every page of a context.
 */
export async function watch(context: BrowserContext): Promise<{ problems: string[] }> {
  const problems: string[] = [];
  await context.exposeBinding("__nmsCspViolation", (_src, v: string) => {
    problems.push(`securitypolicyviolation: ${v}`);
  });
  await context.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      (window as unknown as { __nmsCspViolation: (v: string) => void }).__nmsCspViolation(
        `${e.violatedDirective} blocked=${e.blockedURI} at ${e.sourceFile}:${e.lineNumber}`,
      );
    });
  });
  context.on("console", (m) => {
    if (m.text().includes("Content Security Policy")) problems.push(`console: ${m.text()}`);
  });
  context.on("request", (r) => {
    const url = r.url();
    if (url !== ORIGIN && !url.startsWith(`${ORIGIN}/`) && !url.startsWith("data:")) problems.push(`external request: ${url}`);
  });
  return { problems };
}

/** `test` whose default context is watched; a test fails on any recorded problem. */
export const test = base.extend({
  context: async ({ context }, use) => {
    const w = await watch(context);
    await use(context);
    expect(w.problems, "CSP violations / external requests").toEqual([]);
  },
});

export { expect };
