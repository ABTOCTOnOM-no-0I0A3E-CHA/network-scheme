/* The two origins of one installation, as the gateway publishes them at /origins.json on both of them. */
export type Origins = { panel: string; executor: string };

/** True for exactly `https://host[:port]`: no path, query, fragment, credentials or trailing slash. */
export function isHttpsOrigin(s: unknown): s is string {
  if (typeof s !== "string" || s.length > 255) return false;
  try {
    const u = new URL(s);
    return u.protocol === "https:" && u.origin === s;
  } catch {
    return false;
  }
}

/** Validates a parsed origins.json: exactly the keys panel and executor, two different https origins. */
export function parseOrigins(doc: unknown): Origins {
  const d = doc as Record<string, unknown> | null;
  if (typeof d !== "object" || d === null || Array.isArray(d)) throw new Error("origins.json: unsupported document");
  const keys = Object.keys(d).sort();
  if (keys.length !== 2 || keys[0] !== "executor" || keys[1] !== "panel") throw new Error("origins.json: unexpected fields");
  const { panel, executor } = d;
  if (!isHttpsOrigin(panel) || !isHttpsOrigin(executor)) throw new Error("origins.json: not an https origin");
  if (panel === executor) throw new Error("origins.json: the executor must be a separate origin");
  return { panel, executor };
}

/** Loads the origins from the origin this page was served from, bypassing the HTTP cache. */
export async function loadOrigins(): Promise<Origins> {
  const r = await fetch("/origins.json", { cache: "no-store", credentials: "omit" });
  if (!r.ok) throw new Error(`origins.json: http ${r.status}`);
  return parseOrigins(await r.json());
}
