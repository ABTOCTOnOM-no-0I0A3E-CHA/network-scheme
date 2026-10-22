import { useQuery } from "@tanstack/react-query";
import { sha256 } from "@noble/hashes/sha2.js";

/** The read-domain public key from /keys.json. */
export type ReadKey = { keyVersion: number; publicKey: Uint8Array; fingerprint: string };

const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** First 16 bytes of SHA-256(pub) as hex in groups of four (as internal/keys.Fingerprint). */
export function fingerprint(pub: Uint8Array): string {
  const hex = [...sha256(pub).subarray(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return (hex.match(/.{4}/g) ?? []).join(":");
}

/** Validates a parsed keys.json and returns its read domain; throws on anything unexpected. */
export function parseReadKey(doc: unknown): ReadKey {
  const d = doc as { version?: unknown; domains?: { read?: { key_version?: unknown; public_key?: unknown; fingerprint?: unknown } } } | null;
  const r = d?.domains?.read;
  if (d?.version !== 1 || !r) throw new Error("keys.json: unsupported document");
  const { key_version: kv, public_key: pk, fingerprint: fp } = r;
  if (typeof kv !== "number" || !Number.isInteger(kv) || kv < 1 || typeof pk !== "string" || typeof fp !== "string") throw new Error("keys.json: bad read key");
  const publicKey = unb64(pk);
  if (publicKey.length !== 32 || fingerprint(publicKey) !== fp) throw new Error("keys.json: key does not match its fingerprint");
  return { keyVersion: kv, publicKey, fingerprint: fp };
}

/** Loads the current read key, bypassing the HTTP cache. */
export async function loadReadKey(): Promise<ReadKey> {
  const r = await fetch("/keys.json", { cache: "no-store", credentials: "omit" });
  if (!r.ok) throw new Error(`keys.json: http ${r.status}`);
  return parseReadKey(await r.json());
}

export const readKeyQueryKey = ["keys", "read"] as const;

/** Read key as a query (public data, safe to cache); invalidate it on `stale_key`. */
export function useReadKey() {
  return useQuery({ queryKey: readKeyQueryKey, queryFn: loadReadKey, staleTime: 5 * 60_000 });
}
