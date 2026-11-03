import { x25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { fingerprint, parseReadKey } from "./keys";

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const { publicKey } = x25519.keygen();
const doc = (over: Record<string, unknown> = {}) => ({ version: 1, domains: { read: { key_version: 1, public_key: b64(publicKey), fingerprint: fingerprint(publicKey), ...over } } });

describe("parseReadKey", () => {
  it("returns the read domain of a valid keys.json", () => {
    const k = parseReadKey(doc());
    expect(k.keyVersion).toBe(1);
    expect(k.publicKey).toEqual(publicKey);
    expect(k.fingerprint).toMatch(/^([0-9a-f]{4}:){7}[0-9a-f]{4}$/);
  });

  it.each([
    ["no document", null],
    ["another version", { ...doc(), version: 2 }],
    ["a key that does not match its fingerprint", doc({ fingerprint: "0000:0000:0000:0000:0000:0000:0000:0000" })],
    ["a short key", doc({ public_key: b64(publicKey.subarray(0, 31)) })],
    ["a zero key version", doc({ key_version: 0 })],
    ["a fractional key version", doc({ key_version: 1.5 })],
  ])("refuses %s", (_n, d) => {
    expect(() => parseReadKey(d)).toThrow();
  });
});
