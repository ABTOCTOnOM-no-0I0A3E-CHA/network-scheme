import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import { AUTH_PROTOS, buildPayload, generateKey, openSealed, sealCredential, validateSecret } from "./seal";

const fixture = (name: string) => JSON.parse(readFileSync(path.resolve(__dirname, "../../../../internal/creds/testdata", name), "utf8"));
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const dec = new TextDecoder();
const v3 = { user: "monitor", auth_proto: "SHA256", auth_key: "auth-key-0123456789", priv_proto: "AES", priv_key: "priv-key-0123456789" };

describe("sealed box", () => {
  it("opens the libsodium reference vector", () => {
    const f = fixture("libsodium_vector.json");
    const pt = JSON.parse(dec.decode(openSealed(unhex(f.public_key), unhex(f.private_key), unhex(f.ciphertext))));
    expect(pt).toMatchObject({ v: 1, owner: "device:42", kind: "snmp3", created_at: "2026-10-20T10:00:00Z" });
    expect(pt.secret).toMatchObject({ user: "monitor", auth_key: "auth-key-0123456789", priv_key: "priv-key-0123456789" });
  });

  it("opens what Go-compatible libsodium layout requires: sealCredential round-trips", () => {
    const { secretKey, publicKey } = x25519.keygen();
    const payload = buildPayload("scan:3", "snmp3", v3);
    const ct = sealCredential(publicKey, payload);
    expect(ct.length).toBe(32 + 16 + new TextEncoder().encode(JSON.stringify(payload)).length);
    expect(JSON.parse(dec.decode(openSealed(publicKey, secretKey, ct)))).toEqual(payload);
  });

  it("opens the committed browser-sealed fixture (also opened by the Go test)", () => {
    const f = fixture("browser_sealed_vector.json");
    for (const c of f.cases) {
      const pt = JSON.parse(dec.decode(openSealed(unhex(f.public_key), unhex(f.private_key), unhex(c.ciphertext))));
      expect(pt).toMatchObject({ v: 1, owner: f.owner, kind: c.kind, created_at: "2026-10-20T10:00:00Z" });
    }
  });

  it("uses a fresh ephemeral key each time and rejects tampering and the wrong key", () => {
    const a = x25519.keygen();
    const p = buildPayload("device:1", "snmp2c", { community: "community-0123456789" });
    const c1 = sealCredential(a.publicKey, p);
    const c2 = sealCredential(a.publicKey, p);
    expect(c1.subarray(0, 32)).not.toEqual(c2.subarray(0, 32));
    const t = c1.slice();
    t[t.length - 1] ^= 1;
    expect(() => openSealed(a.publicKey, a.secretKey, t)).toThrow();
    const b = x25519.keygen();
    expect(() => openSealed(b.publicKey, b.secretKey, c1)).toThrow();
  });

  it("takes all randomness from crypto.getRandomValues", () => {
    const spy = vi.spyOn(crypto, "getRandomValues");
    const { publicKey } = x25519.keygen();
    spy.mockClear();
    sealCredential(publicKey, buildPayload("device:1", "snmp2c", { community: "community-0123456789" }));
    expect(spy.mock.calls.map((c) => (c[0] as Uint8Array).length)).toEqual(expect.arrayContaining([16, 32]));
    spy.mockRestore();
  });

  it("refuses an invalid secret instead of sealing it", () => {
    const { publicKey } = x25519.keygen();
    expect(() => sealCredential(publicKey, buildPayload("device:1", "snmp2c", { community: "short" }))).toThrow();
  });
});

describe("payload", () => {
  it("has the exact envelope: no fractional seconds, 16-byte nonce", () => {
    const p = buildPayload("device:5", "snmp2c", { community: "community-0123456789" }, new Date("2026-10-21T01:02:03.456Z"));
    expect(Object.keys(p).sort()).toEqual(["created_at", "kind", "nonce", "owner", "secret", "v"]);
    expect(p).toMatchObject({ v: 1, owner: "device:5", kind: "snmp2c", created_at: "2026-10-21T01:02:03Z" });
    expect(atob(p.nonce).length).toBe(16);
    expect(buildPayload("device:5", "snmp2c", { community: "community-0123456789" }).nonce).not.toBe(p.nonce);
  });
});

describe("validateSecret", () => {
  const k16 = "0123456789abcdef";
  it.each([
    ["short community", "snmp2c", { community: "a".repeat(15) }, "weak_snmp"],
    ["control char", "snmp2c", { community: k16 + "\n" }, "control"],
    ["DEL", "snmp2c", { community: k16 + "\x7f" }, "control"],
    ["MD5", "snmp3", { ...v3, auth_proto: "MD5" }, "bad_proto"],
    ["SHA1", "snmp3", { ...v3, auth_proto: "SHA" }, "bad_proto"],
    ["DES", "snmp3", { ...v3, priv_proto: "DES" }, "bad_proto"],
    ["short auth key", "snmp3", { ...v3, auth_key: "x".repeat(15) }, "weak_snmp"],
    ["long user", "snmp3", { ...v3, user: "u".repeat(33) }, "too_long"],
    ["no ssh credential", "ssh_read", { username: "u" }, "both_or_neither"],
    ["both ssh credentials", "ssh_read", { username: "u", password: "twelve-chars", private_key: "k" }, "both_or_neither"],
    ["short ssh password", "ssh_read", { username: "u", password: "eleven-char" }, "weak_password"],
    ["not a pem", "ssh_read", { username: "u", private_key: "hello" }, "bad_pem"],
    ["username control", "ssh_read", { username: "u\r\nconfigure", password: "twelve-chars" }, "control"],
  ] as const)("%s", (_n, kind, secret, problem) => {
    expect(validateSecret(kind, secret as never)?.problem).toBe(problem);
  });

  it("accepts valid secrets, counting characters (not bytes) for minimums", () => {
    expect(validateSecret("snmp2c", { community: "я".repeat(16) })).toBeNull();
    for (const a of AUTH_PROTOS) expect(validateSecret("snmp3", { ...v3, auth_proto: a })).toBeNull();
    expect(validateSecret("ssh_read", { username: "u", password: "twelve-chars" })).toBeNull();
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    expect(validateSecret("ssh_read", { username: "u", private_key: pem })).toBeNull();
  });
});

describe("generateKey", () => {
  it("makes 24 distinct characters of the safe alphabet", () => {
    const keys = new Set(Array.from({ length: 50 }, () => generateKey()));
    expect(keys.size).toBe(50);
    for (const k of keys) expect(k).toMatch(/^[A-Za-z0-9]{24}$/);
  });
});
