import { hsalsa, xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { blake2b } from "@noble/hashes/blake2.js";

/*
 * crypto_box_seal (libsodium) in pure JS: no WebAssembly, so the panel CSP needs no
 * wasm-unsafe-eval. Output = epk(32) || secretbox(msg), nonce = BLAKE2b-24(epk || pk),
 * box key = HSalsa20(X25519(esk, pk), 0^16). Randomness: crypto.getRandomValues only.
 */

export type Owner = `device:${number}` | `scan:${number}`;
export type CredKind = "snmp2c" | "snmp3" | "ssh_read";

export type Secret2c = { community: string };
export type SecretV3 = { user: string; auth_proto: string; auth_key: string; priv_proto: string; priv_key: string };
export type SecretSSH = { username: string; password?: string; private_key?: string };
export type SecretOf = { snmp2c: Secret2c; snmp3: SecretV3; ssh_read: SecretSSH };

/** Plaintext envelope sealed to the read-domain key; the exact shape `internal/creds` accepts. */
export type CredentialPayload = {
  v: 1;
  owner: Owner;
  kind: CredKind;
  created_at: string;
  nonce: string;
  secret: SecretOf[CredKind];
};

export const AUTH_PROTOS = ["SHA224", "SHA256", "SHA384", "SHA512"] as const;
export const PRIV_PROTOS = ["AES", "AES256"] as const;

/* limits of internal/creds */
const MAX_FIELD = 2048;
const MAX_PRIVATE_KEY = 6 << 10;
const MAX_USERNAME = 64;
const MAX_SNMP_USER = 32;
const MIN_SNMP_SECRET = 16;
const MIN_PASSWORD = 12;
const MAX_PLAINTEXT = 8 << 10;

/** Reasons a secret is refused before sealing; the form maps them to `profile.err.*`. */
export type SecretProblem = "required" | "control" | "too_long" | "weak_snmp" | "weak_password" | "bad_proto" | "both_or_neither" | "bad_pem";

const enc = new TextEncoder();
const bytes = (s: string) => enc.encode(s).length;
/* C0 controls and DEL; PEM may additionally contain line breaks */
const hasControl = (s: string, allowNL = false) =>
  [...s].some((c) => {
    const n = c.charCodeAt(0);
    return (n < 0x20 && !(allowNL && (n === 0x0a || n === 0x0d))) || n === 0x7f;
  });
const chars = (s: string) => [...s].length;

function str(s: string | undefined, limit: number): SecretProblem | null {
  if (!s) return "required";
  if (bytes(s) > limit) return "too_long";
  return hasControl(s) ? "control" : null;
}

/**
 * Checks a secret against the rules of `internal/creds`; returns the offending field
 * and the problem, or null. Mirrors the server so a refusal happens before sealing.
 */
export function validateSecret<K extends CredKind>(kind: K, s: SecretOf[K]): { field: string; problem: SecretProblem } | null {
  const bad = (field: string, problem: SecretProblem | null) => (problem ? { field, problem } : null);
  const snmpKey = (v: string) => str(v, MAX_FIELD) ?? (chars(v) < MIN_SNMP_SECRET ? "weak_snmp" : null);
  if (kind === "snmp2c") return bad("community", snmpKey((s as Secret2c).community));
  if (kind === "snmp3") {
    const v = s as SecretV3;
    if (!(AUTH_PROTOS as readonly string[]).includes(v.auth_proto)) return { field: "auth_proto", problem: "bad_proto" };
    if (!(PRIV_PROTOS as readonly string[]).includes(v.priv_proto)) return { field: "priv_proto", problem: "bad_proto" };
    return bad("user", str(v.user, MAX_SNMP_USER)) ?? bad("auth_key", snmpKey(v.auth_key)) ?? bad("priv_key", snmpKey(v.priv_key));
  }
  const l = s as SecretSSH;
  const nameP = bad("username", str(l.username, MAX_USERNAME));
  if (nameP) return nameP;
  const hasPw = !!l.password;
  const hasKey = !!l.private_key;
  if (hasPw === hasKey) return { field: "password", problem: "both_or_neither" };
  if (hasPw) return bad("password", str(l.password, MAX_FIELD) ?? (chars(l.password!) < MIN_PASSWORD ? "weak_password" : null));
  const k = l.private_key!;
  if (bytes(k) > MAX_PRIVATE_KEY) return { field: "private_key", problem: "too_long" };
  if (hasControl(k, true)) return { field: "private_key", problem: "control" };
  return /^\s*-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*-----END [A-Z ]*PRIVATE KEY-----\s*$/.test(k) ? null : { field: "private_key", problem: "bad_pem" };
}

/** Standard base64 of bytes (the API's `ciphertext` encoding). */
export const toBase64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

/**
 * Builds the envelope: v=1, canonical owner, `created_at` as RFC 3339 UTC without
 * fractional seconds and a 16-byte nonce from crypto.getRandomValues.
 */
export function buildPayload<K extends CredKind>(owner: Owner, kind: K, secret: SecretOf[K], now: Date = new Date()): CredentialPayload {
  return {
    v: 1,
    owner,
    kind,
    created_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
    nonce: toBase64(crypto.getRandomValues(new Uint8Array(16))),
    secret,
  };
}

const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]); /* "expand 32-byte k" */

function u32le(b: Uint8Array): Uint32Array {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return Uint32Array.from({ length: b.length / 4 }, (_, i) => v.getUint32(i * 4, true));
}

function fromU32le(w: Uint32Array): Uint8Array {
  const out = new Uint8Array(w.length * 4);
  const v = new DataView(out.buffer);
  w.forEach((x, i) => v.setUint32(i * 4, x, true));
  return out;
}

/* crypto_box_beforenm: HSalsa20 of the X25519 shared secret with a zero nonce prefix */
function boxKey(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secretKey, publicKey);
  const k = u32le(shared);
  const out = new Uint32Array(8);
  hsalsa(SIGMA, k, new Uint32Array(4), out);
  shared.fill(0);
  k.fill(0);
  const key = fromU32le(out);
  out.fill(0);
  return key;
}

const sealNonce = (epk: Uint8Array, pk: Uint8Array) => blake2b(new Uint8Array([...epk, ...pk]), { dkLen: 24 });

/**
 * Seals the payload to the 32-byte read-domain public key `pub` (libsodium
 * crypto_box_seal). The serialized plaintext is zeroed before returning; the JS
 * strings of the payload itself cannot be wiped and are left to the garbage collector.
 */
export function sealCredential(pub: Uint8Array, payload: CredentialPayload): Uint8Array {
  if (pub.length !== 32) throw new Error("bad public key");
  const problem = validateSecret(payload.kind, payload.secret as never);
  if (problem) throw new Error(`invalid credential: ${problem.field}`);
  const plaintext = enc.encode(JSON.stringify(payload));
  const esk = crypto.getRandomValues(new Uint8Array(32));
  let key: Uint8Array | undefined;
  try {
    if (plaintext.length > MAX_PLAINTEXT) throw new Error("credential too large");
    const epk = x25519.getPublicKey(esk);
    key = boxKey(esk, pub);
    const sealed = xsalsa20poly1305(key, sealNonce(epk, pub)).encrypt(plaintext);
    const out = new Uint8Array(32 + sealed.length);
    out.set(epk, 0);
    out.set(sealed, 32);
    return out;
  } finally {
    plaintext.fill(0);
    esk.fill(0);
    key?.fill(0);
  }
}

/**
 * Opens a sealed box with the key pair (crypto_box_seal_open). For tests and tools
 * only; the panel never holds a private key.
 */
export function openSealed(pub: Uint8Array, priv: Uint8Array, ct: Uint8Array): Uint8Array {
  const epk = ct.subarray(0, 32);
  const key = boxKey(priv, epk);
  try {
    return xsalsa20poly1305(key, sealNonce(epk, pub)).decrypt(ct.subarray(32));
  } finally {
    key.fill(0);
  }
}

const KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"; /* no look-alikes: 57 symbols */

/** Random SNMPv3 key of 24 characters from crypto.getRandomValues (rejection sampling, no modulo bias). */
export function generateKey(length = 24): string {
  const limit = 256 - (256 % KEY_ALPHABET.length);
  let out = "";
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(length))) {
      if (b < limit && out.length < length) out += KEY_ALPHABET[b % KEY_ALPHABET.length];
    }
  }
  return out;
}
