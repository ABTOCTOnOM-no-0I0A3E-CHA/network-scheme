import { fingerprint } from "@nms/shared/keys";
import { buildPayload, sealCredential, toBase64, validateSecret, type CredentialPayload, type SecretSSH } from "@nms/shared/seal";

/** The write-domain public key from the executor origin's keys.json. */
export type WriteKey = { keyVersion: number; publicKey: Uint8Array; fingerprint: string };

const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Validates a parsed keys.json and returns its write domain; throws on anything unexpected. */
export function parseWriteKey(doc: unknown): WriteKey {
  const d = doc as { version?: unknown; domains?: { write?: { key_version?: unknown; public_key?: unknown; fingerprint?: unknown } } } | null;
  const w = d?.domains?.write;
  if (d?.version !== 1 || !w) throw new Error("keys.json: unsupported document");
  const { key_version: kv, public_key: pk, fingerprint: fp } = w;
  if (typeof kv !== "number" || !Number.isInteger(kv) || kv < 1 || typeof pk !== "string" || typeof fp !== "string") throw new Error("keys.json: bad write key");
  const publicKey = unb64(pk);
  if (publicKey.length !== 32 || fingerprint(publicKey) !== fp) throw new Error("keys.json: key does not match its fingerprint");
  return { keyVersion: kv, publicKey, fingerprint: fp };
}

/** The rules of internal/creds for a login secret (ssh_write takes the ssh_read form); null when acceptable. */
export const checkWriteSecret = (s: SecretSSH) => validateSecret("ssh_read", s);

/**
 * Seals {v, owner "device:<id>", kind "ssh_write", created_at, nonce, secret} to the write-domain key and returns the
 * ciphertext as base64. The secret lives only in this call and the caller's form state; nothing is stored.
 */
export function sealWriteCredential(key: WriteKey, deviceId: number, secret: SecretSSH, now: Date = new Date()): string {
  if (!Number.isSafeInteger(deviceId) || deviceId <= 0) throw new Error("bad device id");
  /* the shared envelope types know only the read kinds: the shape is the same, the kind is ssh_write */
  const payload = { ...buildPayload(`device:${deviceId}`, "ssh_read", secret, now), kind: "ssh_write" } as unknown as CredentialPayload;
  return toBase64(sealCredential(key.publicKey, payload));
}
