/*
 * Regenerates internal/creds/testdata/browser_sealed_vector.json with the web app's
 * sealCredential (run: bun scripts/gen-seal-vector.ts). The key pair is a fresh
 * TEST-ONLY pair; the Go test TestBrowserSealedVector opens every case.
 */
import { writeFileSync } from "node:fs";
import path from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { buildPayload, sealCredential, type CredKind, type SecretOf } from "../src/lib/seal";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const { secretKey, publicKey } = x25519.keygen();
const now = new Date("2026-10-20T10:00:00Z");

const cases: { [K in CredKind]: SecretOf[K] } = {
  snmp2c: { community: "community-0123456789" },
  snmp3: { user: "monitor", auth_proto: "SHA256", auth_key: "auth-key-0123456789", priv_proto: "AES", priv_key: "priv-key-0123456789" },
  ssh_read: { username: "admin-\u00e9", password: 'pa55 w0rd "q" 12\u2603' },
};

const out = {
  comment: "TEST-ONLY keys. Sealed by web/app/src/lib/seal.ts sealCredential; regenerate with bun scripts/gen-seal-vector.ts.",
  private_key: hex(secretKey),
  public_key: hex(publicKey),
  owner: "device:7",
  cases: (Object.keys(cases) as CredKind[]).map((kind) => ({
    kind,
    ciphertext: hex(sealCredential(publicKey, buildPayload("device:7", kind, cases[kind] as never, now))),
  })),
};

writeFileSync(path.resolve(import.meta.dirname, "../../../internal/creds/testdata/browser_sealed_vector.json"), JSON.stringify(out, null, 2) + "\n");
