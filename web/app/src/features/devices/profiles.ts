import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";
import type { CredKind, Owner } from "@/lib/seal";
import { deviceKeys } from "./api";

export type Profile = components["schemas"]["Profile"];

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

export const profileKeys = { device: (id: number) => ["devices", "profiles", id] as const };

/** Which read credentials of a device are set (status and date only; content is never returned). */
export function useProfiles(deviceId: number) {
  return useQuery({
    queryKey: profileKeys.device(deviceId),
    queryFn: async () => unwrap(await api.GET("/api/devices/{id}/profiles", { params: { path: { id: deviceId } } })),
  });
}

/** What the mutation carries: ciphertext only, never plaintext (mutation variables are cached). */
export type SealedProfile = { kind: CredKind; ciphertext: string; keyVersion: number };

/**
 * Stores a sealed credential for `owner` (step-up). A device owner uses
 * PUT /api/devices/{id}/profiles/{kind}; a scan owner uses PUT /api/discovery/scans/{id}/profile
 * (snmp2c and snmp3 only).
 */
export function useSaveProfile(owner: Owner) {
  const qc = useQueryClient();
  const [ownerKind, idStr] = owner.split(":") as ["device" | "scan", string];
  const id = Number(idStr);
  return useMutation({
    mutationFn: ({ kind, ciphertext, keyVersion }: SealedProfile) =>
      withStepUp(async () => {
        const body = { ciphertext, key_version: keyVersion };
        if (ownerKind === "device") {
          unwrap(await api.PUT("/api/devices/{id}/profiles/{kind}", { params: { path: { id, kind }, ...CSRF }, body }));
        } else {
          if (kind === "ssh_read") throw new Error("scan profiles are SNMP only");
          unwrap(await api.PUT("/api/discovery/scans/{id}/profile", { params: { path: { id }, ...CSRF }, body: { ...body, kind } }));
        }
      }),
    /* profile queries live under ["devices"]; scan lists under ["discovery"] */
    onSettled: () => Promise.all([qc.invalidateQueries({ queryKey: deviceKeys.all }), qc.invalidateQueries({ queryKey: ["discovery"] })]),
  });
}
