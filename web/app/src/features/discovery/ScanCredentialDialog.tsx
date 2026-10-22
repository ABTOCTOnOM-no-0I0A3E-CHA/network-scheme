import { useState } from "react";
import { Dialog } from "radix-ui";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ProfileForm } from "@/features/devices/ProfileForm";
import type { CredKind } from "@/lib/seal";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
const KINDS: CredKind[] = ["snmp2c", "snmp3"];

type Props = { scanId: number | undefined; onClose: () => void };

/** Sets the one SNMP credential a scan probes with; open while `scanId` is set. */
export function ScanCredentialDialog({ scanId, onClose }: Props) {
  const { t } = useTranslation();
  const [kind, setKind] = useState<CredKind>("snmp2c");
  return (
    <Dialog.Root open={scanId !== undefined} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 grid max-h-[90vh] w-full max-w-md -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-lg border bg-background p-6 shadow-lg">
          <Dialog.Title className="text-lg font-semibold">{t("scan.cred.title")}</Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground">{t("scan.cred.description")}</Dialog.Description>
          {scanId !== undefined && (
            <>
              <div className="grid gap-2">
                <Label htmlFor="scan-cred-kind">{t("devices.addDialog.kind")}</Label>
                <select id="scan-cred-kind" className={SELECT_CLASS} value={kind} onChange={(e) => setKind(e.target.value as CredKind)}>
                  {KINDS.map((k) => (
                    <option key={k} value={k}>
                      {t(`profile.title.${k}`)}
                    </option>
                  ))}
                </select>
              </div>
              {/* keyed by scan and kind so neither switch carries typed secrets over */}
              <ProfileForm key={`${scanId}-${kind}`} owner={`scan:${scanId}`} kind={kind} onSaved={onClose} />
            </>
          )}
          <Button type="button" variant="outline" onClick={onClose}>
            {t("scan.cred.later")}
          </Button>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
