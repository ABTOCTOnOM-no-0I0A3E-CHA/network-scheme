import { useState, type FormEvent } from "react";
import { Dialog } from "radix-ui";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { useCreateTrapRule, type EventSeverity } from "./api";
import { SEVERITIES } from "./EventFilters";

/** Server limit of a rule name, in bytes of UTF-8. */
const MAX_NAME_BYTES = 1024;
const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

type Props = {
  /** OID to name; the dialog is closed while undefined. */
  oid: string | undefined;
  onOpenChange: (open: boolean) => void;
};

/** Names a trap OID and sets its severity. */
export function TrapRuleDialog({ oid, onOpenChange }: Props) {
  return (
    <Dialog.Root open={oid !== undefined} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 grid max-h-[90vh] w-full max-w-md -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-lg border bg-background p-6 shadow-lg">
          {/* mounted only while open, so the form starts fresh every time */}
          {oid !== undefined && <RuleForm oid={oid} onClose={() => onOpenChange(false)} />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function RuleForm({ oid, onClose }: { oid: string; onClose: () => void }) {
  const { t } = useTranslation();
  const create = useCreateTrapRule();
  const [error, setError] = useState<string | undefined>();

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(undefined);
    const fd = new FormData(e.currentTarget);
    const name = String(fd.get("name") ?? "").trim();
    if (!name) return setError(t("events.rule.required"));
    if (new TextEncoder().encode(name).length > MAX_NAME_BYTES) return setError(t("events.rule.tooLong", { max: MAX_NAME_BYTES }));
    try {
      await create.mutateAsync({ trap_oid: oid, name, severity: String(fd.get("severity")) as EventSeverity });
      onClose();
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      if (err instanceof ApiError) return setError(t(errorKey({ error: { code: err.code } })));
      setError(t(thrownKey(err)));
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="grid gap-4" noValidate>
      <Dialog.Title className="text-lg font-semibold">{t("events.rule.title")}</Dialog.Title>
      <Dialog.Description className="text-sm text-muted-foreground">{t("events.rule.description")}</Dialog.Description>
      <div className="grid gap-2">
        <Label htmlFor="rule-oid">{t("events.rule.oid")}</Label>
        <Input id="rule-oid" readOnly value={safeText(oid)} className="font-mono text-xs" />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="rule-name">{t("events.rule.name")}</Label>
        <Input id="rule-name" name="name" autoComplete="off" autoFocus />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="rule-severity">{t("events.rule.severity")}</Label>
        <select id="rule-severity" name="severity" className={SELECT_CLASS} defaultValue="warning">
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {t(`events.severity.${s}`)}
            </option>
          ))}
        </select>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onClose}>
          {t("stepup.cancel")}
        </Button>
        <Button type="submit" disabled={create.isPending}>
          {t("events.rule.create")}
        </Button>
      </div>
    </form>
  );
}
