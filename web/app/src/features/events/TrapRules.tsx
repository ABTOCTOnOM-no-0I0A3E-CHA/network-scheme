import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { useDeleteTrapRule, useTrapRules } from "./api";

/** Trap rules with delete (events.manage); collapsed until asked for. A deletion needs a second click. */
export function TrapRules() {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState<number | undefined>();
  const [error, setError] = useState<string | undefined>();
  const rules = useTrapRules(open);
  const del = useDeleteTrapRule();

  const remove = async (id: number) => {
    setError(undefined);
    try {
      await del.mutateAsync(id);
      setConfirm(undefined);
    } catch (err) {
      setConfirm(undefined);
      if (err instanceof StepUpCancelled) return;
      setError(t(err instanceof ApiError ? errorKey({ error: { code: err.code } }) : thrownKey(err)));
    }
  };
  const loadError = rules.error instanceof ApiError ? t(errorKey({ error: { code: rules.error.code } })) : rules.error ? t("errors.unknown") : undefined;
  const message = error ?? loadError;

  return (
    <div className="grid gap-3">
      <Button type="button" variant="outline" size="sm" className="w-fit" aria-expanded={open} onClick={() => setOpen(!open)}>
        {t("events.rules.title")}
      </Button>
      {open && (
        <div className="grid gap-2">
          {message && (
            <p role="alert" className="text-sm text-destructive">
              {message}
            </p>
          )}
          {rules.isPending && <p className="text-sm text-muted-foreground">{t("events.loading")}</p>}
          {rules.data?.length === 0 && <p className="text-sm text-muted-foreground">{t("events.rules.empty")}</p>}
          {rules.data && rules.data.length > 0 && (
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full min-w-[40rem] text-sm" aria-label={t("events.rules.title")}>
                <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 font-medium">{t("events.rule.oid")}</th>
                    <th className="px-3 py-2 font-medium">{t("events.rule.name")}</th>
                    <th className="px-3 py-2 font-medium">{t("events.rule.severity")}</th>
                    <th className="px-3 py-2 font-medium">{t("events.rules.created")}</th>
                    <th className="px-3 py-2" />
                  </tr>
                </thead>
                <tbody>
                  {rules.data.map((r) => (
                    <tr key={r.id} className="border-t">
                      <td className="max-w-[20rem] px-3 py-2 font-mono text-xs break-all">{safeText(r.trap_oid)}</td>
                      <td className="max-w-[16rem] px-3 py-2 break-words">{safeText(r.name)}</td>
                      <td className="px-3 py-2">{t(`events.severity.${r.severity}`)}</td>
                      <td className="px-3 py-2 text-xs tabular-nums">{new Date(r.created_at).toLocaleString(i18n.language)}</td>
                      <td className="px-3 py-2">
                        {confirm === r.id ? (
                          <span className="flex gap-2">
                            <Button type="button" size="sm" variant="destructive" disabled={del.isPending} onClick={() => void remove(r.id)}>
                              {t("events.rules.confirm")}
                            </Button>
                            <Button type="button" size="sm" variant="outline" onClick={() => setConfirm(undefined)}>
                              {t("stepup.cancel")}
                            </Button>
                          </span>
                        ) : (
                          <Button type="button" size="sm" variant="outline" aria-label={t("events.rules.deleteFor", { oid: safeText(r.trap_oid) })} onClick={() => setConfirm(r.id)}>
                            {t("events.rules.delete")}
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
