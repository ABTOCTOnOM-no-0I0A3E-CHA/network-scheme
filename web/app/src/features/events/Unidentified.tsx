import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey } from "@/features/auth/errors";
import { ApiError } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { useUnidentified, type UnidentifiedTrap } from "./api";
import { VarbindList } from "./EventFeed";
import { PRESETS, resolveWindow, type Preset } from "./EventFilters";
import { TrapRuleDialog } from "./TrapRuleDialog";
import { TrapRules } from "./TrapRules";

const NO_ROWS: UnidentifiedTrap[] = [];
const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

/* a custom period is not offered here: the presets are enough to find a trap worth naming */
const UNIDENTIFIED_PRESETS = PRESETS.filter((p) => p !== "custom");

/** Traps nobody could name, grouped by OID; users with events.manage can name them. Device data is rendered as text. */
export function Unidentified({ canManage }: { canManage: boolean }) {
  const { t, i18n } = useTranslation();
  const [preset, setPreset] = useState<Preset>("7d");
  const [anchor, setAnchor] = useState(() => Date.now());
  const [rule, setRule] = useState<string | undefined>();
  const [open, setOpen] = useState<string | undefined>();

  const w = useMemo(() => resolveWindow({ preset, customFrom: "", customTo: "" }, anchor), [preset, anchor]);
  const from = "from" in w ? w.from : new Date(anchor).toISOString();
  const q = useUnidentified(from);
  const rows = useMemo(() => q.data?.pages.flatMap((p) => p.items) ?? NO_ROWS, [q.data]);
  const loadError = q.error instanceof ApiError ? t(errorKey({ error: { code: q.error.code } })) : q.error ? t("errors.unknown") : undefined;

  return (
    <section className="grid gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <select
          aria-label={t("events.filter.period")}
          className={SELECT_CLASS}
          value={preset}
          onChange={(e) => {
            setPreset(e.target.value as Preset);
            setAnchor(Date.now());
          }}
        >
          {UNIDENTIFIED_PRESETS.map((p) => (
            <option key={p} value={p}>
              {t(`events.period.${p}`)}
            </option>
          ))}
        </select>
        <Button type="button" variant="outline" size="sm" onClick={() => setAnchor(Date.now())}>
          {t("events.refresh")}
        </Button>
      </div>
      {loadError && (
        <p role="alert" className="text-sm text-destructive">
          {loadError}
        </p>
      )}
      {q.isPending && <p className="text-sm text-muted-foreground">{t("events.loading")}</p>}
      {!q.isPending && !loadError && rows.length === 0 && <p className="text-sm text-muted-foreground">{t("events.unidentifiedEmpty")}</p>}
      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full min-w-[40rem] text-sm" aria-label={t("events.unidentifiedTable")}>
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">{t("events.rule.oid")}</th>
                <th className="px-3 py-2 font-medium">{t("events.col.count")}</th>
                <th className="px-3 py-2 font-medium">{t("events.col.lastSeen")}</th>
                <th className="px-3 py-2 font-medium">{t("events.col.device")}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <UnidentifiedRow
                  key={r.trap_oid}
                  r={r}
                  expanded={open === r.trap_oid}
                  onToggle={() => setOpen(open === r.trap_oid ? undefined : r.trap_oid)}
                  onCreate={canManage ? () => setRule(r.trap_oid) : undefined}
                  locale={i18n.language}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.hasNextPage && (
        <Button type="button" variant="outline" size="sm" className="w-fit" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
          {t("events.loadMore")}
        </Button>
      )}
      {canManage && <TrapRules />}
      {canManage && <TrapRuleDialog oid={rule} onOpenChange={(o) => !o && setRule(undefined)} />}
    </section>
  );
}

function UnidentifiedRow({ r, expanded, onToggle, onCreate, locale }: { r: UnidentifiedTrap; expanded: boolean; onToggle: () => void; onCreate?: () => void; locale: string }) {
  const { t } = useTranslation();
  const oid = safeText(r.trap_oid);
  return (
    <>
      <tr className="border-t">
        <td className="max-w-[24rem] px-3 py-2 font-mono text-xs break-all">{oid}</td>
        <td className="px-3 py-2 tabular-nums">{r.count}</td>
        <td className="px-3 py-2 text-xs tabular-nums">{new Date(r.last_ts).toLocaleString(locale)}</td>
        <td className="max-w-[12rem] truncate px-3 py-2" title={safeText(r.last_device_name)}>
          {safeText(r.last_device_name)}
        </td>
        <td className="flex gap-2 px-3 py-2">
          <Button type="button" variant="ghost" size="sm" aria-expanded={expanded} aria-label={t("events.varbindsOf", { oid })} onClick={onToggle}>
            {t("events.varbinds")}
          </Button>
          {onCreate && (
            <Button type="button" size="sm" aria-label={t("events.rule.createFor", { oid })} onClick={onCreate}>
              {t("events.rule.create")}
            </Button>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="border-t bg-muted/30">
          <td colSpan={5} className="px-4 py-3">
            <VarbindList raw={r.last_varbinds} omitted={r.last_varbinds_omitted} />
          </td>
        </tr>
      )}
    </>
  );
}
