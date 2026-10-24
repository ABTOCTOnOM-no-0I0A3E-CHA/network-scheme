import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorKey } from "@/features/auth/errors";
import { ApiError } from "@/features/common/stepup";
import { safeLines } from "@/lib/text";
import { cn } from "@/lib/utils";
import { useBackups, useBackupState, useBackupVersion } from "./backups";
import { splitSections, type SectionKey } from "./sections";

/* error text of a failed query, never the server's message */
export function queryError(t: (k: string) => string, e: unknown): string {
  return t(e instanceof ApiError ? errorKey({ error: { code: e.code } }) : "errors.unknown");
}

/** "Конфиг" tab: read-only tree of the sections of a masked configuration version; the equivalent commands are the section's lines. */
export function ConfigTab({ deviceId }: { deviceId: number }) {
  const { t, i18n } = useTranslation();
  const state = useBackupState(deviceId);
  const versions = useBackups(deviceId);
  const list = useMemo(() => versions.data?.pages.flatMap((p) => p.items) ?? [], [versions.data]);
  const [picked, setPicked] = useState<number | undefined>();
  const vid = picked ?? list[0]?.id;
  const version = useBackupVersion(deviceId, vid);
  const sections = useMemo(() => (version.data ? splitSections(version.data.text) : []), [version.data]);
  const [section, setSection] = useState<SectionKey | undefined>();
  const current = sections.find((s) => s.name === section) ?? sections[0];

  if (state.data?.needs_write) return <NeedsWrite />;
  if (versions.isPending) return <p className="text-sm text-muted-foreground">{t("card.loading")}</p>;
  if (versions.error)
    return (
      <p role="alert" className="text-sm text-destructive">
        {queryError(t, versions.error)}
      </p>
    );
  if (list.length === 0) return <p className="text-sm text-muted-foreground">{t("backup.none")}</p>;

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="grid gap-1 text-xs text-muted-foreground">
          {t("config.version")}
          <select
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm text-foreground dark:bg-input/30"
            value={vid}
            onChange={(e) => {
              setPicked(Number(e.target.value));
              setSection(undefined);
            }}
          >
            {list.map((v) => (
              <option key={v.id} value={v.id}>
                {new Date(v.taken_at).toLocaleString(i18n.language)} · {v.sha256}
              </option>
            ))}
          </select>
        </label>
        <p className="text-xs text-muted-foreground">{t("config.readOnly")}</p>
      </div>
      {version.error && (
        <p role="alert" className="text-sm text-destructive">
          {queryError(t, version.error)}
        </p>
      )}
      {version.isPending ? (
        <p className="text-sm text-muted-foreground">{t("card.loading")}</p>
      ) : sections.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("config.empty")}</p>
      ) : (
        <div className="grid gap-3 md:grid-cols-[14rem_1fr]">
          <nav aria-label={t("config.sections")}>
            <ul role="tree" className="grid gap-1">
              {sections.map((s) => (
                <li key={s.name} role="treeitem" aria-selected={current?.name === s.name}>
                  <button
                    type="button"
                    className={cn("flex w-full justify-between rounded-md px-3 py-1.5 text-left text-sm", current?.name === s.name ? "bg-muted font-medium" : "hover:bg-muted/60")}
                    onClick={() => setSection(s.name)}
                  >
                    <span>{t(`config.section.${s.name}`)}</span>
                    <span className="text-xs text-muted-foreground tabular-nums">{s.lines.length}</span>
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          {current && (
            <section className="grid min-w-0 content-start gap-1">
              <h3 className="text-sm font-medium">{t("config.commands", { section: t(`config.section.${current.name}`) })}</h3>
              <pre data-testid="config-lines" className="max-h-[65vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre">
                {safeLines(current.lines.join("\n"))}
              </pre>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

/** The model needs a write account to read its configuration: no backups before phase 4. */
export function NeedsWrite() {
  const { t } = useTranslation();
  return (
    <p role="status" className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
      {t("backup.needsWrite")}
    </p>
  );
}
