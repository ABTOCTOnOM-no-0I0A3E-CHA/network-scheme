import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { Alert } from "../session/Dialog";
import { listAnswer, messageOf, op, openedAnswer, workspaceGone, type ChangesetPreset, type Detail as D, type Item, type Workspace } from "./api";
import { Detail } from "./Detail";
import { Editor } from "./Editor";
import { codeInput, section, StatusBadge, when } from "./parts";

type View =
  | { kind: "list" }
  | { kind: "detail"; id: string }
  | { kind: "new"; type: "lines" | "restore"; restore?: { device: number; version: number }[] }
  | { kind: "edit"; detail: D };

/*
 * «Изменения» (Task 5.8): the changeset workspace. Opening it costs one change TOTP code (ticket + code: a bearer
 * token kept in this component's memory only, idle and lifetime from the policy); then the list, a changeset, the
 * editor. The panel may preselect a changeset or a restore (prefill only). Everything the executor says is text.
 */
export function ChangesetsPage({ poster, preset, onRecordings }: { poster: Poster; preset: ChangesetPreset; onRecordings: (session: string, device: number) => void }) {
  const { t } = useTranslation();
  const [ws, setWs] = useState<Workspace | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [view, setView] = useState<View>(() =>
    preset.changeset ? { kind: "detail", id: preset.changeset } : preset.restore ? { kind: "new", type: "restore", restore: [preset.restore] } : { kind: "list" },
  );
  const [items, setItems] = useState<Item[] | null>(null);

  const gone = useCallback(() => {
    setWs(null);
    setItems(null);
    setMsg({ key: "executor.changesets.refused.no_workspace" });
  }, []);

  const open = async () => {
    if (!/^\d{6}$/.test(code)) return;
    const c = code;
    setCode(""); /* sent once, never again */
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/changesets/open", { totp: c }, openedAnswer);
    setBusy(false);
    if (r.ok) setWs(r.value.result);
    else setMsg(messageOf(r.failure));
  };

  const token = ws?.token;
  const load = useCallback(() => {
    if (!token) return;
    void op(token, "list", {}, listAnswer).then((r) => {
      if (r.ok) return setItems(r.value.result);
      if (workspaceGone(r.failure)) return gone();
      setMsg(messageOf(r.failure));
    });
  }, [token, gone]);
  useEffect(() => {
    if (view.kind === "list") load();
  }, [view.kind, load]);

  if (!ws) {
    return (
      <section className={`${section} mx-auto max-w-xl`} data-testid="cs-open">
        <h2 className="text-base font-semibold">{t("executor.changesets.title")}</h2>
        <p className="text-sm text-muted-foreground">{t("executor.changesets.openExplain")}</p>
        {(preset.changeset || preset.restore) && <Alert tone="warn">{t(preset.changeset ? "executor.changesets.presetChangeset" : "executor.changesets.presetRestore")}</Alert>}
        <label className="block text-sm font-medium">
          {t("executor.confirm.code")}
          <input className={codeInput} id="cs-code" name="cs-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void open()} />
        </label>
        <Button type="button" disabled={busy || !/^\d{6}$/.test(code)} onClick={() => void open()}>
          {t("executor.changesets.open")}
        </Button>
        {msg && <Alert testId="failure">{t(msg.key, msg.params)}</Alert>}
      </section>
    );
  }

  if (view.kind === "detail") {
    return (
      <Detail key={view.id} poster={poster} token={ws.token} me={ws} id={view.id} onBack={() => setView({ kind: "list" })} onGone={gone} onRecordings={onRecordings}
        onEdit={(d) => setView({ kind: "edit", detail: d })} onRestore={(restore) => setView({ kind: "new", type: "restore", restore })} />
    );
  }
  if (view.kind === "new" || view.kind === "edit") {
    const kind = view.kind === "edit" ? view.detail.kind : view.type;
    return (
      <Editor token={ws.token} kind={kind} initial={view.kind === "edit" ? view.detail : undefined} restore={view.kind === "new" ? view.restore : undefined} onGone={gone}
        onSaved={(id) => setView({ kind: "detail", id })} onCancel={() => setView(view.kind === "edit" ? { kind: "detail", id: view.detail.changeset_id } : { kind: "list" })} />
    );
  }

  return (
    <div className="space-y-4" data-testid="cs-list">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="mr-auto text-base font-semibold">{t("executor.changesets.title")}</h2>
        <span className="text-xs text-muted-foreground">{t("executor.changesets.signedAs", { user: ws.username, until: when(ws.expires) })}</span>
        <Button type="button" variant="ghost" size="sm" onClick={load}>
          {t("executor.changesets.refresh")}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => setView({ kind: "new", type: "restore" })} data-testid="cs-new-restore">
          {t("executor.changesets.newRestore")}
        </Button>
        <Button type="button" size="sm" onClick={() => setView({ kind: "new", type: "lines" })} data-testid="cs-new">
          {t("executor.changesets.new")}
        </Button>
      </div>
      {msg && <Alert>{t(msg.key, msg.params)}</Alert>}
      {items === null && <p className="text-sm text-muted-foreground">{t("executor.changesets.loading")}</p>}
      {items && items.length === 0 && (
        <div className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground" data-testid="cs-empty">
          {t("executor.changesets.empty")}
        </div>
      )}
      {items && items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/40 text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">{t("executor.changesets.col.title")}</th>
                <th className="px-3 py-2 font-medium">{t("executor.changesets.col.status")}</th>
                <th className="px-3 py-2 font-medium">{t("executor.changesets.col.kind")}</th>
                <th className="px-3 py-2 text-right font-medium">{t("executor.changesets.col.devices")}</th>
                <th className="px-3 py-2 font-medium">{t("executor.changesets.col.author")}</th>
                <th className="px-3 py-2 font-medium">{t("executor.changesets.col.updated")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.changeset_id} className="cursor-pointer border-b last:border-0 hover:bg-muted/40" data-testid={`cs-row-${it.changeset_id}`}
                  onClick={() => setView({ kind: "detail", id: it.changeset_id })}>
                  <td className="max-w-md px-3 py-2">
                    <button type="button" className="block max-w-full truncate text-left font-medium hover:underline" onClick={() => setView({ kind: "detail", id: it.changeset_id })}>
                      {it.title}
                    </button>
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {it.changeset_id.slice(0, 8)} · r{it.revision}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge status={it.status} />
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{t(`executor.changesets.kind.${it.kind}`)}</td>
                  <td className="px-3 py-2 text-right font-mono">{it.device_count}</td>
                  <td className="px-3 py-2">
                    {it.author}
                    {it.author_id === ws.user_id && <span className="ml-1 text-xs text-muted-foreground">({t("executor.changesets.you")})</span>}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap text-muted-foreground">{when(it.updated)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
