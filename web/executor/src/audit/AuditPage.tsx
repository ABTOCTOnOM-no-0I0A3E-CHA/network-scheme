import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@nms/shared/ui/card";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { EMPTY, RESULTS, messageOf, pageAnswer, params, type Filters, type Page } from "./api";

/*
 * The executor's audit chain (Task 4d.2), read only: filters, one page per change TOTP code (grant audit-read; the
 * executor audits every view), the next page by the executor's cursor. Every cell is text: the executor cleaned what
 * a device or a client wrote, and nothing is rendered as markup.
 */
export function AuditPage({ poster }: { poster: Poster }) {
  const { t } = useTranslation();
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [page, setPage] = useState<Page | null>(null);
  /* the filters of the shown page: the next page continues those, not what is typed since */
  const [shownWith, setShownWith] = useState<Filters>(EMPTY);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const read = async (f: Filters, before: number) => {
    const p = params(f, before);
    if (!/^\d{6}$/.test(code) || !p) return setMsg(p ? null : { key: "executor.audit.badFilter" });
    const c = code;
    setCode(""); /* sent once, never again */
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/audit", { code: c, params: p }, pageAnswer);
    if (!alive.current) return;
    setBusy(false);
    if (!r.ok) return setMsg(messageOf(r.failure));
    setPage(r.value.result);
    setShownWith(f);
  };

  const set = (k: keyof Filters) => (e: { target: { value: string } }) => setFilters((f) => ({ ...f, [k]: e.target.value }));
  const field = "mt-1 block h-9 rounded-md border bg-background px-3 font-normal outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";
  const codeOk = /^\d{6}$/.test(code);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("executor.audit.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">{t("executor.audit.cost")}</p>
        <div className="flex flex-wrap gap-3">
          <label className="block font-medium">
            {t("executor.audit.from")}
            <input className={`${field} w-52`} type="datetime-local" name="aud-from" autoComplete="off" value={filters.from} onChange={set("from")} />
          </label>
          <label className="block font-medium">
            {t("executor.audit.to")}
            <input className={`${field} w-52`} type="datetime-local" name="aud-to" autoComplete="off" value={filters.to} onChange={set("to")} />
          </label>
          <label className="block font-medium">
            {t("executor.audit.user")}
            <input className={`${field} w-28`} name="aud-user" inputMode="numeric" maxLength={18} autoComplete="off" value={filters.user} onChange={set("user")} />
          </label>
          <label className="block font-medium">
            {t("executor.audit.action")}
            <input className={`${field} w-48`} name="aud-action" maxLength={65} autoComplete="off" value={filters.action} onChange={set("action")} />
          </label>
          <label className="block font-medium">
            {t("executor.audit.device")}
            <input className={`${field} w-28`} name="aud-device" inputMode="numeric" maxLength={18} autoComplete="off" value={filters.device} onChange={set("device")} />
          </label>
          <label className="block font-medium">
            {t("executor.audit.result")}
            <select className={`${field} w-32`} name="aud-result" value={filters.result} onChange={set("result")}>
              <option value="">{t("executor.audit.any")}</option>
              {RESULTS.map((r) => (
                <option key={r} value={r}>
                  {t(`executor.audit.results.${r}`)}
                </option>
              ))}
            </select>
          </label>
          <label className="block font-medium">
            {t("executor.confirm.code")}
            <input className={`${field} w-36`} name="aud-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="button" disabled={busy || !codeOk} onClick={() => void read(filters, 0)}>
            {t("executor.audit.load")}
          </Button>
          {page && page.next > 0 && (
            <Button type="button" variant="outline" disabled={busy || !codeOk} onClick={() => void read(shownWith, page.next)}>
              {t("executor.audit.more")}
            </Button>
          )}
        </div>
        {msg && (
          <p role="alert" className="text-destructive" data-testid="failure">
            {t(msg.key, msg.params)}
          </p>
        )}
        {page && page.rows.length === 0 && <p>{t("executor.audit.empty")}</p>}
        {page && page.rows.length > 0 && (
          <div className="overflow-auto">
            <table className="w-full border-collapse text-xs" data-testid="audit-table">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  {["id", "ts", "user", "action", "object", "result", "ip", "details"].map((k) => (
                    <th key={k} className="px-2 py-1 font-medium">
                      {t(`executor.audit.col.${k}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {page.rows.map((r) => (
                  <tr key={r.id} className="border-b align-top" data-testid={`audit-${r.id}`}>
                    <td className="px-2 py-1 font-mono">{r.id}</td>
                    <td className="px-2 py-1 whitespace-nowrap">{r.ts}</td>
                    <td className="px-2 py-1">{r.user_id ?? t("executor.audit.host")}</td>
                    <td className="px-2 py-1 font-mono">{r.action}</td>
                    <td className="px-2 py-1 font-mono break-all">{r.object}</td>
                    <td className="px-2 py-1">{t(`executor.audit.results.${r.result}`)}</td>
                    <td className="px-2 py-1 font-mono">{r.ip}</td>
                    <td className="px-2 py-1 font-mono break-all whitespace-pre-wrap">{r.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
