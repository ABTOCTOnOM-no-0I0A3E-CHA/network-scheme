import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Poster } from "../client";
import { ConfirmPanel, type ShownField } from "../ConfirmPanel";
import type { Message } from "../errors";
import { Alert, Dialog } from "../session/Dialog";
import { APPROVE, approvedAnswer, challengeSchema, messageOf, type Challenge, type Detail, type Workspace } from "./api";
import { when } from "./parts";

/*
 * The approval of a changeset (Task 5.4, FR-CHG-10): the executor describes it (confirm(H) over the author, revision,
 * plan_sha256 of the dry-run, groups, canary, batch, settle and title), every field is shown with H, and the user types
 * the number of devices the changeset changes (not in H; a wrong number is refused and the challenge is spent) and the
 * NEXT change TOTP code. A group of two persons: the author approves first and waits; another user with write on every
 * group sees who authored it and what, and approves with their own code: the run starts then. The author never
 * approves twice (same_person). A spent code is never resent (the poster refuses it).
 */
export function ApproveDialog({ poster, detail, me, onClose, onDone }: { poster: Poster; detail: Detail; me: Workspace; onClose: () => void; onDone: (status: string, until?: string) => void }) {
  const { t, i18n } = useTranslation();
  const [c, setC] = useState<Challenge | null>(null);
  const [count, setCount] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const author = me.user_id === detail.author_id;

  const issue = async () => {
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/confirm/issue", { action: APPROVE, params: { changeset_id: detail.changeset_id } }, challengeSchema);
    setBusy(false);
    if (!r.ok) return setMsg(messageOf(r.failure));
    const f = Object.fromEntries(r.value.fields.map((x) => [x.key, x.value]));
    if (f.changeset !== detail.changeset_id || f.revision !== String(detail.revision)) return setMsg({ key: "executor.changesets.approve.mismatch" });
    setC(r.value);
  };

  const confirm = async (code: string) => {
    if (!c || !/^\d{1,3}$/.test(count)) return;
    setMsg(null);
    setBusy(true);
    const r = await poster.post(`/x/changesets/${detail.changeset_id}/approve/${Number(count)}`, { challenge_id: c.challenge_id, h: c.h, code }, approvedAnswer);
    setBusy(false);
    setCount("");
    if (r.ok) return onDone(r.value.result.status, r.value.result.second_person_until);
    const f = r.failure;
    setMsg(messageOf(f));
    /* refused (the device count too), or the executor failed: the challenge may be spent, start again */
    if (f.kind === "http" && (f.status === 422 || f.status >= 500 || f.code === "denied")) setC(null);
  };

  const label = (k: string) => (i18n.exists(`executor.changesets.field.${k}`) ? t(`executor.changesets.field.${k}`) : k);
  const fields: ShownField[] = c ? c.fields.map((f) => ({ key: f.key, label: label(f.key), value: f.value })) : [];
  const role = (
    <div className={`rounded-lg border px-3 py-2.5 ${author ? "bg-muted/40" : "border-violet-500/50 bg-violet-500/10"}`} data-testid="approve-role">
      {author ? (
        <p>{t("executor.changesets.approve.asAuthor")}</p>
      ) : (
        <>
          <p className="text-base font-semibold">{t("executor.changesets.approve.asSecond", { author: detail.author, id: detail.author_id })}</p>
          <p className="mt-1 text-xs">{t("executor.changesets.approve.secondExplain")}</p>
        </>
      )}
    </div>
  );

  return (
    <Dialog title={t(author ? "executor.changesets.approve.title" : "executor.changesets.approve.titleSecond")} wide busy={busy} onClose={onClose} testId="approve-dialog">
      {!c && (
        <>
          {role}
          <p>{t("executor.changesets.approve.explain")}</p>
          <div className="flex gap-2">
            <Button type="button" disabled={busy} onClick={() => void issue()} data-testid="approve-issue">
              {t("executor.changesets.approve.issue")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {t("executor.confirm.cancel")}
            </Button>
          </div>
        </>
      )}
      {c && (
        <ConfirmPanel title={t("executor.changesets.approve.confirmTitle")} fields={fields} h={c.h} busy={busy} extraReady={/^\d{1,3}$/.test(count)}
          confirmLabel={t(author ? "executor.changesets.approve.confirm" : "executor.changesets.approve.confirmSecond")} onConfirm={(code) => void confirm(code)} onCancel={onClose}
          lead={role}>
          <label className="block font-medium">
            {t("executor.changesets.approve.count")}
            <input className="mt-1 block h-9 w-24 rounded-md border bg-background px-3 font-mono text-base outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
              id="cs-count" name="cs-count" inputMode="numeric" maxLength={3} autoComplete="off" value={count} onChange={(e) => setCount(e.target.value)} />
            <span className="mt-1 block text-xs font-normal text-muted-foreground">{t("executor.changesets.approve.countHint")}</span>
          </label>
          <p className="text-xs text-muted-foreground">{t("executor.changesets.approve.expires", { at: when(c.expires) })}</p>
        </ConfirmPanel>
      )}
      {msg && <Alert testId="approve-failure">{t(msg.key, msg.params)}</Alert>}
    </Dialog>
  );
}
