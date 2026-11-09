import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@nms/shared/ui/card";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { Terminal } from "../session/Terminal";
import { eventText, listAnswer, messageOf, replayAnswer, type Item, type Replay } from "./api";

/* Longest pause between two events while playing (a session idles for minutes). */
const MAX_PAUSE_MS = 2000;

/*
 * Session recordings (Task 4c.5): the list of a device's or a session's recordings and the player. Every list and every
 * replay costs one change TOTP code (grant audit-read; the executor audits each view). The player is the read-only line
 * terminal: the executor verified the recording and cleaned every event; it is rendered as text only.
 */
export function RecordingsPage({ poster }: { poster: Poster }) {
  const { t } = useTranslation();
  const [device, setDevice] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [items, setItems] = useState<Item[] | null>(null);
  const [replay, setReplay] = useState<Replay | null>(null);
  const [shown, setShown] = useState(0);
  const [playing, setPlaying] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const active = playing && !!replay && shown < replay.events.length;
  /* plays the next event after the recorded pause (bounded) */
  useEffect(() => {
    if (!active || !replay) return;
    const prev = shown > 0 ? replay.events[shown - 1].t : 0;
    const wait = Math.min(Math.max(replay.events[shown].t - prev, 0) * 1000, MAX_PAUSE_MS);
    const id = window.setTimeout(() => setShown((n) => n + 1), wait);
    return () => window.clearTimeout(id);
  }, [active, replay, shown]);

  const takeCode = () => {
    const c = code;
    setCode(""); /* sent once, never again */
    setMsg(null);
    setBusy(true);
    return c;
  };

  const load = async () => {
    if (!/^\d{6}$/.test(code) || !/^\d{1,18}$/.test(device)) return;
    const r = await poster.post("/x/recordings", { code: takeCode(), params: { device_id: Number(device) } }, listAnswer);
    if (!alive.current) return;
    setBusy(false);
    if (r.ok) setItems(r.value.result);
    else setMsg(messageOf(r.failure));
  };

  const play = async (it: Item) => {
    if (!/^\d{6}$/.test(code)) return;
    setReplay(null);
    setPlaying(false);
    const r = await poster.post("/x/recordings/replay", { code: takeCode(), params: { session_id: it.session_id, device_id: it.device_id } }, replayAnswer);
    if (!alive.current) return;
    setBusy(false);
    if (!r.ok) {
      setMsg(messageOf(r.failure));
      return;
    }
    setReplay(r.value.result);
    setShown(0);
    setPlaying(true);
  };

  const output = replay ? replay.events.slice(0, shown).map(eventText).join("") : "";
  const codeOk = /^\d{6}$/.test(code);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("executor.recordings.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p>{t("executor.recordings.cost")}</p>
        <div className="flex flex-wrap gap-3">
          <label className="block">
            {t("executor.recordings.device")}
            <input className="block w-32 rounded border px-2 py-1" name="rec-device" inputMode="numeric" maxLength={18} autoComplete="off"
              value={device} onChange={(e) => setDevice(e.target.value)} />
          </label>
          <label className="block">
            {t("executor.confirm.code")}
            <input className="block w-32 rounded border px-2 py-1" name="rec-code" inputMode="numeric" maxLength={6} autoComplete="off"
              value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
        </div>
        <Button type="button" disabled={busy || !codeOk || !/^\d{1,18}$/.test(device)} onClick={() => void load()}>
          {t("executor.recordings.load")}
        </Button>
        {msg && (
          <p role="alert" className="text-destructive" data-testid="failure">
            {t(msg.key, msg.params)}
          </p>
        )}
        {items && items.length === 0 && <p>{t("executor.recordings.empty")}</p>}
        {items && items.length > 0 && (
          <ul className="space-y-1">
            {items.map((it) => (
              <li key={`${it.session_id}/${it.device_id}`} className="flex items-center gap-2" data-testid={`recording-${it.session_id}`}>
                <span className="font-mono text-xs">{it.session_id}</span>
                <span>{t("executor.recordings.row", { opened: it.opened_at, user: it.user_id })}</span>
                <span>{t(`executor.recordings.state.${it.state}`)}</span>
                <Button type="button" size="sm" variant="outline" disabled={busy || !codeOk || it.state !== "complete"} onClick={() => void play(it)}>
                  {t("executor.recordings.play")}
                </Button>
              </li>
            ))}
          </ul>
        )}
        {replay && (
          <div className="space-y-2" data-testid="player">
            <p>{replay.title}</p>
            <Terminal output={output} readOnly onKeys={() => {}} onPaste={() => {}} />
            <div className="flex gap-2">
              <Button type="button" size="sm" variant="outline" disabled={shown >= replay.events.length} onClick={() => setPlaying((p) => !p)}>
                {t(active ? "executor.recordings.pause" : "executor.recordings.resume")}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => {
                setPlaying(false);
                setShown(replay.events.length);
              }}>
                {t("executor.recordings.all")}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
