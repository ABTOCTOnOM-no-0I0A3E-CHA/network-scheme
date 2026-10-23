import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import alertUrl from "@/assets/alert.wav";
import { meQuery } from "@/features/auth/useSession";
import { problemKeys, type EventSeverity, type ProblemSummary } from "@/features/problems/api";
import { loadSettings, parseMessage, ProblemSocket, saveSettings, shouldNotify, type NotifySettings } from "./feed";

const MAX_ITEMS = 20;
/* close code of the server for a lost session or revoked scope */
const POLICY_CLOSE = 1008;

/** Plays the bundled beep; a browser that blocks autoplay rejects play(), which is ignored. */
export function playAlert(): void {
  try {
    void new Audio(alertUrl).play()?.catch(() => undefined);
  } catch {
    /* no audio support */
  }
}

function sendSubscribe(socket: ProblemSocket, severityMin: EventSeverity): void {
  socket.send(JSON.stringify({ type: "subscribe", severity_min: severityMin }));
}

export type FeedItem = { key: number; problem: ProblemSummary };

type Options = { enabled: boolean; play?: () => void };

/**
 * Subscribes to /api/ws while `enabled`: every message refreshes the problem queries; newly opened,
 * unsuppressed problems matching the stored preferences raise the unread badge and, if enabled, play the sound.
 */
export function useProblemFeed({ enabled, play = playAlert }: Options) {
  const qc = useQueryClient();
  const [settings, setSettingsState] = useState<NotifySettings>(loadSettings);
  const [items, setItems] = useState<FeedItem[]>([]);
  const [unread, setUnread] = useState(0);
  const settingsRef = useRef(settings);
  const playRef = useRef(play);
  const seq = useRef(0);
  const socketRef = useRef<ProblemSocket | undefined>(undefined);

  useEffect(() => {
    settingsRef.current = settings;
    playRef.current = play;
  });

  useEffect(() => {
    if (!enabled) return;
    const socket = new ProblemSocket({
      onOpen: (reconnect) => {
        sendSubscribe(socket, settingsRef.current.severityMin);
        if (reconnect) void qc.invalidateQueries({ queryKey: problemKeys.all });
      },
      onClose: (code) => {
        /* the session may be gone: refetching /me turns a 401 into the login redirect */
        if (code === POLICY_CLOSE) void qc.invalidateQueries({ queryKey: meQuery.queryKey });
      },
      onMessage: (data) => {
        const m = parseMessage(data);
        if (!m) return;
        void qc.invalidateQueries({ queryKey: problemKeys.all });
        const s = settingsRef.current;
        if (!shouldNotify(m, s)) return;
        setItems((l) => [{ key: ++seq.current, problem: m.problem }, ...l].slice(0, MAX_ITEMS));
        setUnread((n) => n + 1);
        if (s.sound) playRef.current();
      },
    });
    socketRef.current = socket;
    socket.start();
    return () => {
      socketRef.current = undefined;
      socket.stop();
    };
  }, [enabled, qc]);

  /* the server filters by severity before queueing; tell it again when the preference changes */
  useEffect(() => {
    if (socketRef.current) sendSubscribe(socketRef.current, settings.severityMin);
  }, [settings.severityMin]);

  const setSettings = useCallback((patch: Partial<NotifySettings>) => {
    setSettingsState((s) => {
      const next = { ...s, ...patch };
      saveSettings(next);
      return next;
    });
  }, []);

  const markRead = useCallback(() => setUnread(0), []);

  return { settings, setSettings, items, unread, markRead };
}
