import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey } from "@/features/auth/errors";
import { ApiError } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { parseVarbinds, useEvents, type EventSeverity, type NmsEvent } from "./api";
import { buildQuery, EventFilters, INITIAL_FILTERS, type FilterState } from "./EventFilters";

const ROW_HEIGHT = 40;
const NO_EVENTS: NmsEvent[] = [];
const GRID = "grid grid-cols-[1.5rem_9.5rem_4.5rem_6rem_minmax(7rem,0.8fr)_minmax(7rem,0.8fr)_minmax(12rem,3fr)] items-center gap-3 px-3";
const MIN_WIDTH = "min-w-[56rem]";
const NEAR_END = 5;

const TONE: Record<EventSeverity | "none", string> = {
  none: "bg-muted text-muted-foreground",
  info: "bg-muted text-muted-foreground",
  warning: "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-300",
  average: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  disaster: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
};

/** Severity badge; a trap no rule named has none. */
export function SeverityBadge({ severity }: { severity: EventSeverity | null }) {
  const { t } = useTranslation();
  return (
    <span data-severity={severity ?? "none"} className={cn("inline-flex w-fit items-center rounded-full px-2 py-0.5 text-xs font-medium", TONE[severity ?? "none"])}>
      {severity ? t(`events.severity.${severity}`) : t("events.severity.none")}
    </span>
  );
}

/** Varbinds of a trap as monospace text; truncated values are marked. */
export function VarbindList({ raw }: { raw: unknown }) {
  const { t } = useTranslation();
  const vb = parseVarbinds(raw);
  if (vb === undefined) return <p className="text-xs text-muted-foreground">{t("events.noVarbinds")}</p>;
  if (typeof vb === "string") return <pre className="overflow-x-auto font-mono text-xs break-words whitespace-pre-wrap">{safeText(vb)}</pre>;
  return (
    <ul className="grid gap-1 font-mono text-xs">
      {vb.map((v, i) => (
        <li key={i} className="break-all">
          <span>{safeText(v.oid)}</span> <span className="text-muted-foreground">{safeText(v.type)}</span> = <span>{safeText(v.value)}</span>
          {v.truncated && <span className="ml-2 rounded bg-amber-100 px-1.5 py-0.5 font-sans text-[10px] text-amber-800 dark:bg-amber-950 dark:text-amber-300">{t("events.truncated")}</span>}
        </li>
      ))}
    </ul>
  );
}

function EventRow({ e, expanded, onToggle, showDevice }: { e: NmsEvent; expanded: boolean; onToggle: () => void; showDevice: boolean }) {
  const { t, i18n } = useTranslation();
  const text = safeText(e.text);
  const source = safeText(e.kind === "trap" ? e.name : e.app);
  return (
    <>
      <div className={cn(GRID, "h-10 text-sm")}>
        <button type="button" aria-expanded={expanded} aria-label={t(expanded ? "events.collapse" : "events.expand")} className="text-muted-foreground" onClick={onToggle}>
          {expanded ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
        </button>
        <time dateTime={e.ts} className="text-xs tabular-nums">
          {new Date(e.ts).toLocaleString(i18n.language)}
        </time>
        <span className="text-xs">{t(`events.kind.${e.kind}`)}</span>
        <SeverityBadge severity={e.severity} />
        <span className="truncate" title={safeText(e.device_name)}>
          {showDevice ? safeText(e.device_name) : ""}
        </span>
        <span className="flex min-w-0 items-center gap-1">
          <span className="truncate" title={source}>
            {source}
          </span>
          {e.kind === "trap" && !e.identified && <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-800 dark:bg-amber-950 dark:text-amber-300">{t("events.unidentified")}</span>}
        </span>
        <span className="truncate font-mono text-xs" title={text}>
          {text}
        </span>
      </div>
      {expanded && (
        <div className="grid gap-2 border-t bg-muted/30 px-4 py-3" data-testid="event-details">
          <p className="font-mono text-xs break-words whitespace-pre-wrap">{text}</p>
          {e.kind === "trap" && <VarbindList raw={e.varbinds} />}
        </div>
      )}
    </>
  );
}

type Props = {
  /** Fixes the device (journal tab of a device card): the device filter is hidden and the device column left empty. */
  deviceId?: number;
};

/** Syslog and trap feed: filters, cursor paging and a virtualized list with expandable rows. All event text is device data and rendered as text. */
export function EventFeed({ deviceId }: Props) {
  const { t } = useTranslation();
  const [filters, setFilters] = useState<FilterState>(INITIAL_FILTERS);
  /* the moment presets are measured from; it moves on every filter change and on refresh */
  const [anchor, setAnchor] = useState(() => Date.now());
  const update = useCallback((patch: Partial<FilterState>) => {
    setFilters((f) => ({ ...f, ...patch }));
    setAnchor(Date.now());
  }, []);

  const built = useMemo(() => buildQuery(filters, anchor, deviceId), [filters, anchor, deviceId]);
  const query = "query" in built ? built.query : undefined;
  /* hooks need a value even while the period is invalid; the request is disabled then */
  const feed = useEvents(query ?? { from: new Date(anchor).toISOString() }, !!query);
  const events = useMemo(() => feed.data?.pages.flatMap((p) => p.items) ?? NO_EVENTS, [feed.data]);

  const [open, setOpen] = useState<Set<string>>(new Set());
  const keyOf = (e: NmsEvent, i: number) => `${e.ts}|${e.device_id}|${e.kind}|${i}`;
  const toggle = (k: string) =>
    setOpen((s) => {
      const n = new Set(s);
      if (!n.delete(k)) n.add(k);
      return n;
    });

  const scrollRef = useRef<HTMLDivElement>(null);
  /* the compiler skips memoizing this component, which the virtualizer needs */
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtual = useVirtualizer({ count: events.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_HEIGHT, overscan: 8 });
  const items = virtual.getVirtualItems();
  const lastIndex = items.length ? items[items.length - 1].index : -1;
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = feed;
  useEffect(() => {
    if (lastIndex >= events.length - NEAR_END && hasNextPage && !isFetchingNextPage) void fetchNextPage();
  }, [lastIndex, events.length, hasNextPage, isFetchingNextPage, fetchNextPage]);

  const loadError = feed.error instanceof ApiError ? t(errorKey({ error: { code: feed.error.code } })) : feed.error ? t("errors.unknown") : undefined;

  return (
    <section className="grid gap-4">
      <EventFilters value={filters} onChange={update} hideDevice={deviceId !== undefined} error={"error" in built ? built.error : undefined} />
      {loadError && (
        <p role="alert" className="text-sm text-destructive">
          {loadError}
        </p>
      )}
      <div role="table" aria-label={t("events.table")} aria-rowcount={events.length + 1} className="overflow-x-auto rounded-md border">
        <div className={MIN_WIDTH}>
          <div role="row" className={cn(GRID, "h-10 border-b bg-muted/50 text-xs font-medium text-muted-foreground")}>
            <span />
            <span role="columnheader">{t("events.col.time")}</span>
            <span role="columnheader">{t("events.col.kind")}</span>
            <span role="columnheader">{t("events.col.severity")}</span>
            <span role="columnheader">{t("events.col.device")}</span>
            <span role="columnheader">{t("events.col.source")}</span>
            <span role="columnheader">{t("events.col.text")}</span>
          </div>
          <div ref={scrollRef} className="h-[65vh] overflow-y-auto" data-testid="event-scroll">
            <div className="relative w-full" style={{ height: virtual.getTotalSize() }}>
              {items.map((v) => {
                const e = events[v.index];
                const k = keyOf(e, v.index);
                return (
                  <div
                    key={k}
                    ref={virtual.measureElement}
                    data-index={v.index}
                    role="row"
                    aria-rowindex={v.index + 2}
                    className="absolute top-0 left-0 w-full border-b"
                    style={{ transform: `translateY(${v.start}px)` }}
                  >
                    <EventRow e={e} expanded={open.has(k)} onToggle={() => toggle(k)} showDevice={deviceId === undefined} />
                  </div>
                );
              })}
            </div>
            {query && feed.isPending && <p className="p-4 text-sm text-muted-foreground">{t("events.loading")}</p>}
            {query && !feed.isPending && !loadError && events.length === 0 && <p className="p-4 text-sm text-muted-foreground">{t("events.empty")}</p>}
          </div>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <p className="text-xs text-muted-foreground">{t("events.count", { count: events.length })}</p>
        {hasNextPage && (
          <Button type="button" variant="outline" size="sm" disabled={isFetchingNextPage} onClick={() => void fetchNextPage()}>
            {t("events.loadMore")}
          </Button>
        )}
        <Button type="button" variant="outline" size="sm" onClick={() => update({})}>
          {t("events.refresh")}
        </Button>
      </div>
    </section>
  );
}
