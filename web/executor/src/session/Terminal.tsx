import { useEffect, useRef, type ClipboardEvent, type KeyboardEvent } from "react";
import { useTranslation } from "react-i18next";

/*
 * Minimal line terminal (ruling Q8: xterm.js injects runtime <style>, which the :8443 CSP forbids).
 * Device output is rendered only as a React text child: nothing is parsed, no escape is interpreted.
 * The executor owns the line editor and the echo; this component only forwards keys and pastes.
 */

/* Key sequences the executor's line editor understands (VT, like xterm would send); anything else is dropped here. */
const NAMED_KEYS: Record<string, string> = {
  Enter: "\r",
  Backspace: "\x7f",
  Tab: "\t",
  Delete: "\x1b[3~",
  ArrowUp: "\x1b[A",
  ArrowDown: "\x1b[B",
  ArrowRight: "\x1b[C",
  ArrowLeft: "\x1b[D",
  Home: "\x1b[H",
  End: "\x1b[F",
};

/* Maps one key press to the bytes for a `keys` frame, or null when the key is not forwarded. */
export function encodeKey(e: Pick<KeyboardEvent, "key" | "ctrlKey" | "altKey" | "metaKey">): string | null {
  if (e.metaKey || e.altKey) return null;
  if (e.ctrlKey) return /^[a-z]$/i.test(e.key) ? String.fromCharCode(e.key.toUpperCase().charCodeAt(0) - 64) : null;
  if (e.key in NAMED_KEYS) return NAMED_KEYS[e.key];
  return [...e.key].length === 1 ? e.key : null;
}

export type TerminalProps = {
  /** Sanitised device output (the executor strips ESC/OSC/CSI and C0); rendered as plain text. */
  output: string;
  /** One key press, encoded for a `keys` frame. */
  onKeys: (data: string) => void;
  /** Pasted text for a `paste` frame; the server decides whether it needs confirmation. */
  onPaste: (text: string) => void;
  /** Read-only mode (recording player): no input is forwarded. */
  readOnly?: boolean;
  /** Where the executor's line editor has its cursor, as an index into output: drawn as a block (text, not a style). */
  caret?: number;
  /** Extra classes (height) for the screen. */
  className?: string;
};

export function Terminal({ output, onKeys, onPaste, readOnly = false, caret, className }: TerminalProps) {
  const { t } = useTranslation();
  const ref = useRef<HTMLPreElement>(null);

  /* follow the tail as output grows */
  useEffect(() => {
    const el = ref.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [output]);

  const keyDown = (e: KeyboardEvent<HTMLPreElement>) => {
    if (readOnly) return;
    /* let the browser copy a selection and fire the paste event */
    if (e.ctrlKey && (e.key === "v" || (e.key === "c" && !!window.getSelection()?.toString()))) return;
    const data = encodeKey(e);
    if (data === null) return;
    e.preventDefault();
    onKeys(data);
  };

  const paste = (e: ClipboardEvent<HTMLPreElement>) => {
    e.preventDefault();
    if (readOnly) return;
    const text = e.clipboardData.getData("text/plain");
    if (text) onPaste(text);
  };

  return (
    <pre
      ref={ref}
      role="log"
      aria-label={t("executor.terminal.label")}
      tabIndex={0}
      data-testid="terminal"
      className={`${className ?? "h-96"} overflow-auto whitespace-pre-wrap break-all rounded-md border border-neutral-800 bg-neutral-950 p-3 font-mono text-[13px] leading-5 text-neutral-100 outline-none focus-visible:ring-2 focus-visible:ring-ring`}
      onKeyDown={keyDown}
      onPaste={paste}
    >
      {caret === undefined || caret < 0 || caret > output.length ? (
        output
      ) : (
        <>
          {output.slice(0, caret)}
          <span data-testid="caret" className="bg-neutral-200 text-neutral-950">
            {output[caret] === undefined || output[caret] === "\n" ? " " : output[caret]}
          </span>
          {output.slice(caret + (output[caret] === undefined || output[caret] === "\n" ? 0 : 1))}
        </>
      )}
    </pre>
  );
}
