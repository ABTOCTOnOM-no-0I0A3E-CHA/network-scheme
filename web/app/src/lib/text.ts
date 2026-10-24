/**
 * Makes a string reported by a device safe to show: C0/C1 control characters and
 * bidirectional overrides/isolates are replaced with U+FFFD so they can neither
 * disturb the layout nor reorder the surrounding text. The result is still plain text.
 */
export function safeText(s: string | null | undefined): string {
  if (!s) return "";
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    const bad = c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029 || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += bad ? "\uFFFD" : ch;
  }
  return out;
}

/**
 * Multi-line device text (configuration, command output) made safe line by
 * line: tabs become spaces, line breaks are kept, everything else follows
 * safeText. The result is plain text for a <pre>.
 */
export function safeLines(s: string | null | undefined): string {
  if (!s) return "";
  return s
    .split(/\r?\n/)
    .map((l) => safeText(l.replace(/\t/g, "    ")))
    .join("\n");
}
