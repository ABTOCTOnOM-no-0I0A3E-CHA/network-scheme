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
