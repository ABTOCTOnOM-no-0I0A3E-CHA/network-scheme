/* a spreadsheet treats a cell starting with one of these as a formula (OWASP CSV injection) */
const FORMULA_START = /^[=+\-@\t\r]/;

/**
 * One CSV cell: strings that a spreadsheet would run as a formula get a
 * leading apostrophe, then every cell is quoted with inner quotes doubled.
 * Numbers are written as they are (a negative number is not a formula).
 */
export function csvCell(v: unknown): string {
  let s: string;
  if (v === null || v === undefined) s = "";
  else if (typeof v === "number" || typeof v === "boolean") s = String(v);
  else {
    s = typeof v === "string" ? v : JSON.stringify(v);
    if (FORMULA_START.test(s)) s = `'${s}`;
  }
  return `"${s.replace(/"/g, '""')}"`;
}

/** CSV text (CRLF rows, header first) of the given columns of `rows`. */
export function toCsv<R extends object>(columns: readonly (keyof R & string)[], rows: readonly R[]): string {
  const lines = [columns.map(csvCell).join(","), ...rows.map((r) => columns.map((c) => csvCell(r[c])).join(","))];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Saves `text` as a file through a data: link with the download attribute
 * (the CSP and the build checks rule out blob: object URLs). A BOM lets
 * spreadsheets read the file as UTF-8.
 */
export function saveText(text: string, filename: string, type = "text/csv"): void {
  const a = document.createElement("a");
  a.href = `data:${type};charset=utf-8,${encodeURIComponent(String.fromCharCode(0xfeff) + text)}`;
  a.download = filename;
  a.rel = "noopener";
  document.body.append(a);
  a.click();
  a.remove();
}
