package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/store"
)

/* Limits of the inventory CSV export. */
const (
	maxExportRows  = 20000   /* rows written at most */
	maxExportScan  = 200_000 /* rows read at most while filtering (the poller's per-table cap) */
	maxExportQuery = 100     /* characters of q, as in the global search */
	exportSlots    = 2
	exportWait     = time.Second /* how long an export waits for a slot before answering 503 */
)

/* exportTimeout is the statement limit of the export's read (a variable for tests). */
var exportTimeout = 15 * time.Second

var errExportBusy = apiError{http.StatusServiceUnavailable, "busy", "Сервер занят выгрузкой таблиц, повторите позже"}

/* errExportFull stops the read once the outcome is known to be capped. */
var errExportFull = errors.New("export: capped")

/*
exportTable reads one inventory table of a device for the export: the header
(the API field names) and the rows as cells, in key order, keeping the rows
keep admits, at most maxExportRows of them after at most maxExportScan read.
capped tells that rows were left out.
*/
type exportTable struct {
	read    func(s *server, ctx context.Context, id int64, keep func(header, cells []string) bool) (header []string, rows [][]string, capped bool, err error)
	filters map[string]func(header, cells []string) bool /* named row filters of the table (the filter parameter) */
}

/* operIs filters interface rows by oper_up. */
func operIs(up bool) func(header, cells []string) bool {
	want := strconv.FormatBool(up)
	return func(header, cells []string) bool {
		for i, h := range header {
			if h == "oper_up" {
				return cells[i] == want
			}
		}
		return false
	}
}

var exportTables = map[string]exportTable{
	"interfaces": {exportRows(inventory.InterfaceTable), map[string]func([]string, []string) bool{"up": operIs(true), "down": operIs(false)}},
	"arp":        {exportRows(inventory.ARPTable), nil},
	"mac":        {exportRows(inventory.MACTable), nil},
	"vlans":      {exportRows(inventory.VLANTable), nil},
	"lldp":       {exportRows(inventory.LLDPTable), nil},
	"entities":   {exportRows(inventory.EntityTable), nil},
	"routes":     {exportRows(inventory.RouteTable), nil},
}

/*
exportRows reads the table by one statement (at most maxExportScan+1 rows) in
a read-only REPEATABLE READ transaction under exportTimeout, stopping as soon
as the export is known to be capped: a kept row past maxExportRows, or a row
past maxExportScan.
*/
func exportRows[T any](t inventory.Table[T]) func(*server, context.Context, int64, func([]string, []string) bool) ([]string, [][]string, bool, error) {
	return func(s *server, ctx context.Context, id int64, keep func([]string, []string) bool) ([]string, [][]string, bool, error) {
		var zero T
		header, _, err := rowCells(zero)
		if err != nil {
			return nil, nil, false, err
		}
		var out [][]string
		scanned, capped := 0, false
		err = store.BoundedSnapshot(ctx, s.pool, exportTimeout, func(tx pgx.Tx) error {
			return t.Each(ctx, tx, id, maxExportScan+1, func(row T) error {
				if scanned++; scanned > maxExportScan {
					capped = true
					return errExportFull
				}
				cells, err := headerCells(header, row)
				if err != nil {
					return err
				}
				if !keep(header, cells) {
					return nil
				}
				if len(out) == maxExportRows {
					capped = true
					return errExportFull
				}
				out = append(out, cells)
				return nil
			})
		})
		if err != nil && !errors.Is(err, errExportFull) {
			return nil, nil, false, err
		}
		return header, out, capped, nil
	}
}

/* headerCells renders row by rowCells and fails unless its fields are header, in order (a cell would land in another column). */
func headerCells(header []string, row any) ([]string, error) {
	keys, cells, err := rowCells(row)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(keys, header) {
		return nil, fmt.Errorf("export: row fields %v differ from the header %v", keys, header)
	}
	return cells, nil
}

/*
rowCells renders a row through its JSON form, so that the file holds the API
fields and values: strings as they are, null as an empty cell, anything else
as its JSON text. Text cells are neutralized by textCell.
*/
func rowCells(row any) (keys, cells []string, err error) {
	b, err := json.Marshal(row)
	if err != nil {
		return nil, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, errors.New("export: row is not an object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		k, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, err
		}
		cell := string(raw)
		switch {
		case cell == "null":
			cell = ""
		case strings.HasPrefix(cell, `"`):
			if err := json.Unmarshal(raw, &cell); err != nil {
				return nil, nil, err
			}
			cell = textCell(cell)
		}
		keys, cells = append(keys, k), append(cells, cell)
	}
	return keys, cells, nil
}

/*
textCell neutralizes a text value a spreadsheet would run as a formula (OWASP
CSV injection): one whose first character other than white space (NBSP
included) is =, +, - or @, or that starts with a tab or a carriage return,
gets a leading apostrophe. Numbers are not text cells (a negative number is
not a formula).
*/
func textCell(s string) string {
	if strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") {
		return "'" + s
	}
	t := strings.TrimLeftFunc(s, unicode.IsSpace)
	if t != "" && strings.ContainsRune("=+-@", rune(t[0])) {
		return "'" + s
	}
	return s
}

/* writeCSVRow writes one RFC 4180 record: every field quoted, inner quotes doubled, CRLF. */
func writeCSVRow(w io.Writer, cells []string) error {
	var sb strings.Builder
	for i, c := range cells {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(strings.ReplaceAll(c, `"`, `""`))
		sb.WriteByte('"')
	}
	sb.WriteString("\r\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

/*
exportInventory streams one inventory table of a device as a CSV attachment
(security.md §9: needs a fresh step-up; §11: audited as inventory.export).
q keeps the rows with a field containing it (case-insensitive, as the table
search of the panel) and filter applies a named filter of the table. At most
maxExportRows rows are written; X-Export-Capped and a "-capped" suffix of the
file name tell that rows were left out. At most exportSlots exports run at a
time; with every slot taken for exportWait the answer is 503 busy. A BOM
lets spreadsheets read the file as UTF-8.
*/
func (s *server) exportInventory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	name := chi.URLParam(r, "table")
	tbl, found := exportTables[name]
	params := r.URL.Query()
	q, okQ := single(params, "q")
	filter, okF := single(params, "filter")
	okQ = okQ && utf8.ValidString(q) && utf8.RuneCountInString(q) <= maxExportQuery && !strings.ContainsFunc(q, unicode.IsControl)
	keepNamed := tbl.filters[filter]
	if !found {
		writeError(w, errNotFound)
		return
	}
	if !okQ || !okF || (filter != "" && keepNamed == nil) {
		writeError(w, errBadRequest)
		return
	}
	d, err := s.authorizeDevice(r, rbac.PermDevicesRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	lq := strings.ToLower(strings.TrimSpace(q))
	keep := func(header, cells []string) bool {
		if keepNamed != nil && !keepNamed(header, cells) {
			return false
		}
		if lq == "" {
			return true
		}
		for _, c := range cells {
			if strings.Contains(strings.ToLower(c), lq) {
				return true
			}
		}
		return false
	}
	select {
	case s.exportSem <- struct{}{}:
		defer func() { <-s.exportSem }()
	case <-time.After(exportWait):
		w.Header().Set("Retry-After", "1")
		writeError(w, errExportBusy)
		return
	case <-r.Context().Done():
		return
	}
	header, rows, capped, err := tbl.read(s, r.Context(), id, keep)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "inventory.export", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"table": name, "rows": len(rows), "capped": capped, "q": q, "filter": filter}}
	if !s.change(w, r, ev, func(pgx.Tx, *audit.Event) error { return nil }) {
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	suffix := ""
	if capped {
		suffix = "-capped"
	}
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s%s.csv"`, name, strings.TrimSuffix(downloadName(d.Name, s.now()), ".txt"), suffix))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Export-Capped", strconv.FormatBool(capped))
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriter(w)
	_, _ = bw.Write([]byte{0xEF, 0xBB, 0xBF}) /* UTF-8 BOM */
	_ = writeCSVRow(bw, header)
	for _, row := range rows {
		if writeCSVRow(bw, row) != nil {
			return
		}
	}
	_ = bw.Flush()
}

/* stepUpStatus answers 204 while the session holds a fresh step-up (the route policy answers stepup_required otherwise). */
func (s *server) stepUpStatus(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
