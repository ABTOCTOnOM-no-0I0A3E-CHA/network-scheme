package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* fakeJobs records enqueued jobs; with fail set every enqueue errors. */
type fakeJobs struct {
	mu    sync.Mutex
	polls []int64
	scans []int64
	fail  bool
}

func (j *fakeJobs) EnqueuePollNow(_ context.Context, tx pgx.Tx, id int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if tx == nil || j.fail {
		return errors.New("fake: enqueue failed")
	}
	j.polls = append(j.polls, id)
	return nil
}

func (j *fakeJobs) EnqueueDiscovery(_ context.Context, tx pgx.Tx, id int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if tx == nil || j.fail {
		return errors.New("fake: enqueue failed")
	}
	j.scans = append(j.scans, id)
	return nil
}

/* nextAddr returns a fresh address from 198.18.0.0/15 so that tests never collide. */
func nextAddr() netip.Addr {
	n := seq.Add(1)
	return netip.AddrFrom4([4]byte{198, 18 + byte(n>>16&1), byte(n >> 8), byte(n)})
}

func (f *fixture) inTx(fn func(ctx context.Context, tx pgx.Tx, st *devices.Store) error) {
	f.t.Helper()
	ctx := context.Background()
	st := devices.NewStore(f.env.Pool("nms_api"))
	if err := pgx.BeginFunc(ctx, f.env.Pool("nms_api"), func(tx pgx.Tx) error { return fn(ctx, tx, st) }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) newGroup() int64 {
	f.t.Helper()
	var id int64
	f.inTx(func(ctx context.Context, tx pgx.Tx, _ *devices.Store) (err error) {
		id, err = rbac.NewStore(f.env.Pool("nms_api")).CreateGroup(ctx, tx, nil, uniqueName("grp"))
		return err
	})
	return id
}

func (f *fixture) newDevice(g int64) int64 {
	f.t.Helper()
	var id int64
	f.inTx(func(ctx context.Context, tx pgx.Tx, st *devices.Store) (err error) {
		id, err = st.Create(ctx, tx, devices.NewDevice{Name: uniqueName("dev"), Address: nextAddr(), GroupID: g})
		return err
	})
	return id
}

func (f *fixture) newProfile(owner devices.Owner, kind string) {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx pgx.Tx, st *devices.Store) error {
		return st.PutProfile(ctx, tx, owner, kind, []byte{1, 2, 3}, 1)
	})
}

func (f *fixture) newScan(g int64) int64 {
	f.t.Helper()
	var id int64
	f.inTx(func(ctx context.Context, tx pgx.Tx, st *devices.Store) (err error) {
		id, err = st.CreateScan(ctx, tx, devices.NewScan{CIDR: netip.MustParsePrefix("198.51.100.0/24"), GroupID: g, Enabled: true})
		return err
	})
	return id
}

/* newDiscovered records a pending find of a fresh address by a new scan in group g. */
func (f *fixture) newDiscovered(g int64) int64 {
	f.t.Helper()
	ctx := context.Background()
	scan := f.newScan(g)
	addr := nextAddr()
	pst := devices.NewStore(f.env.Pool("nms_poller"))
	if err := pgx.BeginFunc(ctx, f.env.Pool("nms_poller"), func(tx pgx.Tx) error {
		return pst.UpsertDiscovered(ctx, tx, scan, addr, "1.3.6.1.4.1.35265.1.1", "descr", "name")
	}); err != nil {
		f.t.Fatal(err)
	}
	d, err := devices.NewStore(f.env.Pool("nms_api")).Inbox(ctx, devices.InboxFilter{GroupIDs: []int64{g}, Status: "pending"})
	if err != nil {
		f.t.Fatal(err)
	}
	for _, it := range d {
		if it.Address == addr {
			return it.ID
		}
	}
	f.t.Fatal("discovered item not found")
	return 0
}

type deviceItem struct {
	ID                int64   `json:"id"`
	Name              string  `json:"name"`
	Address           string  `json:"address"`
	GroupID           int64   `json:"group_id"`
	State             string  `json:"state"`
	StateSince        *string `json:"state_since"`
	InsecureProtocols bool    `json:"insecure_protocols"`
}

func TestDeviceListFilteredByGroup(t *testing.T) {
	f := newFixture(t, nil)
	a, b := f.newGroup(), f.newGroup()
	var child int64
	f.inTx(func(ctx context.Context, tx pgx.Tx, _ *devices.Store) (err error) {
		child, err = rbac.NewStore(f.env.Pool("nms_api")).CreateGroup(ctx, tx, &a, uniqueName("child"))
		return err
	})
	inA, inChild, inB := f.newDevice(a), f.newDevice(child), f.newDevice(b)
	ids := func(s *subject) map[int64]deviceItem {
		resp := f.do(s.authed(req{method: "GET", path: "/api/devices"}))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list status %d", resp.StatusCode)
		}
		out := map[int64]deviceItem{}
		for _, d := range decode[[]deviceItem](t, resp) {
			out[d.ID] = d
		}
		return out
	}
	scoped := ids(f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &a}))
	if _, ok := scoped[inA]; !ok {
		t.Error("own group device missing")
	}
	if _, ok := scoped[inChild]; !ok {
		t.Error("descendant group device missing")
	}
	if _, ok := scoped[inB]; ok {
		t.Error("foreign group device listed")
	}
	if d := scoped[inA]; d.State != "unknown" || d.StateSince != nil || d.GroupID != a {
		t.Errorf("item = %+v", d)
	}
	global := ids(f.login(false, rbac.Binding{Role: rbac.RoleViewer}))
	for _, id := range []int64{inA, inChild, inB} {
		if _, ok := global[id]; !ok {
			t.Errorf("global viewer misses device %d", id)
		}
	}
	/* A binding without devices.read in any group never widens to "all". */
	if resp := f.do(f.login(false, rbac.Binding{Role: rbac.RoleAuditor}).authed(req{method: "GET", path: "/api/devices"})); resp.StatusCode != http.StatusForbidden {
		t.Errorf("auditor list status %d", resp.StatusCode)
	}
}

func TestForeignDeviceIs404(t *testing.T) {
	f := newFixture(t, nil)
	a, b := f.newGroup(), f.newGroup()
	foreign := f.newDevice(b)
	f.newProfile(devices.Owner{Kind: devices.OwnerDevice, ID: foreign}, "snmp3")
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &a})
	ct := base64.StdEncoding.EncodeToString([]byte("sealed"))
	for _, r := range []req{
		{method: "GET", path: fmt.Sprintf("/api/devices/%d", foreign)},
		{method: "PATCH", path: fmt.Sprintf("/api/devices/%d", foreign), body: map[string]any{"name": "x"}},
		{method: "DELETE", path: fmt.Sprintf("/api/devices/%d", foreign)},
		{method: "GET", path: fmt.Sprintf("/api/devices/%d/profiles", foreign)},
		{method: "PUT", path: fmt.Sprintf("/api/devices/%d/profiles/snmp3", foreign), body: map[string]any{"ciphertext": ct, "key_version": 1}},
		{method: "DELETE", path: fmt.Sprintf("/api/devices/%d/profiles/snmp3", foreign)},
		{method: "POST", path: fmt.Sprintf("/api/devices/%d/poll", foreign)},
		{method: "POST", path: "/api/devices", body: map[string]any{"name": "x", "address": nextAddr().String(), "group_id": b}},
		{method: "PATCH", path: fmt.Sprintf("/api/devices/%d", f.newDevice(a)), body: map[string]any{"group_id": b}},
		{method: "GET", path: "/api/devices/999999999"},
	} {
		wantError(t, f.do(admin.authed(r)), http.StatusNotFound, "not_found")
	}
	if d, err := devices.NewStore(f.env.Pool("nms_api")).Get(context.Background(), foreign); err != nil || d.GroupID != b {
		t.Fatalf("foreign device changed: %+v %v", d, err)
	}
	if len(f.jobs.polls) != 0 {
		t.Fatalf("poll enqueued for a foreign device: %v", f.jobs.polls)
	}
}

func TestDeviceCRUD(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	addr := nextAddr()
	resp := f.do(admin.authed(req{method: "POST", path: "/api/devices", body: map[string]any{"name": "sw1", "address": addr.String(), "group_id": g}}))
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create %d %s", resp.StatusCode, b)
	}
	id := decode[struct {
		ID int64 `json:"id"`
	}](t, resp).ID
	path := fmt.Sprintf("/api/devices/%d", id)
	resp = f.do(admin.authed(req{method: "PATCH", path: path, body: map[string]any{"name": "sw1b", "interval_avail_s": 15}}))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("patch %d", resp.StatusCode)
	}
	resp = f.do(admin.authed(req{method: "PATCH", path: path, body: map[string]any{"interval_metrics_s": 120}}))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("patch 2 %d", resp.StatusCode)
	}
	type detail struct {
		deviceItem
		SNMPPort         int  `json:"snmp_port"`
		IntervalAvailS   *int `json:"interval_avail_s"`
		IntervalMetricsS *int `json:"interval_metrics_s"`
	}
	d := decode[detail](t, f.do(admin.authed(req{method: "GET", path: path})))
	if d.Name != "sw1b" || d.Address != addr.String() || d.SNMPPort != 161 || d.IntervalAvailS == nil || *d.IntervalAvailS != 15 ||
		d.IntervalMetricsS == nil || *d.IntervalMetricsS != 120 {
		t.Fatalf("detail = %+v", d)
	}
	resp = f.do(admin.authed(req{method: "PATCH", path: path, body: map[string]any{"interval_avail_s": nil}}))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("patch null %d", resp.StatusCode)
	}
	if d := decode[detail](t, f.do(admin.authed(req{method: "GET", path: path}))); d.IntervalAvailS != nil || d.IntervalMetricsS == nil {
		t.Fatalf("after clearing avail: %+v", d)
	}
	for _, body := range []map[string]any{
		{}, {"interval_avail_s": 5}, {"interval_avail_s": 86401}, {"name": ""}, {"name": " x"},
		{"address": "not-an-ip"}, {"address": "127.0.0.1"}, {"address": "224.0.0.1"}, {"address": "0.0.0.0"},
		{"snmp_port": 0}, {"snmp_port": 65536},
	} {
		wantError(t, f.do(admin.authed(req{method: "PATCH", path: path, body: body})), http.StatusBadRequest, "bad_request")
	}
	resp = f.do(admin.authed(req{method: "DELETE", path: path}))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", resp.StatusCode)
	}
	wantError(t, f.do(admin.authed(req{method: "GET", path: path})), http.StatusNotFound, "not_found")
	wantAudit(t, f, "devices.create", "devices.update", "devices.delete")
}

func TestDuplicateAddress409(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	addr := nextAddr().String()
	body := map[string]any{"name": "a", "address": addr, "group_id": g}
	if resp := f.do(admin.authed(req{method: "POST", path: "/api/devices", body: body})); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create %d", resp.StatusCode)
	}
	body["name"] = "b"
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/devices", body: body})), http.StatusConflict, "address_exists")
	body["snmp_port"] = 1161
	if resp := f.do(admin.authed(req{method: "POST", path: "/api/devices", body: body})); resp.StatusCode != http.StatusCreated {
		t.Fatalf("same address, other port: %d", resp.StatusCode)
	}
	other := f.newDevice(g)
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/devices/%d", other), body: map[string]any{"address": addr}})),
		http.StatusConflict, "address_exists")
}

func TestCIDRTooWide(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	for _, c := range []struct {
		cidr   string
		status int
		code   string
	}{
		{"10.0.0.0/15", 400, "cidr_too_wide"},
		{"2001:db8::/111", 400, "cidr_too_wide"},
		{"10.0.0.0/16", 201, ""},
		{"2001:db8::/112", 201, ""},
		{"not-a-cidr", 400, "bad_request"},
	} {
		resp := f.do(admin.authed(req{method: "POST", path: "/api/discovery/scans", body: map[string]any{"cidr": c.cidr, "group_id": g, "interval_s": 3600}}))
		if c.code != "" {
			wantError(t, resp, c.status, c.code)
		} else if resp.StatusCode != c.status {
			t.Errorf("%s: status %d", c.cidr, resp.StatusCode)
		}
	}
	scan := f.newScan(g)
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/discovery/scans/%d", scan), body: map[string]any{"cidr": "10.0.0.0/8"}})),
		http.StatusBadRequest, "cidr_too_wide")
}

/*
TestPutProfileStoresOpaqueCiphertext: the API stores a sealed credential
without parsing it, and neither the plaintext nor the ciphertext shows up in
any column nms_api can read, in the logs or in any response.
*/
func TestPutProfileStoresOpaqueCiphertext(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	id := f.newDevice(g)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	plaintext := "community-" + uniqueName("KnownPlaintext")
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.SealAnonymous(nil, []byte(plaintext), pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct := base64.StdEncoding.EncodeToString(sealed)
	var bodies bytes.Buffer
	do := func(r req) *http.Response {
		resp := f.do(admin.authed(r))
		b, _ := io.ReadAll(resp.Body)
		bodies.Write(b)
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return resp
	}
	path := fmt.Sprintf("/api/devices/%d/profiles/snmp2c", id)
	if resp := do(req{method: "PUT", path: path, body: map[string]any{"ciphertext": ct, "key_version": 1}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put %d", resp.StatusCode)
	}
	wantError(t, do(req{method: "PUT", path: path, body: map[string]any{"ciphertext": ct, "key_version": 2}}), http.StatusBadRequest, "stale_key")
	wantError(t, do(req{method: "PUT", path: path, body: map[string]any{"ciphertext": base64.StdEncoding.EncodeToString(make([]byte, 8<<10+48+1)), "key_version": 1}}),
		http.StatusBadRequest, "bad_request")
	wantError(t, do(req{method: "PUT", path: path, body: map[string]any{"ciphertext": "", "key_version": 1}}), http.StatusBadRequest, "bad_request")
	wantError(t, do(req{method: "PUT", path: fmt.Sprintf("/api/devices/%d/profiles/ssh_write", id), body: map[string]any{"ciphertext": ct, "key_version": 1}}),
		http.StatusNotFound, "not_found")

	profiles := decode[[]struct {
		Kind      string `json:"kind"`
		Status    string `json:"status"`
		UpdatedAt string `json:"updated_at"`
	}](t, do(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/profiles", id)}))
	if len(profiles) != 1 || profiles[0].Kind != "snmp2c" || profiles[0].Status != "pending" || profiles[0].UpdatedAt == "" {
		t.Fatalf("profiles = %+v", profiles)
	}
	if d := decode[deviceItem](t, do(req{method: "GET", path: fmt.Sprintf("/api/devices/%d", id)})); !d.InsecureProtocols {
		t.Fatal("snmp2c must mark the device insecure")
	}
	do(req{method: "GET", path: "/api/audit?limit=200"})

	/* The stored bytes are exactly what was sent (checked as the superuser; nms_api cannot read them). */
	var stored []byte
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT ciphertext FROM core.access_profile
		WHERE owner_kind = 'device' AND owner_id = $1 AND kind = 'snmp2c'`, id).Scan(&stored); err != nil || !bytes.Equal(stored, sealed) {
		t.Fatalf("stored ciphertext differs: %v", err)
	}

	needles := []string{plaintext, ct, hex.EncodeToString(sealed)}
	haystacks := map[string]string{"logs": f.logs.String(), "responses": bodies.String()}
	for name, text := range readableByAPI(t, f) {
		haystacks[name] = text
	}
	for name, text := range haystacks {
		for _, n := range needles {
			if strings.Contains(text, n) {
				t.Errorf("%s contains secret material %.16q...", name, n)
			}
		}
	}

	resp := do(req{method: "DELETE", path: path})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", resp.StatusCode)
	}
	wantError(t, do(req{method: "DELETE", path: path}), http.StatusNotFound, "not_found")
	if d := decode[deviceItem](t, do(req{method: "GET", path: fmt.Sprintf("/api/devices/%d", id)})); d.InsecureProtocols {
		t.Fatal("removing the last insecure profile must clear the flag")
	}
	wantAudit(t, f, "devices.profile_set", "devices.profile_delete")
}

/*
readableByAPI dumps, per table, every column nms_api may SELECT, as text;
bytea columns both as hex and escape-encoded (so JSON payloads read as text).
*/
func readableByAPI(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	ctx := context.Background()
	pool := f.env.Pool("nms_api")
	rows, err := pool.Query(ctx, `
		SELECT c.table_schema, c.table_name,
		       array_agg(CASE WHEN c.data_type = 'bytea'
		                      THEN format('%1$I::text, encode(%1$I, ''escape'')', c.column_name)
		                      ELSE format('%I::text', c.column_name) END ORDER BY c.ordinal_position)
		FROM information_schema.columns c
		JOIN information_schema.tables tb USING (table_schema, table_name)
		WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema') AND c.table_schema NOT LIKE '\_timescaledb%'
		  AND tb.table_type IN ('BASE TABLE', 'VIEW')
		  AND has_schema_privilege(c.table_schema, 'USAGE')
		  AND has_column_privilege(format('%I.%I', c.table_schema, c.table_name), c.column_name, 'SELECT')
		GROUP BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	type tbl struct {
		schema, name string
		cols         []string
	}
	var tables []tbl
	for rows.Next() {
		var x tbl
		if err := rows.Scan(&x.schema, &x.name, &x.cols); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, x)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, x := range tables {
		q := fmt.Sprintf("SELECT concat_ws(' ', %s) FROM %s", strings.Join(x.cols, ", "), pgx.Identifier{x.schema, x.name}.Sanitize())
		vals, err := pgx.CollectRows(must(pool.Query(ctx, q)), pgx.RowTo[*string])
		if err != nil {
			t.Fatalf("%s.%s: %v", x.schema, x.name, err)
		}
		var b strings.Builder
		for _, v := range vals {
			if v != nil {
				b.WriteString(*v)
				b.WriteByte('\n')
			}
		}
		out[x.schema+"."+x.name] = b.String()
	}
	/* Sanity: the scan must cover the profile metadata and the audit log. */
	if !strings.Contains(out["core.access_profile"], "snmp2c") || !strings.Contains(out["audit.event"], `"details":{"key_version":1,"kind":"snmp2c"}`) {
		t.Fatalf("readable tables look incomplete: %d tables", len(out))
	}
	return out
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

/* wantAudit checks that each action has a success record in the audit log. */
func wantAudit(t *testing.T, f *fixture, actions ...string) {
	t.Helper()
	for _, a := range actions {
		var n int
		if err := f.env.Pool("postgres").QueryRow(context.Background(),
			`SELECT count(*) FROM audit.event WHERE action = $1 AND convert_from(payload, 'UTF8')::jsonb->>'result' = 'success'`, a).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("no audit record for %s", a)
		}
	}
}

func TestPollEnqueuesInTransaction(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	id := f.newDevice(g)
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	path := fmt.Sprintf("/api/devices/%d/poll", id)
	if resp := f.do(op.authed(req{method: "POST", path: path})); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("poll %d", resp.StatusCode)
	}
	if len(f.jobs.polls) != 1 || f.jobs.polls[0] != id {
		t.Fatalf("polls = %v", f.jobs.polls)
	}
	wantAudit(t, f, "devices.poll_now")
	/* A failed enqueue rolls the audit record back with it. */
	count := func() (n int) {
		_ = f.env.Pool("postgres").QueryRow(context.Background(),
			`SELECT count(*) FROM audit.event WHERE action = 'devices.poll_now' AND convert_from(payload, 'UTF8')::jsonb->>'object_id' = $1`, fmt.Sprint(id)).Scan(&n)
		return n
	}
	before := count()
	f.jobs.fail = true
	wantError(t, f.do(op.authed(req{method: "POST", path: path})), http.StatusInternalServerError, "internal")
	if count() != before {
		t.Fatal("audit record committed without its job")
	}
}

func TestPollNowQueuesRiverJob(t *testing.T) {
	enq, err := jobs.NewEnqueuer(testdb.New(t).Pool("nms_api"))
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(d *httpapi.Deps) { d.Jobs = enq })
	g := f.newGroup()
	id := f.newDevice(g)
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	if resp := f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/poll", id)})); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("poll %d", resp.StatusCode)
	}
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT count(*) FROM jobs.river_job
		WHERE kind = 'poll_now' AND queue = 'poller_local' AND (args->>'device_id')::bigint = $1`, id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("queued poll_now jobs = %d, %v", n, err)
	}
	wantAudit(t, f, "devices.poll_now")
}

func TestDiscoveryFlow(t *testing.T) {
	f := newFixture(t, nil)
	a, b := f.newGroup(), f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &a})
	resp := f.do(admin.authed(req{method: "POST", path: "/api/discovery/scans", body: map[string]any{"cidr": "192.0.2.0/24", "group_id": a, "interval_s": 3600}}))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create scan %d", resp.StatusCode)
	}
	scan := decode[struct {
		ID int64 `json:"id"`
	}](t, resp).ID
	foreignScan := f.newScan(b)
	scans := decode[[]struct {
		ID        int64  `json:"id"`
		CIDR      string `json:"cidr"`
		IntervalS int    `json:"interval_s"`
		Enabled   bool   `json:"enabled"`
	}](t, f.do(admin.authed(req{method: "GET", path: "/api/discovery/scans"})))
	if len(scans) != 1 || scans[0].ID != scan || scans[0].CIDR != "192.0.2.0/24" || !scans[0].Enabled {
		t.Fatalf("scans = %+v", scans)
	}
	if resp := f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/discovery/scans/%d", scan), body: map[string]any{"enabled": false, "interval_s": 7200}})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("patch scan %d", resp.StatusCode)
	}
	ct := base64.StdEncoding.EncodeToString([]byte("sealed-scan-credential"))
	for _, kind := range []string{"snmp2c", "snmp3"} {
		if resp := f.do(admin.authed(req{method: "PUT", path: fmt.Sprintf("/api/discovery/scans/%d/profile", scan),
			body: map[string]any{"kind": kind, "ciphertext": ct, "key_version": 1}})); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("put scan profile %s: %d", kind, resp.StatusCode)
		}
	}
	/* A scan has one profile: setting snmp3 replaced snmp2c. */
	ps, err := devices.NewStore(f.env.Pool("nms_api")).Profiles(context.Background(), devices.Owner{Kind: devices.OwnerScan, ID: scan})
	if err != nil || len(ps) != 1 || ps[0].Kind != "snmp3" {
		t.Fatalf("scan profiles = %+v, %v", ps, err)
	}
	wantError(t, f.do(admin.authed(req{method: "PUT", path: fmt.Sprintf("/api/discovery/scans/%d/profile", scan),
		body: map[string]any{"kind": "ssh_read", "ciphertext": ct, "key_version": 1}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/discovery/scans/%d", foreignScan), body: map[string]any{"enabled": false}})),
		http.StatusNotFound, "not_found")

	mine, foreign, ignored := f.newDiscovered(a), f.newDiscovered(b), f.newDiscovered(a)
	inbox := decode[[]struct {
		ID      int64  `json:"id"`
		GroupID int64  `json:"group_id"`
		Status  string `json:"status"`
		SysName string `json:"sys_name"`
	}](t, f.do(admin.authed(req{method: "GET", path: "/api/discovery/inbox"})))
	seen := map[int64]bool{}
	for _, it := range inbox {
		seen[it.ID] = true
		if it.GroupID != a || it.Status != "pending" {
			t.Errorf("inbox item %+v", it)
		}
	}
	if !seen[mine] || !seen[ignored] || seen[foreign] {
		t.Fatalf("inbox = %+v", inbox)
	}
	wantError(t, f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/accept", foreign), body: map[string]any{"name": "x", "group_id": a}})),
		http.StatusNotFound, "not_found")
	wantError(t, f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/accept", mine), body: map[string]any{"name": "x", "group_id": b}})),
		http.StatusNotFound, "not_found")
	resp = f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/accept", mine), body: map[string]any{"name": "found", "group_id": a}}))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("accept %d", resp.StatusCode)
	}
	devID := decode[struct {
		ID int64 `json:"id"`
	}](t, resp).ID
	if d := decode[deviceItem](t, f.do(admin.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d", devID)}))); d.Name != "found" || d.GroupID != a {
		t.Fatalf("accepted device = %+v", d)
	}
	wantError(t, f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/accept", mine), body: map[string]any{"name": "again", "group_id": a}})),
		http.StatusConflict, "not_pending")
	if resp := f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/ignore", ignored)})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ignore %d", resp.StatusCode)
	}
	wantError(t, f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/ignore", foreign)})), http.StatusNotFound, "not_found")
	if got := decode[[]struct {
		ID int64 `json:"id"`
	}](t, f.do(admin.authed(req{method: "GET", path: "/api/discovery/inbox?status=ignored"}))); len(got) != 1 || got[0].ID != ignored {
		t.Fatalf("ignored inbox = %+v", got)
	}
	wantError(t, f.do(admin.authed(req{method: "GET", path: "/api/discovery/inbox?status=bogus"})), http.StatusBadRequest, "bad_request")
	wantAudit(t, f, "discovery.scan_create", "discovery.scan_update", "discovery.accept", "discovery.ignore")
}

/* TestScanCIDRRejectsSpecialPrefixes: prefixes that touch unspecified, loopback, link-local or multicast space are refused. */
func TestScanCIDRRejectsSpecialPrefixes(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	for _, c := range []string{
		"0.0.0.0/24", "0.0.0.0/32", "::/112", "::/128", "::1/128",
		"169.254.0.0/16", "169.254.10.0/24", "fe80::/112", "fe80::1:0/112",
		"127.0.0.0/24", "224.0.0.0/24", "239.255.255.0/24", "ff02::/112",
	} {
		wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/discovery/scans", body: map[string]any{"cidr": c, "group_id": g}})),
			http.StatusBadRequest, "bad_request")
	}
	for _, c := range []string{"169.253.0.0/16", "10.0.0.0/24", "2001:db8::/112"} {
		if resp := f.do(admin.authed(req{method: "POST", path: "/api/discovery/scans", body: map[string]any{"cidr": c, "group_id": g}})); resp.StatusCode != http.StatusCreated {
			t.Errorf("%s: status %d", c, resp.StatusCode)
		}
	}
	scan := f.newScan(g)
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/discovery/scans/%d", scan), body: map[string]any{"cidr": "169.254.0.0/24"}})),
		http.StatusBadRequest, "bad_request")
}

/* TestScopedAdminCannotMoveScanToForeignGroup: an admin of group A cannot move a scan of A into group B. */
func TestScopedAdminCannotMoveScanToForeignGroup(t *testing.T) {
	f := newFixture(t, nil)
	a, b := f.newGroup(), f.newGroup()
	adminA := f.login(true, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &a})
	scan := f.newScan(a)
	wantError(t, f.do(adminA.authed(req{method: "PATCH", path: fmt.Sprintf("/api/discovery/scans/%d", scan), body: map[string]any{"group_id": b}})),
		http.StatusNotFound, "not_found")
	got, err := devices.NewStore(f.env.Pool("nms_api")).GetScan(context.Background(), scan)
	if err != nil || got.GroupID != a {
		t.Fatalf("scan after a refused move: %+v, %v", got, err)
	}
}

/* TestScanProfileTriggersRun: setting the profile of an enabled scan queues a run in the same transaction. */
func TestScanProfileTriggersRun(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	enabled, disabled := f.newScan(g), f.newScan(g)
	if resp := f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/discovery/scans/%d", disabled), body: map[string]any{"enabled": false}})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("disable scan %d", resp.StatusCode)
	}
	ct := base64.StdEncoding.EncodeToString([]byte("sealed-scan-credential"))
	for _, id := range []int64{enabled, disabled} {
		if resp := f.do(admin.authed(req{method: "PUT", path: fmt.Sprintf("/api/discovery/scans/%d/profile", id),
			body: map[string]any{"kind": "snmp2c", "ciphertext": ct, "key_version": 1}})); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("put scan profile: %d", resp.StatusCode)
		}
	}
	if len(f.jobs.scans) != 1 || f.jobs.scans[0] != enabled {
		t.Fatalf("scan runs = %v, want [%d]", f.jobs.scans, enabled)
	}
	/* An enqueue failure rolls the profile change back. */
	f.jobs.fail = true
	if resp := f.do(admin.authed(req{method: "PUT", path: fmt.Sprintf("/api/discovery/scans/%d/profile", enabled),
		body: map[string]any{"kind": "snmp3", "ciphertext": ct, "key_version": 1}})); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("put with a failing enqueue: %d", resp.StatusCode)
	}
	ps, err := devices.NewStore(f.env.Pool("nms_api")).Profiles(context.Background(), devices.Owner{Kind: devices.OwnerScan, ID: enabled})
	if err != nil || len(ps) != 1 || ps[0].Kind != "snmp2c" {
		t.Fatalf("profiles after a failed enqueue = %+v, %v", ps, err)
	}
}
