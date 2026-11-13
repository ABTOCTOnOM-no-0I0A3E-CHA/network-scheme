package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"aead.dev/minisign"
	"filippo.io/age"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/sysbackup"
)

/*
nmsctl update [--sig F] BUNDLE runs on the host, as root, and reads only
local files (no download: an online bundle is the same file, fetched by the
operator).

Bundle: a tar whose first entry is manifest.json (bundleManifest), followed
by one "docker save" tarball per service image; next to it BUNDLE.minisig,
a minisign signature (prehashed, Ed25519) of the whole file by the offline
release key.

Flow: the bundle is copied into a private directory under varDir/updates
while its signature is checked (a bad or missing signature, or no release
key, refuses before any other step; only that copy is read afterwards) →
the copy is checked against its manifest (structure, every image's SHA-256)
→ current image tag and schema version against the manifest's range →
the writing services stopped until the end (writers) →
backup (the executor's state and pg_dump, as nmsctl backup; read back to its
authenticated end) and a copy of compose.yaml → docker load → compose.yaml
retagged → migrations → docker compose up --wait (every health check). Any
failure from the retag on rolls back: the previous compose.yaml, a fresh
postgres volume restored from the backup, the executor's state volume and
the anchors file put back, the stack up again. The outcome is appended to the panel audit
(cli.update) by the tools container.
*/

/*
releaseKey is the minisign public key (the base64 line of minisign.pub)
bundles are verified with; empty refuses every bundle. The maintainer keeps
the key pair offline (minisign -G; the secret key is never in CI or on a
server) and sets the public half at build time:

	go build -ldflags "-X main.releaseKey=RWQ..." ./cmd/nmsctl

The release workflow passes the repository variable MINISIGN_PUBLIC_KEY.
*/
var releaseKey = ""

/* bundleFormat is the manifest version this nmsctl reads; any other is refused. */
const bundleFormat = 1

const (
	maxBundleManifest = 64 << 10
	maxSignature      = 4 << 10
	maxRecordError    = 1000
)

/* composeVolumes are the compose project's (name: nms) volumes a rollback recreates. */
var composeVolumes = []string{"nms_pgdata", "nms_executor-state"}

/* bundleRepos are the images a bundle replaces, all at its image_tag; the database image stays. */
var bundleRepos = []string{install.DefaultAPIImage, install.DefaultGatewayImage, install.DefaultExecutorImage}

var (
	bundleTagRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	bundleFileRe = regexp.MustCompile(`^images/[a-z0-9-]{1,32}\.tar$`)
	sha256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

/* schemaScript prints the applied goose version (internal/store's table). */
const schemaScript = `exec psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -c "SELECT coalesce(max(version_id), 0) FROM core.goose_db_version WHERE is_applied"`

type bundleImage struct {
	Ref    string `json:"ref"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

/* bundleManifest is manifest.json; Schema.From..To is the range of current schema versions it upgrades, To the version after. */
type bundleManifest struct {
	Format   int    `json:"format"`
	Version  string `json:"version"`
	ImageTag string `json:"image_tag"`
	Schema   struct {
		From int64 `json:"from"`
		To   int64 `json:"to"`
	} `json:"schema"`
	Images []bundleImage `json:"images"`
}

func (m bundleManifest) validate() error {
	if m.Format != bundleFormat {
		return fmt.Errorf("bundle format %d, this nmsctl reads %d", m.Format, bundleFormat)
	}
	if !bundleTagRe.MatchString(m.Version) || !bundleTagRe.MatchString(m.ImageTag) {
		return errors.New("bundle manifest: bad version or image_tag")
	}
	if m.Schema.From < 1 || m.Schema.To < m.Schema.From {
		return errors.New("bundle manifest: bad schema range")
	}
	if len(m.Images) != len(bundleRepos) {
		return fmt.Errorf("bundle manifest: %d images, want %d", len(m.Images), len(bundleRepos))
	}
	refs, files := map[string]bool{}, map[string]bool{}
	for _, im := range m.Images {
		if !bundleFileRe.MatchString(im.File) || !sha256Re.MatchString(im.SHA256) || files[im.File] {
			return fmt.Errorf("bundle manifest: bad image entry %q", im.File)
		}
		refs[im.Ref], files[im.File] = true, true
	}
	for _, repo := range bundleRepos {
		if !refs[repo+":"+m.ImageTag] {
			return fmt.Errorf("bundle manifest: no image %s:%s", repo, m.ImageTag)
		}
	}
	return nil
}

func updateCmd(ctx context.Context, args []string, d deps) error {
	fs := newFlags("update")
	sigFile := fs.String("sig", "", "minisign signature of the bundle (default: BUNDLE.minisig)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return errors.New("usage: nmsctl update [--sig F] BUNDLE")
	}
	bundle := fs.Arg(0)
	if *sigFile == "" {
		*sigFile = bundle + ".minisig"
	}
	if err := os.MkdirAll(filepath.Join(varDir, "updates"), 0o700); err != nil {
		return err
	}
	dir := filepath.Join(varDir, "updates", d.now().UTC().Format("20060102T150405Z"))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	copied := filepath.Join(dir, "bundle.tar")
	m, err := verifiedCopy(bundle, *sigFile, copied)
	if err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("%w; nothing was changed", err)
	}
	defer func() { _ = os.Remove(copied); _ = os.Remove(dir) }() /* the directory only when nothing else is in it */
	printf(d.out, "Bundle %s verified.\n", m.Version)
	return update(ctx, stack{d.sys, d.errw}, m, copied, dir, d)
}

/*
verifiedCopy copies src to dst (0600, new) while hashing it for minisign,
checks the signature, then checks the copy against its manifest.
*/
func verifiedCopy(src, sigFile, dst string) (bundleManifest, error) {
	if releaseKey == "" {
		return bundleManifest{}, errors.New("this nmsctl was built without a release key: it cannot verify bundles")
	}
	var pub minisign.PublicKey
	if err := pub.UnmarshalText([]byte(releaseKey)); err != nil {
		return bundleManifest{}, fmt.Errorf("release key: %w", err)
	}
	sig, err := readLimited(sigFile, maxSignature)
	if err != nil {
		return bundleManifest{}, fmt.Errorf("signature: %w", err)
	}
	in, err := os.Open(src) // #nosec G304 -- path given by the operator
	if err != nil {
		return bundleManifest{}, err
	}
	defer func() { _ = in.Close() }()
	r := minisign.NewReader(in)
	if err := newArchive(dst, func(w io.Writer) error { _, err := io.Copy(w, r); return err }); err != nil {
		return bundleManifest{}, err
	}
	if !r.Verify(pub, sig) {
		return bundleManifest{}, errors.New("the bundle's signature does not verify with the release key")
	}
	return checkBundle(dst)
}

func readLimited(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) // #nosec G304 -- path given by the operator
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("file too large")
	}
	return b, err
}

/* openBundle opens a bundle and reads its manifest entry (always the first). */
func openBundle(p string) (*os.File, *tar.Reader, bundleManifest, error) {
	var m bundleManifest
	f, err := os.Open(p) // #nosec G304 -- nmsctl's private copy
	if err != nil {
		return nil, nil, m, err
	}
	tr := tar.NewReader(f)
	h, err := tr.Next()
	if err == nil && (h.Name != "manifest.json" || h.Typeflag != tar.TypeReg || h.Size > maxBundleManifest) {
		err = errors.New("bundle: manifest.json is not its first entry")
	}
	if err == nil {
		dec := json.NewDecoder(tr)
		dec.DisallowUnknownFields()
		if err = dec.Decode(&m); err == nil {
			err = m.validate()
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, m, fmt.Errorf("bundle: %w", err)
	}
	return f, tr, m, nil
}

/* checkBundle reads the whole bundle: exactly the manifest's image files, each of its SHA-256. */
func checkBundle(p string) (bundleManifest, error) {
	f, tr, m, err := openBundle(p)
	if err != nil {
		return m, err
	}
	defer func() { _ = f.Close() }()
	want := map[string]string{}
	for _, im := range m.Images {
		want[im.File] = im.SHA256
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("bundle: %w", err)
		}
		sum, ok := want[h.Name]
		if !ok || h.Typeflag != tar.TypeReg {
			return m, fmt.Errorf("bundle: unexpected entry %q", h.Name)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, tr); err != nil {
			return m, fmt.Errorf("bundle: %w", err)
		}
		if hex.EncodeToString(hash.Sum(nil)) != sum {
			return m, fmt.Errorf("bundle: %s does not match its manifest", h.Name)
		}
		delete(want, h.Name)
	}
	if len(want) > 0 {
		return m, errors.New("bundle: image files missing")
	}
	return m, nil
}

/* update runs everything after the verified copy; dir keeps the backup and the previous compose.yaml. */
func update(ctx context.Context, s stack, m bundleManifest, bundle, dir string, d deps) error {
	composePath := filepath.Join(etcDir, "compose.yaml")
	old, err := os.ReadFile(composePath) // #nosec G304 -- the install's compose project
	if err != nil {
		return err
	}
	from, err := currentTag(old)
	if err != nil {
		return err
	}
	if from == m.ImageTag {
		return fmt.Errorf("the images are already at %s", from)
	}
	schema, err := schemaVersion(ctx, s)
	if err != nil {
		return err
	}
	if schema < m.Schema.From || schema > m.Schema.To {
		return fmt.Errorf("the database schema is at version %d, the bundle upgrades %d..%d", schema, m.Schema.From, m.Schema.To)
	}

	id, err := sysbackup.Identity(filepath.Join(etcDir, identityFile))
	if err != nil {
		return fmt.Errorf("backup identity: %w", err)
	}
	/* Maintenance window: from here until the update succeeded or was rolled back, nothing writes what a rollback would discard. */
	printf(d.out, "Stopping the services for the update…\n")
	if err := s.compose(ctx, nil, d.out, append([]string{"stop"}, writers...)...); err != nil {
		return resume(ctx, s, d, fmt.Errorf("stop the services: %w; nothing was changed", err))
	}
	backup := filepath.Join(dir, "backup.age")
	var bm sysbackup.Manifest
	err = newArchive(backup, func(w io.Writer) (err error) {
		bm, err = snapshot(ctx, s, w, id.Recipient(), d, false)
		return err
	})
	if err == nil {
		err = verifyBackup(backup, id)
	}
	if err != nil {
		return resume(ctx, s, d, fmt.Errorf("backup before the update: %w; nothing was changed", err))
	}
	if err := writeNewFile(filepath.Join(dir, "compose.yaml"), old); err != nil {
		return resume(ctx, s, d, err)
	}
	printf(d.out, "Backup %s written to %s.\n", bm.ID, backup)

	if err := loadImages(ctx, s, bundle, m, d); err != nil {
		return resume(ctx, s, d, fmt.Errorf("load the images: %w; the running services were not changed", err))
	}
	rec := updateSummary{From: from, To: m.ImageTag, Backup: bm.ID, Result: "success"}
	if err = apply(ctx, s, composePath, retag(old, from, m.ImageTag), m, d); err != nil {
		printf(d.errw, "Update failed: %v\nRolling back to %s…\n", err, from)
		if rerr := rollback(context.WithoutCancel(ctx), s, composePath, old, backup, bm, id, d); rerr != nil {
			return fmt.Errorf("%w\nrollback failed: %w\nrecover by hand: previous compose file %s, backup %s (nmsctl restore)",
				err, rerr, filepath.Join(dir, "compose.yaml"), backup)
		}
		rec.Result, rec.Error = "failure", truncate(err.Error(), maxRecordError)
		err = fmt.Errorf("update to %s failed and was rolled back to %s: %w", m.ImageTag, from, err)
	}
	if rerr := recordUpdate(context.WithoutCancel(ctx), s, rec, d); rerr != nil {
		err = errors.Join(err, fmt.Errorf("record the update in the audit: %w", rerr))
	}
	if err == nil {
		printf(d.out, "Updated from %s to %s.\n", from, m.ImageTag)
	}
	return err
}

func verifyBackup(p string, id age.Identity) error {
	f, err := os.Open(p) // #nosec G304 -- the archive just written
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = sysbackup.VerifyData(f, id)
	return err
}

/* currentTag is the one tag of every bundleRepos image in compose.yaml. */
func currentTag(compose []byte) (string, error) {
	tag := ""
	for _, repo := range bundleRepos {
		re := regexp.MustCompile(`image: "` + regexp.QuoteMeta(repo) + `:([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})"`)
		ms := re.FindAllSubmatch(compose, -1)
		if len(ms) == 0 {
			return "", fmt.Errorf("compose.yaml: no %s image", repo)
		}
		for _, mm := range ms {
			if tag == "" {
				tag = string(mm[1])
			}
			if string(mm[1]) != tag {
				return "", errors.New("compose.yaml: the service images have different tags")
			}
		}
	}
	return tag, nil
}

func retag(compose []byte, from, to string) []byte {
	for _, repo := range bundleRepos {
		compose = bytes.ReplaceAll(compose, []byte(`"`+repo+":"+from+`"`), []byte(`"`+repo+":"+to+`"`))
	}
	return compose
}

func schemaVersion(ctx context.Context, s stack) (int64, error) {
	var out bytes.Buffer
	if err := s.pg(ctx, schemaScript, nil, &out); err != nil {
		return 0, fmt.Errorf("schema version: %w", err)
	}
	v, err := strconv.ParseInt(strings.TrimSpace(out.String()), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("schema version: unexpected %q", out.String())
	}
	return v, nil
}

/* loadImages streams each image tarball of the bundle into docker load and checks every reference then exists. */
func loadImages(ctx context.Context, s stack, bundle string, m bundleManifest, d deps) error {
	f, tr, _, err := openBundle(bundle)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	printf(d.out, "Loading the images…\n")
	for {
		if _, err := tr.Next(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if err := s.docker(ctx, tr, d.out, "load"); err != nil {
			return err
		}
	}
	for _, im := range m.Images {
		if err := s.docker(ctx, nil, io.Discard, "image", "inspect", "--format", "{{.Id}}", im.Ref); err != nil {
			return fmt.Errorf("image %s not loaded: %w", im.Ref, err)
		}
	}
	return nil
}

/* apply switches compose.yaml to the new images, migrates, and waits for every service to be healthy. */
func apply(ctx context.Context, s stack, composePath string, compose []byte, m bundleManifest, d deps) error {
	if err := install.ReplaceFile(composePath, compose); err != nil {
		return err
	}
	printf(d.out, "Running the migrations…\n")
	if err := s.compose(ctx, nil, d.out, "run", "--rm", "migrate"); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	v, err := schemaVersion(ctx, s)
	if err != nil {
		return err
	}
	if v != m.Schema.To {
		return fmt.Errorf("migrations: schema at version %d, the bundle expects %d", v, m.Schema.To)
	}
	printf(d.out, "Starting the services…\n")
	if err := s.compose(ctx, nil, d.out, "up", "-d", "--wait", "--wait-timeout", composeWait); err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

/*
writers are the services that write the database or the executor's state.
update stops them before its backup and starts them only with the new
images (apply) or after a rollback, so a rollback discards nothing written
in between: no lifted freeze, revived grant or lost audit of a device write.
The gateway writes nothing and stays up (the panel shows its api as
unavailable).
*/
var writers = []string{"executor", "api", "poller", "eventd"}

/* resume starts the writers again after an update that changed nothing. */
func resume(ctx context.Context, s stack, d deps, err error) error {
	if serr := s.compose(context.WithoutCancel(ctx), nil, d.out, append([]string{"start"}, writers...)...); serr != nil {
		return errors.Join(err, fmt.Errorf("start the services again: %w", serr))
	}
	return err
}

/* composeWait bounds docker compose up --wait, in seconds. */
const composeWait = "600"

/*
rollback puts back the previous compose.yaml, then the backup's database
into a fresh postgres volume, its executor state into a fresh state volume
and its audit anchors file (as restore does), and starts the stack.

Unlike restore it does not leave the executor frozen (restoredMarker): the
writers stayed stopped since the backup was taken (writers), so the backup
is the last state they wrote and the rollback discards no freeze, grant
change or audit row.
*/
func rollback(ctx context.Context, s stack, composePath string, old []byte, backup string, bm sysbackup.Manifest, id age.Identity, d deps) error {
	if err := install.ReplaceFile(composePath, old); err != nil {
		return err
	}
	if err := s.compose(ctx, nil, d.out, "stop"); err != nil {
		return err
	}
	if err := restoreAnchors(bm, d.sys); err != nil {
		return fmt.Errorf("restore the audit anchors: %w", err)
	}
	if err := s.compose(ctx, nil, d.out, "rm", "-f", "postgres", "executor"); err != nil {
		return err
	}
	if err := s.docker(ctx, nil, d.out, append([]string{"volume", "rm"}, composeVolumes...)...); err != nil {
		return err
	}
	if err := s.compose(ctx, nil, d.out, "up", "-d", "--wait", "postgres"); err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}
	f, err := os.Open(backup) // #nosec G304 -- the archive this update wrote
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := sysbackup.RestoreDB(ctx, f, id, s.pg); err != nil {
		return err
	}
	if err := s.compose(ctx, nil, d.out, "up", "--no-start", "executor"); err != nil {
		return err
	}
	cid, err := s.executorID(ctx)
	if err != nil {
		return err
	}
	if err := s.docker(ctx, bytes.NewReader(bm.ExecutorState), d.out, "cp", "-a", "-", cid+":"+path.Dir(executorStateDir)); err != nil {
		return fmt.Errorf("restore the executor state: %w", err)
	}
	return s.compose(ctx, nil, d.out, "up", "-d", "--wait", "--wait-timeout", composeWait)
}

/* restoreAnchors puts the backup's anchors file back (removes it if the backup had none): every anchor then names an event of the restored audit. */
func restoreAnchors(bm sysbackup.Manifest, sys install.System) error {
	p := filepath.Join(varDir, "anchors", "anchors.log")
	b, ok := bm.Files["anchors/anchors.log"]
	if !ok {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := install.ReplaceFile(p, b); err != nil {
		return err
	}
	return errors.Join(os.Chmod(p, 0o600), sys.Chown(p, install.ContainerUID, install.ContainerUID))
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

/* updateSummary is what update hands the tools container to record. */
type updateSummary struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Backup string `json:"backup"`
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

func recordUpdate(ctx context.Context, s stack, rec updateSummary, d deps) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return install.RunInTools(ctx, s.sys, etcDir, []string{"update", "record"}, bytes.NewReader(b), d.out, d.errw)
}

/* updateRecord (tools container) appends the update handed on stdin to the panel audit (INSERT only). */
func updateRecord(ctx context.Context, pool *pgxpool.Pool, args []string, d deps) error {
	if len(args) > 0 {
		return errors.New("usage: nmsctl update record (summary on stdin; run by nmsctl update)")
	}
	var s updateSummary
	dec := json.NewDecoder(io.LimitReader(d.in, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || !bundleTagRe.MatchString(s.To) || (s.Result != "success" && s.Result != "failure") {
		return errors.New("update record: bad summary on stdin")
	}
	details := map[string]any{"from": s.From, "backup": s.Backup}
	if s.Error != "" {
		details["error"], details["rolled_back"] = truncate(s.Error, maxRecordError), true
	}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Event{
			UserAgent: "nmsctl", Action: "cli.update", ObjectType: "release", ObjectID: s.To, Result: s.Result, Details: details,
		})
		return err
	})
	if err != nil {
		return err
	}
	printf(d.out, "update to %s recorded in the audit (%s)\n", s.To, s.Result)
	return nil
}
