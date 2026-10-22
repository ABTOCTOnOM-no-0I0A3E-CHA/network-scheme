package install

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/internal/keys"
	"github.com/beekamai/network-scheme/internal/pki"
)

/*
Container users that read secrets. Compose file secrets are bind mounts that
keep the host owner and mode, so every secret is owned by its consumer.
*/
const (
	/* ContainerUID is the distroless "nonroot" user of api, migrate, nmsctl, poller, eventd and gateway. */
	ContainerUID = 65532
	/*
		PostgresUID is uid and gid of "postgres" in DefaultDBImage, found with
		docker run --rm --entrypoint id <DefaultDBImage> postgres
		→ uid=70(postgres) gid=70(postgres).
	*/
	PostgresUID = 70
)

// ErrSecretsExist means the secrets directory (or a file in it) already exists; nothing was written.
var ErrSecretsExist = errors.New("install: secrets already exist")

/* Validity of generated certificates. */
const (
	caValidity  = 10 * 365 * 24 * time.Hour
	webValidity = 365 * 24 * time.Hour
)

// DomainKeyFiles maps key domains to their private key file in the secrets directory.
var DomainKeyFiles = map[string]string{
	"read":   "domain_read.key",
	"write":  "domain_write.key",
	"backup": "domain_backup.key",
}

/* secretFile is one file of the secrets directory with its owner and mode. */
type secretFile struct {
	name     string
	data     []byte
	uid, gid int
	mode     os.FileMode
}

// SecretsInput parameterizes WriteSecrets.
type SecretsInput struct {
	PublicHost string /* SAN of the self-signed web certificate */
	/* Corporate web certificate and key (PEM); both nil → issued by the internal CA. */
	WebCertPEM, WebKeyPEM []byte
	Chown                 func(path string, uid, gid int) error
}

/*
WriteSecrets creates dir (0700) with every installation secret: role
passwords db_{postgres,migrator,api,cli,poller,eventd}_password (32 random bytes,
base64url), api_data_key and executor_sealing_key (32 random bytes, base64),
domain_{read,write,backup}.key (X25519 private keys, base64), ca.crt/ca.key
web.crt/web.key and syslog.crt/syslog.key. Files are created with O_EXCL in a temporary sibling
directory and owned by their consumer container user, then the directory is
renamed into place, so an existing dir is an error (ErrSecretsExist) and a
failure leaves nothing behind. Existing secrets are never touched.
*/
func WriteSecrets(dir string, in SecretsInput) error {
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("%w: %s", ErrSecretsExist, dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("install: %w", err)
	}
	files, err := generateSecrets(in)
	if err != nil {
		return err
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, ".secrets-tmp-")
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o700); err != nil { // #nosec G302 -- a directory needs the x bit
		return fmt.Errorf("install: %w", err)
	}
	for _, f := range files {
		p := filepath.Join(tmp, f.name)
		if err := writeExcl(p, f.data, f.mode); err != nil {
			return err
		}
		if err := in.Chown(p, f.uid, f.gid); err != nil {
			return fmt.Errorf("install: chown %s: %w", f.name, err)
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrSecretsExist, dir, err)
	}
	done = true
	return nil
}

/* writeExcl creates path with O_EXCL and mode, writes data and syncs it. */
func writeExcl(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- path built by the installer
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("install: write %s: %w", path, err)
	}
	/* The umask may have narrowed mode (e.g. 0440 under umask 0077): set it exactly. */
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

/* generateSecrets builds every secret in memory; nothing touches the disk. */
func generateSecrets(in SecretsInput) ([]secretFile, error) {
	var files []secretFile
	add := func(name string, data []byte, uid, gid int, mode os.FileMode) {
		files = append(files, secretFile{name, data, uid, gid, mode})
	}
	add("db_postgres_password", nil, PostgresUID, PostgresUID, 0o400)
	/* Read by postgres' init script once and by the service at runtime. */
	add("db_migrator_password", nil, ContainerUID, PostgresUID, 0o440)
	add("db_api_password", nil, ContainerUID, PostgresUID, 0o440)
	add("db_cli_password", nil, ContainerUID, PostgresUID, 0o440)
	add("db_poller_password", nil, ContainerUID, PostgresUID, 0o440)
	add("db_eventd_password", nil, ContainerUID, PostgresUID, 0o440)
	for i := range files {
		b, err := keys.NewSymmetricKey()
		if err != nil {
			return nil, err
		}
		files[i].data = []byte(base64.RawURLEncoding.EncodeToString(b[:]))
	}

	for _, name := range []string{"api_data_key", "executor_sealing_key"} {
		k, err := keys.NewSymmetricKey()
		if err != nil {
			return nil, err
		}
		uid := 0
		if name == "api_data_key" {
			uid = ContainerUID
		}
		add(name, []byte(base64.StdEncoding.EncodeToString(k[:])), uid, uid, 0o400)
	}
	for _, d := range []string{"read", "write", "backup"} {
		k, err := keys.NewDomainKey()
		if err != nil {
			return nil, err
		}
		uid := 0
		if d == "read" { /* opened by the poller to verify read credentials */
			uid = ContainerUID
		}
		add(DomainKeyFiles[d], []byte(base64.StdEncoding.EncodeToString(k.Private[:])), uid, uid, 0o400)
	}

	caCrt, caKey, err := pki.NewCA("network-scheme internal CA", caValidity)
	if err != nil {
		return nil, fmt.Errorf("install: CA: %w", err)
	}
	add("ca.crt", caCrt, 0, 0, 0o400)
	add("ca.key", caKey, 0, 0, 0o400)

	var dns []string
	var ips []net.IP
	in.PublicHost = strings.ToLower(in.PublicHost)
	if ip := net.ParseIP(in.PublicHost); ip != nil {
		ips = append(ips, ip)
	} else {
		dns = append(dns, in.PublicHost)
	}

	webCrt, webKey := in.WebCertPEM, in.WebKeyPEM
	switch {
	case webCrt == nil && webKey == nil:
		if webCrt, webKey, err = pki.IssueServerCert(caCrt, caKey, dns, ips, webValidity); err != nil {
			return nil, fmt.Errorf("install: web certificate: %w", err)
		}
	case webCrt == nil || webKey == nil:
		return nil, errors.New("install: the web certificate and its key must be given together")
	default:
		if _, err := tls.X509KeyPair(webCrt, webKey); err != nil {
			return nil, fmt.Errorf("install: web certificate and key do not form a pair: %w", err)
		}
	}
	add("web.crt", webCrt, ContainerUID, ContainerUID, 0o400)
	add("web.key", webKey, ContainerUID, ContainerUID, 0o400)

	/*
		TLS syslog (eventd, 6514): always issued by the internal CA, also when the panel uses a
		corporate certificate, so the devices trust ca.crt and nothing else. Read by eventd (uid 65532).
	*/
	sysCrt, sysKey, err := pki.IssueServerCert(caCrt, caKey, dns, ips, webValidity)
	if err != nil {
		return nil, fmt.Errorf("install: syslog certificate: %w", err)
	}
	add("syslog.crt", sysCrt, ContainerUID, ContainerUID, 0o400)
	add("syslog.key", sysKey, ContainerUID, ContainerUID, 0o400)
	return files, nil
}
