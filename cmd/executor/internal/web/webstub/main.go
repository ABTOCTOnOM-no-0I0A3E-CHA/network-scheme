/*
Command webstub is a test tool of test/gateway, never built into an image
(the Dockerfiles build ./cmd/executor only). "serve" runs the executor's real
/x server (package web: TLS, client certificate, Origin, headers, limits)
with an authorizer that refuses everything, on the given address only, plus
/x/evil/* that plays a compromised executor answer (it echoes the request
headers it received and sets Set-Cookie, Service-Worker-Allowed, a CSP and
an HTML type) so the test sees what the gateway passes either way. "probe"
dials addresses from inside a test network and reports what a client of a
given certificate gets.
*/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: webstub serve|probe ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "probe":
		err = probe(os.Args[2:])
	default:
		err = errors.New("unknown mode " + os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

/* refuser refuses every ticket; nothing reaches a registry. */
type refuser struct{}

func (refuser) TicketUser(string) (int64, bool) { return 0, false }

func (refuser) Identify(context.Context, authz.Request) (authz.Decision, error) {
	return authz.Decision{}, authz.ErrDenied
}

func (refuser) Authorize(context.Context, authz.Request) (authz.Decision, error) {
	return authz.Decision{}, authz.ErrDenied
}

func (refuser) Issue(int64, authz.Need, confirm.Description) (confirm.Challenge, error) {
	return confirm.Challenge{}, authz.ErrDenied
}

func (refuser) Action(string) (string, bool) { return "", false }

func (refuser) Confirm(context.Context, string, []byte, authz.Request) (confirm.Challenge, authz.Decision, error) {
	return confirm.Challenge{}, authz.Decision{}, authz.ErrDenied
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "address:port")
	cert, key, ca := fs.String("cert", "", ""), fs.String("key", "", ""), fs.String("ca", "", "")
	exOrigin, panel := fs.String("executor-origin", "", ""), fs.String("panel-origin", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := web.New(web.Config{CertFile: *cert, KeyFile: *key, ClientCAFile: *ca, ExecutorOrigin: *exOrigin, PanelOrigin: *panel,
		Auth: refuser{}, Confirm: refuser{}, State: func() (bool, bool) { return true, false }, Log: log})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	/* The same TLS as the real server: only the handler gains the evil route. */
	hs := &http.Server{ReadHeaderTimeout: 5 * time.Second, TLSConfig: srv.TLSConfig(),
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/x/evil/") {
				evil(w, r)
				return
			}
			srv.ServeHTTP(w, r)
		})}
	go func() { <-ctx.Done(); _ = hs.Close() }()
	fmt.Println("webstub serving on", ln.Addr())
	if err := hs.Serve(tls.NewListener(ln, srv.TLSConfig())); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func evil(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Set-Cookie", "nms_session=evil; Path=/")
	h.Add("Set-Cookie", "__Host-x=1; Path=/; Secure")
	h.Set("Service-Worker-Allowed", "/")
	h.Set("Content-Security-Policy", "script-src *")
	h.Set("Content-Type", "text/html")
	got := map[string][]string{}
	for k, v := range r.Header {
		got[k] = v
	}
	got["Host"] = []string{r.Host}
	_ = json.NewEncoder(w).Encode(got)
}

/*
probe runs each case "name address cert" (cert: a path prefix of
<prefix>.crt and <prefix>.key, or - for none) as GET /x/status and prints
one line per case: "name OK <status>" or "name ERR <refused|timeout|tls|other> <error>".
*/
func probe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	ca := fs.String("ca", "", "CA that signed the server certificate")
	host := fs.String("host", "", "Host header (default: the address)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pem, err := os.ReadFile(*ca)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	rest := fs.Args()
	for i := 0; i+2 < len(rest); i += 3 {
		name, addr, prefix := rest[i], rest[i+1], rest[i+2]
		cfg := &tls.Config{RootCAs: roots, ServerName: "executor", MinVersion: tls.VersionTLS13}
		if prefix != "-" {
			c, err := tls.LoadX509KeyPair(prefix+".crt", prefix+".key")
			if err != nil {
				return err
			}
			cfg.Certificates = []tls.Certificate{c}
		}
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg,
			DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/x/status", nil)
		if *host != "" {
			req.Host = *host
		}
		req.Header.Set("X-Forwarded-For", "192.0.2.1")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(name, "ERR", class(err), strings.ReplaceAll(err.Error(), "\n", " "))
			continue
		}
		_ = resp.Body.Close()
		fmt.Println(name, "OK", resp.StatusCode)
	}
	return nil
}

func class(err error) string {
	var ne net.Error
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "refused"
	case errors.As(err, &ne) && ne.Timeout(), strings.Contains(s, "timeout"), strings.Contains(s, "no route"), strings.Contains(s, "unreachable"):
		return "timeout"
	case strings.Contains(s, "tls") || strings.Contains(s, "certificate"):
		return "tls"
	}
	return "other"
}
