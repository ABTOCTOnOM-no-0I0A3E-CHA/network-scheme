package devemu

import (
	"strings"
	"testing"
	"time"
)

/* TestFixtures parses every fixture directory: profile, configuration, show outputs and transcripts. */
func TestFixtures(t *testing.T) {
	lines, err := Lines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) < 3 {
		t.Fatalf("fixture lines %v: want at least esr, mes6, mes10", lines)
	}
	for _, l := range lines {
		t.Run(l, func(t *testing.T) {
			fx, err := LoadLine(l)
			if err != nil {
				t.Fatal(err)
			}
			if len(fx.Transcripts) == 0 {
				t.Fatal("no transcripts")
			}
			/* an unchanged configuration prints exactly as the fixture */
			if got := New(fx, Options{}).Running(); got != strings.TrimRight(fx.Running, "\n") {
				t.Fatalf("running-config does not round-trip:\n%s", got)
			}
		})
	}
}

/* TestTranscripts replays every transcript against a fresh device of its fixture. */
func TestTranscripts(t *testing.T) {
	lines, err := Lines()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		fx, err := LoadLine(l)
		if err != nil {
			t.Fatal(err)
		}
		for _, tr := range fx.Transcripts {
			t.Run(l+"/"+tr.Name, func(t *testing.T) {
				if err := Replay(fx, tr); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

/* TestReplayDetectsDifference: a transcript that the device does not reproduce fails. */
func TestReplayDetectsDifference(t *testing.T) {
	fx, err := LoadLine("esr")
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"<<< esr-lab-01#\n>>> confirm\nConfiguration has been confirmed. Commit timer canceled.\n<<< esr-lab-01#\n",
		"<<< esr-lab-01#\n>>> configure\n<<< esr-lab-01#\n",
		"<<< esr>\n",
	} {
		tr, err := ParseTranscript(fx.Profile, "bad", text)
		if err != nil {
			t.Fatal(err)
		}
		if Replay(fx, tr) == nil {
			t.Errorf("replay of %q passed", text)
		}
	}
}

func TestParseTranscriptErrors(t *testing.T) {
	fx, err := LoadLine("esr")
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		">>> show version\n",                       /* input before a prompt */
		"<<< esr#\n<<< esr#\n",                     /* two prompts */
		"<<< esr#\n>>| <bogus>\n",                  /* unknown key */
		"<<< esr#\nstray output\n>>> show x\n",     /* output after a prompt */
		"<<< esr#\n## advance soon\n>>> confirm\n", /* bad duration */
		"just text\n",                              /* raw, but no prompt */
	} {
		if _, err := ParseTranscript(fx.Profile, "bad", text); err == nil {
			t.Errorf("ParseTranscript(%q) accepted", text)
		}
	}
}

/* TestRawCapture: a capture with ANSI colour, backspace edits and a pager prompt parses like the marked format. */
func TestRawCapture(t *testing.T) {
	fx, err := LoadLine("esr")
	if err != nil {
		t.Fatal(err)
	}
	raw := "\x1b[0mesr-lab-01# show versoin\b\b\bion\r\nBoot version:\r\n  1.23.3.2 (date 27/03/2024 time 21:13:26)\r\nSW version:\r\n" +
		"  1.23.3 build 3[a1b2c3d4] (date 27/03/2024 time 21:13:26)\r\nHW version:\r\n  2v1\r\nesr-lab-01# \r\n"
	tr, err := ParseTranscript(fx.Profile, "raw", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Steps) != 1 || tr.Steps[0].Input != "show version" || tr.Start != "esr-lab-01#" {
		t.Fatalf("parsed %+v", tr)
	}
	if err := Replay(fx, tr); err != nil {
		t.Fatal(err)
	}
}

/* TestJournal: the journal shows exactly what the device received, answers and keys included. */
func TestJournal(t *testing.T) {
	d := NewLine(t, "mes6", Options{})
	c := d.Dial("admin")
	c.Do("configure")
	c.Do("interface gigabitethernet1/0/2")
	c.Do("no shutdown")
	c.Do("end")
	c.Do("write")
	c.Do("Y")
	d.ExpectLines(t, "configure", "interface gigabitethernet1/0/2", "no shutdown", "end", "write")
	j := d.Journal()
	if last := j[len(j)-1]; last.Kind != "answer" || last.Input != "Y" || last.Mode != "confirm" {
		t.Fatalf("last entry %+v", last)
	}
	if !strings.Contains(d.Saved(), "interface gigabitethernet1/0/2\n exit") && strings.Contains(d.Saved(), " shutdown\nexit\n!\ninterface vlan") {
		t.Fatalf("startup-config not written:\n%s", d.Saved())
	}
	d.ExpectNone(t, "new-password", "password")
}

/* TestMESImmediateApply: MES 6.x applies at once; only write saves; reload loads startup-config [R §2a]. */
func TestMESImmediateApply(t *testing.T) {
	d := NewLine(t, "mes6", Options{})
	c := d.Dial("admin")
	c.Do("configure")
	c.Do("hostname sw-new")
	if !strings.Contains(d.Running(), "hostname sw-new") || strings.Contains(d.Saved(), "hostname sw-new") {
		t.Fatal("running should change at once, startup not")
	}
	c.Do("end")
	c.Do("reload in 5")
	c.Do("y")
	d.Advance(5 * time.Minute)
	if d.Reboots() != 1 || !c.Closed() || !strings.Contains(d.Running(), "hostname sw-lab-01") {
		t.Fatalf("reload in: reboots %d closed %v\n%s", d.Reboots(), c.Closed(), d.Running())
	}
}

/* TestMESCopyMerges: copy … running-config merges the file into running [R §2a]. */
func TestMESCopyMerges(t *testing.T) {
	d := NewLine(t, "mes6", Options{})
	d.PutFile("tftp://192.0.2.5/add.cfg", "interface gigabitethernet1/0/2\n description merged\nexit\nno ip ssh server\n")
	c := d.Dial("admin")
	if out := c.Do("copy tftp://192.0.2.5/add.cfg running-config"); out != "Copy succeeded" {
		t.Fatalf("copy: %q", out)
	}
	r := d.Running()
	if !strings.Contains(r, "interface gigabitethernet1/0/2\n shutdown\n description merged\nexit") || strings.Contains(r, "ip ssh server") ||
		!strings.Contains(r, "interface gigabitethernet1/0/1") {
		t.Fatalf("merged running:\n%s", r)
	}
	if out := c.Do("copy tftp://192.0.2.5/none.cfg running-config"); !strings.HasPrefix(out, "%") {
		t.Fatalf("missing file: %q", out)
	}
}

/* TestESRSharedCandidate: the candidate is one for all sessions [R §8]; commit of one applies the other's edit. */
func TestESRSharedCandidate(t *testing.T) {
	d := NewLine(t, "esr", Options{})
	a, b := d.Dial("admin"), d.Dial("admin")
	a.Do("configure")
	a.Do("hostname from-a")
	b.Do("commit")
	if !strings.Contains(d.Running(), "hostname from-a") || d.Pending().IsZero() {
		t.Fatal("commit in b should apply a's candidate edit")
	}
	if !strings.Contains(d.Saved(), "hostname from-a") {
		t.Fatal("commit writes flash [R §1]")
	}
	d.Advance(10 * time.Minute)
	if strings.Contains(d.Running(), "from-a") || strings.Contains(d.Saved(), "from-a") || !strings.Contains(d.Candidate(), "from-a") {
		t.Fatal("timer: running and flash revert, candidate keeps the edit")
	}
}

/* TestESRDeleteFile: the executor's snapshot file is copied, deleted at Close without a question, and gone [R §6]. */
func TestESRDeleteFile(t *testing.T) {
	d := NewLine(t, "esr", Options{})
	c := d.Dial("admin")
	c.Do("copy system:running-config flash:data/nms-pre-1")
	if out := c.Do("delete flash:data/nms-pre-1"); out != "" {
		t.Fatalf("delete: %q", out)
	}
	if out := c.Do("delete flash:data/nms-pre-1"); !strings.Contains(out, "% Invalid input") {
		t.Fatalf("second delete: %q", out)
	}
}

/* TestESRConfirmTimeoutFromConfig: system config-confirm timeout sets the default timer [R §1]. */
func TestESRConfirmTimeoutFromConfig(t *testing.T) {
	d := NewLine(t, "esr", Options{})
	c := d.Dial("admin")
	c.Do("configure")
	c.Do("system config-confirm timeout 300")
	c.Do("end")
	c.Do("commit")
	if got := d.Pending().Sub(d.Now()); got != 300*time.Second {
		t.Fatalf("timer %v", got)
	}
	if out := c.Do("commit confirm-timeout 900"); !strings.Contains(out, "900 seconds") {
		t.Fatalf("explicit timeout: %q", out)
	}
}

/* TestPagerAndSyslog: paged output, async log lines between commands and inside output [R §5]. */
func TestPagerAndSyslog(t *testing.T) {
	d := NewLine(t, "mes6", Options{})
	c := d.Dial("admin")
	_ = c.Read()
	out := c.Type("show long")
	if !strings.HasSuffix(out, d.P.Pager.Prompt.Text) || strings.Contains(out, "line 25") {
		t.Fatalf("first page: %q", out)
	}
	if out := c.Key('r'); !strings.Contains(out, "line 30") || !strings.HasSuffix(out, "sw-lab-01#") {
		t.Fatalf("rest: %q", out)
	}
	c.s.input([]byte("show ver"))
	_ = c.Read()
	d.Syslog("%LINK-W-Down:  gi1/0/2")
	if out := c.Read(); out != "\r\n01-Jan-2026 00:00:00 %LINK-W-Down:  gi1/0/2\r\nsw-lab-01#show ver" {
		t.Fatalf("async line: %q", out)
	}
	if out := c.Do("sion"); !strings.HasPrefix(out, "Active-image") {
		t.Fatalf("command after the async line: %q", out)
	}
	c.Do("terminal datadump")
	if out := c.Do("show long"); !strings.HasSuffix(out, "line 30") {
		t.Fatalf("datadump: %q", out)
	}
}

/* TestReject: a configured failure changes nothing and prints the message. */
func TestReject(t *testing.T) {
	d := NewLine(t, "esr", Options{})
	d.Reject(`^commit`, "Can't commit configuration")
	c := d.Dial("admin")
	c.Do("configure")
	c.Do("hostname x")
	c.Do("end")
	if out := c.Do("commit"); out != "Can't commit configuration" || !d.Pending().IsZero() {
		t.Fatalf("commit: %q", out)
	}
}

/* TestExpiredPasswordStops: the device waits for a new password; the journal shows whether one was sent. */
func TestExpiredPasswordStops(t *testing.T) {
	d := NewLine(t, "esr", Options{Users: map[string]User{"admin": {Password: "p", Privilege: 15, Expired: true}}})
	c := d.Dial("admin")
	if out := c.Read(); !strings.Contains(out, "expired") || c.Waiting() != "New password:" {
		t.Fatalf("expired: %q", out)
	}
	d.ExpectNone(t, "new-password")
	if out := c.Type("secret-new"); strings.Contains(out, "secret-new") {
		t.Fatal("new password echoed")
	}
	if j := d.Journal(); len(j) != 1 || j[0].Kind != "new-password" {
		t.Fatalf("journal %+v", j)
	}
}

func TestProfileValidation(t *testing.T) {
	p := &Profile{Line: "esr"}
	if err := p.validate(); err == nil {
		t.Fatal("empty profile accepted")
	}
	p = &Profile{Line: "ios"}
	if err := p.validate(); err == nil {
		t.Fatal("unknown line accepted")
	}
}
