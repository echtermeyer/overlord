package logs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChainAndVerify(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(Options{Dir: dir, Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Write("event", map[string]any{"i": i, "cmd": "curl -H 'Authorization: Bearer abcdefghijklmnop' x"}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	path := filepath.Join(dir, "overlord.ndjson")
	n, err := Verify(path)
	if err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "abcdefghijklmnop") {
		t.Error("token not redacted")
	}
	if !strings.Contains(string(raw), "[redacted]") {
		t.Error("redaction marker missing")
	}

	l2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if l2.Seq() != 3 {
		t.Errorf("seq after reopen: %d", l2.Seq())
	}
	_ = l2.Write("event", "more")
	l2.Close()
	if n, err := Verify(path); err != nil || n != 4 {
		t.Fatalf("verify after reopen: %d %v", n, err)
	}

	tampered := strings.Replace(string(raw), `"i":1`, `"i":9`, 1)
	_ = os.WriteFile(path, []byte(tampered), 0o600)
	if _, err := Verify(path); err == nil {
		t.Error("tampering not detected")
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS_SECRET_ACCESS_KEY=[redacted]",
		"export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789":   "export GITHUB_TOKEN=[redacted]",
		"ls -la /tmp": "ls -la /tmp",
		"curl -H 'x-api-key: sk-ant-abcdefghijklmnopqrstuvwxyz' u": "curl -H 'x-api-key: [redacted]' u",
		"curl -H 'Authorization: Bearer abcdefghijklmnop' x":       "curl -H 'Authorization: Bearer [redacted]' x",
		"PGPASSWORD=hunter2hunter2 psql":                           "PGPASSWORD=[redacted] psql",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestShipper(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("X-Overlord-Host") != "mac1" {
			t.Errorf("headers: %v", r.Header)
		}
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		got = append(got, string(buf[:n]))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	l, _ := Open(Options{Dir: t.TempDir()})
	s := NewShipper(l, srv.URL, "tok", "mac1", 2, time.Hour)
	_ = l.Write("a", 1)
	_ = l.Write("b", 2)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2; i++ {
			s.pending = append(s.pending, <-l.queue)
		}
		s.flush(t.Context())
		close(done)
	}()
	<-done
	if len(got) != 1 || strings.Count(got[0], "\n") != 2 {
		t.Errorf("shipped: %q", got)
	}
}
