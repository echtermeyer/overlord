// Package simulate reproduces a stealer's observable behaviour without any harm: it opens the
// credential files that exist and posts nothing but a fixed string to a listener it starts itself.
package simulate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var targets = []string{
	"Library/Application Support/Google/Chrome/Default/Cookies",
	"Library/Application Support/Google/Chrome/Default/Login Data",
	"Library/Keychains/login.keychain-db",
	".ssh/id_ed25519",
	".ssh/id_rsa",
	".aws/credentials",
	".config/gcloud/credentials.db",
	".npmrc",
	".netrc",
	".gnupg/pubring.kbx",
}

func Stealer(out io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "overlord simulate stealer: reading credential files that exist (one byte each)")
	opened := 0
	for _, rel := range targets {
		path := filepath.Join(home, rel)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		buf := make([]byte, 1)
		_, _ = f.Read(buf)
		f.Close()
		opened++
		fmt.Fprintln(out, "  read", path)
	}
	if opened < 2 {
		fmt.Fprintln(out, "  fewer than two credential files readable; host.stealer-pattern needs two categories")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	url := "http://" + ln.Addr().String() + "/exfil"
	fmt.Fprintln(out, "  posting a fixed string to", url)
	resp, err := http.Post(url, "text/plain", strings.NewReader("overlord-simulation"))
	if err != nil {
		return err
	}
	resp.Body.Close()
	fmt.Fprintln(out, "done: check `overlord status` and the log for host.stealer-pattern")
	return nil
}
