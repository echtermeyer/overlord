// Command overlord-sink is the reference log receiver: append-only NDJSON per host, a bearer
// token, and an alert when a host's heartbeat stops. Put it behind TLS and on storage with a
// retention lock (a GCS bucket with retention policy, S3 Object Lock) for the real thing.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var hostName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type sink struct {
	dir     string
	token   string
	mu      sync.Mutex
	last    map[string]time.Time
	webhook string
	missing time.Duration
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8760", "address to listen on")
	dir := flag.String("dir", "./sink-data", "directory for per-host log files")
	tokenFile := flag.String("token-file", "", "file with the bearer token hosts must send")
	webhook := flag.String("webhook", "", "Slack-compatible webhook for missing-heartbeat alerts")
	missing := flag.Duration("missing-after", 5*time.Minute, "alert when a host's heartbeat is older than this")
	flag.Parse()
	token := ""
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatal(err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatal(err)
	}
	s := &sink{dir: *dir, token: token, last: map[string]time.Time{}, webhook: *webhook, missing: *missing}
	go s.watch(context.Background())
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", s.ingest)
	mux.HandleFunc("GET /hosts", s.hosts)
	log.Printf("overlord-sink listening on %s, writing to %s", *listen, *dir)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func (s *sink) ingest(w http.ResponseWriter, r *http.Request) {
	if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	host := r.Header.Get("X-Overlord-Host")
	if !hostName.MatchString(host) {
		http.Error(w, "bad host header", http.StatusBadRequest)
		return
	}
	f, err := os.OpenFile(filepath.Join(s.dir, host+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(r.Body)
	scanner.Buffer(make([]byte, 0, 1<<20), 64<<20)
	n := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(line, &rec) != nil {
			http.Error(w, "bad record", http.StatusBadRequest)
			return
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rec.Kind == "heartbeat" || rec.Kind == "start" {
			s.mu.Lock()
			s.last[host] = time.Now()
			s.mu.Unlock()
		}
		n++
	}
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, "%d\n", n)
}

func (s *sink) hosts(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(s.last)
}

func (s *sink) watch(ctx context.Context) {
	alerted := map[string]bool{}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			for host, at := range s.last {
				late := time.Since(at) > s.missing
				if late && !alerted[host] {
					alerted[host] = true
					s.alert(fmt.Sprintf("Overlord on %s stopped sending heartbeats %s ago", host, time.Since(at).Round(time.Second)))
				}
				if !late {
					alerted[host] = false
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *sink) alert(text string) {
	log.Println("ALERT:", text)
	if s.webhook == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := http.Post(s.webhook, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Println("webhook:", err)
		return
	}
	resp.Body.Close()
}
