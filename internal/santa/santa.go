// Package santa is a sync server for Santa on loopback. Santa does the blocking with its own
// Endpoint Security entitlement; Overlord supplies the rules and receives execution events.
package santa

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/echtermeyer/overlord/internal/events"
)

type Rule struct {
	Identifier string `json:"identifier"`
	Policy     string `json:"policy"`    // BLOCKLIST | ALLOWLIST | REMOVE
	RuleType   string `json:"rule_type"` // BINARY | CERTIFICATE | TEAMID | SIGNINGID | CDHASH
	CustomMsg  string `json:"custom_msg,omitempty"`
	Added      int64  `json:"added"`
}

type Event struct {
	FileSHA256      string   `json:"file_sha256"`
	FilePath        string   `json:"file_path"`
	FileName        string   `json:"file_name"`
	ExecutingUser   string   `json:"executing_user"`
	ExecutionTime   float64  `json:"execution_time"`
	Decision        string   `json:"decision"`
	PID             int      `json:"pid"`
	PPID            int      `json:"ppid"`
	ParentName      string   `json:"parent_name"`
	SigningID       string   `json:"signing_id"`
	TeamID          string   `json:"team_id"`
	CDHash          string   `json:"cdhash"`
	CurrentSessions []string `json:"current_sessions"`
}

type Server struct {
	path  string
	mu    sync.Mutex
	rules []Rule
	emit  func(*events.Event)
	Seen  map[string]time.Time
}

func New(dataDir string, emit func(*events.Event)) (*Server, error) {
	s := &Server{path: filepath.Join(dataDir, "santa-rules.json"), emit: emit, Seen: map[string]time.Time{}}
	raw, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(raw, &s.rules); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Server) Rules() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Rule{}, s.rules...)
}

// Block adds a blocklist rule; Santa picks it up at its next sync and refuses the next execution.
func (s *Server) Block(ruleType, identifier, msg string) error {
	switch ruleType {
	case "BINARY", "CERTIFICATE", "TEAMID", "SIGNINGID", "CDHASH":
	default:
		return errors.New("rule type must be BINARY, CERTIFICATE, TEAMID, SIGNINGID or CDHASH")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rules {
		if r.RuleType == ruleType && r.Identifier == identifier {
			s.rules[i].Policy = "BLOCKLIST"
			s.rules[i].CustomMsg = msg
			return s.save()
		}
	}
	s.rules = append(s.rules, Rule{Identifier: identifier, Policy: "BLOCKLIST", RuleType: ruleType, CustomMsg: msg, Added: time.Now().Unix()})
	return s.save()
}

func (s *Server) Unblock(ruleType, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rules {
		if r.RuleType == ruleType && r.Identifier == identifier {
			s.rules[i].Policy = "REMOVE"
			return s.save()
		}
	}
	return errors.New("no such rule")
}

func (s *Server) save() error {
	raw, err := json.MarshalIndent(s.rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /preflight/{machine}", s.preflight)
	mux.HandleFunc("POST /eventupload/{machine}", s.eventupload)
	mux.HandleFunc("POST /ruledownload/{machine}", s.ruledownload)
	mux.HandleFunc("POST /postflight/{machine}", s.postflight)
	return mux
}

func (s *Server) ListenAndServe(ctx context.Context, listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("santa sync must listen on loopback")
	}
	srv := &http.Server{Addr: listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func body(r *http.Request) (io.ReadCloser, error) {
	switch strings.ToLower(r.Header.Get("Content-Encoding")) {
	case "zlib", "deflate":
		return zlib.NewReader(r.Body)
	case "gzip":
		return gzip.NewReader(r.Body)
	}
	return r.Body, nil
}

func (s *Server) preflight(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.Seen[r.PathValue("machine")] = time.Now()
	s.mu.Unlock()
	writeJSON(w, map[string]any{
		"client_mode":        "MONITOR",
		"batch_size":         100,
		"enable_bundles":     false,
		"full_sync_interval": 600,
		"clean_sync":         false,
	})
}

func (s *Server) eventupload(w http.ResponseWriter, r *http.Request) {
	rc, err := body(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer rc.Close()
	var in struct {
		Events []Event `json:"events"`
	}
	if err := json.NewDecoder(io.LimitReader(rc, 32<<20)).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, e := range in.Events {
		at := time.Unix(int64(e.ExecutionTime), int64((e.ExecutionTime-float64(int64(e.ExecutionTime)))*1e9))
		ev := &events.Event{
			Kind: events.SantaExec, At: at, Source: "santa",
			Process: events.Process{PID: e.PID, PPID: e.PPID, Path: e.FilePath + "/" + e.FileName, SigningID: e.SigningID, TeamID: e.TeamID, CDHash: e.CDHash},
			Detail:  map[string]string{"decision": e.Decision, "sha256": e.FileSHA256, "user": e.ExecutingUser, "parent": e.ParentName},
		}
		if strings.HasSuffix(e.FilePath, "/") || e.FileName == "" {
			ev.Process.Path = e.FilePath + e.FileName
		}
		s.emit(ev)
	}
	writeJSON(w, map[string]any{"event_upload_bundle_binaries": []string{}})
}

func (s *Server) ruledownload(w http.ResponseWriter, r *http.Request) {
	rc, err := body(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer rc.Close()
	var in struct {
		Cursor string `json:"cursor"`
	}
	_ = json.NewDecoder(rc).Decode(&in)
	from, _ := strconv.Atoi(in.Cursor)
	rules := s.Rules()
	if from > len(rules) {
		from = len(rules)
	}
	const page = 500
	end := from + page
	cursor := ""
	if end >= len(rules) {
		end = len(rules)
	} else {
		cursor = strconv.Itoa(end)
	}
	out := make([]map[string]string, 0, end-from)
	for _, rule := range rules[from:end] {
		item := map[string]string{"identifier": rule.Identifier, "policy": rule.Policy, "rule_type": rule.RuleType}
		if rule.CustomMsg != "" {
			item["custom_msg"] = rule.CustomMsg
		}
		out = append(out, item)
	}
	writeJSON(w, map[string]any{"rules": out, "cursor": cursor})
}

func (s *Server) postflight(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
