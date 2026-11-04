package santa

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/echtermeyer/overlord/internal/events"
)

func TestSyncFlow(t *testing.T) {
	var got []*events.Event
	s, err := New(t.TempDir(), func(e *events.Event) { got = append(got, e) })
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/preflight/mac1", "application/json", bytes.NewReader([]byte(`{"serial_num":"x"}`)))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("preflight: %v %v", err, resp)
	}
	var pre map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pre)
	if pre["client_mode"] != "MONITOR" {
		t.Errorf("preflight: %v", pre)
	}

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"events":[{"file_sha256":"abc","file_path":"/Users/eric/Downloads","file_name":"updater","decision":"ALLOW_UNKNOWN","pid":4000,"ppid":10,"team_id":"","execution_time":1762250000.5}]}`))
	zw.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventupload/mac1", &buf)
	req.Header.Set("Content-Encoding", "zlib")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("eventupload: %v %v", err, resp)
	}
	if len(got) != 1 || got[0].Kind != events.SantaExec || got[0].Process.Path != "/Users/eric/Downloads/updater" || got[0].Detail["sha256"] != "abc" {
		t.Fatalf("events: %+v", got)
	}

	if err := s.Block("BINARY", "abc", "stealer"); err != nil {
		t.Fatal(err)
	}
	resp, _ = http.Post(srv.URL+"/ruledownload/mac1", "application/json", bytes.NewReader([]byte(`{}`)))
	var rules struct {
		Rules  []map[string]string `json:"rules"`
		Cursor string              `json:"cursor"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rules)
	if len(rules.Rules) != 1 || rules.Rules[0]["policy"] != "BLOCKLIST" || rules.Rules[0]["rule_type"] != "BINARY" || rules.Cursor != "" {
		t.Errorf("rules: %+v", rules)
	}

	reloaded, err := New(s.path[:len(s.path)-len("/santa-rules.json")], nil)
	if err != nil || len(reloaded.Rules()) != 1 {
		t.Errorf("rules not persisted: %v %v", err, reloaded)
	}
	if err := s.Block("HASH", "x", ""); err == nil {
		t.Error("bad rule type accepted")
	}
}

func TestLoopbackOnly(t *testing.T) {
	s, _ := New(t.TempDir(), nil)
	if err := s.ListenAndServe(t.Context(), "0.0.0.0:0"); err == nil {
		t.Error("non-loopback accepted")
	}
}
