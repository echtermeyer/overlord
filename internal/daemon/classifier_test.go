package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/echtermeyer/overlord/internal/classifier"
	"github.com/echtermeyer/overlord/internal/events"
	"github.com/echtermeyer/overlord/internal/hooks"
)

// fakeDecisionServer answers every noul question with the same probability.
func fakeDecisionServer(t *testing.T, p float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Questions map[string]struct {
				Type string `json:"type"`
			} `json:"questions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		answers := map[string]any{}
		for id, q := range req.Questions {
			if q.Type == "noul" {
				answers[id] = map[string]any{"type": "noul", "noul": p}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"answers": answers, "latency_ms": 5})
	}))
}

func TestClassifierStages(t *testing.T) {
	call := hooks.Call{Phase: "pre", Info: events.ToolCallInfo{Agent: "claude", Session: "s", Tool: "Bash", Command: "make test", CWD: "/w", Project: "/w", AgentPID: 777}}
	for _, c := range []struct {
		stage string
		want  hooks.Permission
	}{
		{"shadow", hooks.Allow},
		{"ask", hooks.Ask},
		{"enforce", hooks.Deny},
	} {
		srv := fakeDecisionServer(t, 0.99)
		d := testDaemon(t, "default_stage: shadow\nstages:\n  classifier.agent-intent: "+c.stage+"\n")
		d.clf = &classifier.Client{URL: srv.URL, Model: "test", Timeout: time.Second}
		got := d.ToolCall(context.Background(), call)
		if got.Permission != c.want {
			t.Errorf("stage %s: got %s, want %s (%+v)", c.stage, got.Permission, c.want, got)
		}
		recorded := false
		for _, rec := range logLines(t, d) {
			if rec["kind"] == "classifier" {
				recorded = true
			}
		}
		if !recorded {
			t.Errorf("stage %s: no classifier record in the log", c.stage)
		}
		srv.Close()
	}
}

func TestClassifierBelowThresholdIsQuiet(t *testing.T) {
	srv := fakeDecisionServer(t, 0.1)
	defer srv.Close()
	d := testDaemon(t, "default_stage: enforce\n")
	d.clf = &classifier.Client{URL: srv.URL, Model: "test", Timeout: time.Second}
	got := d.ToolCall(context.Background(), hooks.Call{Phase: "pre", Info: events.ToolCallInfo{Agent: "claude", Session: "s", Tool: "Bash", Command: "make test", CWD: "/w", AgentPID: 778}})
	if got.Permission != hooks.Allow || strings.Contains(strings.Join(got.Rules, ","), "classifier") {
		t.Errorf("%+v", got)
	}
}
