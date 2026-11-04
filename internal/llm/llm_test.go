package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOllamaRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path %s", r.URL.Path)
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["model"] != "m" || in["format"] != "json" {
			t.Errorf("request: %v", in)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": `{"explanation":"reads cookies then posts","verdict":"deny"}`}})
	}))
	defer srv.Close()
	e := &Explainer{Provider: "ollama", Model: "m", URL: srv.URL, Timeout: time.Second}
	r, err := e.Explain(t.Context(), Case{Rule: "x"})
	if err != nil || r.Verdict != "deny" || r.Explanation == "" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestParseNeverAllows(t *testing.T) {
	r, err := parse(`text before {"explanation":"ok","verdict":"allow"} after`)
	if err != nil || r.Verdict != "keep" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := parse("no json"); err == nil {
		t.Error("accepted non-JSON")
	}
}

func TestDisabled(t *testing.T) {
	var e *Explainer
	if e.Enabled() {
		t.Error("nil enabled")
	}
	if (&Explainer{Provider: "none"}).Enabled() {
		t.Error("none enabled")
	}
}
