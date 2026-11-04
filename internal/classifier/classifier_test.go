package classifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	overlord "github.com/echtermeyer/overlord"
)

func TestShippedQuestions(t *testing.T) {
	raw, err := overlord.Files.ReadFile("rules/questions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	qs, err := ParseQuestions(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) == 0 {
		t.Fatal("no questions")
	}
	for _, q := range qs {
		if q.RuleID() != "classifier."+q.ID {
			t.Errorf("rule id %s", q.RuleID())
		}
		if _, err := json.Marshal(q.Criteria); err != nil {
			t.Errorf("%s: criteria not JSON-able: %v", q.ID, err)
		}
	}
}

func TestJudge(t *testing.T) {
	cases := []struct {
		q    Question
		a    Answer
		want Outcome
	}{
		{Question{Type: "noul", AskAbove: 0.7}, Answer{Noul: 0.8}, Outcome{Ask: true}},
		{Question{Type: "noul", AskAbove: 0.7, DenyAbove: 0.95}, Answer{Noul: 0.96}, Outcome{Ask: true, Deny: true}},
		{Question{Type: "noul", AskAbove: 0.7}, Answer{Noul: 0.3}, Outcome{}},
		{Question{Type: "choice", AskOn: []string{"exfiltration", "persistence"}}, Answer{Choice: "persistence"}, Outcome{Ask: true}},
		{Question{Type: "choice", AskOn: []string{"exfiltration"}}, Answer{Choice: "build"}, Outcome{}},
		{Question{Type: "score", AskAbove: 2}, Answer{Score: 2.4}, Outcome{Ask: true}},
	}
	for i, c := range cases {
		if got := c.q.Judge(c.a); got != c.want {
			t.Errorf("%d: got %+v, want %+v", i, got, c.want)
		}
	}
}

func TestRender(t *testing.T) {
	q := Question{ID: "x", Explain: "p={{pct .Noul}} c={{.Choice}}"}
	if got := q.Render(Answer{Noul: 0.874, Choice: "exfiltration"}); got != "p=87% c=exfiltration" {
		t.Errorf("%q", got)
	}
	if got := (Question{ID: "y"}).Render(Answer{Noul: 0.5}); got == "" {
		t.Error("empty fallback")
	}
}

func TestValidation(t *testing.T) {
	bad := []string{
		"- id: x\n  on: exec\n  type: noul\n  instructions: i\n",
		"- id: x\n  on: exec\n  type: choice\n  instructions: i\n",
		"- id: x\n  on: exec\n  type: magic\n  instructions: i\n  ask_above: 0.5\n",
		"- id: x\n  on: exec\n  type: noul\n  ask_above: 0.5\n",
		"- id: x\n  on: exec\n  type: noul\n  ask_above: 0.5\n  instructions: i\n- id: x\n  on: exec\n  type: noul\n  ask_above: 0.5\n  instructions: i\n",
	}
	for _, raw := range bad {
		if _, err := ParseQuestions([]byte(raw)); err == nil {
			t.Errorf("accepted: %s", raw)
		}
	}
}

func TestAskRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/systemone" || r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("request: %s %v", r.URL.Path, r.Header)
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		qs := req["questions"].(map[string]any)
		if req["model"] != "kev-latest" || qs["malicious"].(map[string]any)["type"] != "noul" {
			t.Errorf("body: %v", req)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":      "kev-latest",
			"answers":    map[string]any{"malicious": map[string]any{"type": "noul", "noul": 0.91}, "kind": map[string]any{"type": "choice", "choice": "exfiltration", "probabilities": map[string]float64{"exfiltration": 0.8, "build": 0.2}, "confidence": 0.6}},
			"latency_ms": 40,
		})
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Model: "kev-latest", Key: "k", Timeout: time.Second}
	answers, err := c.Ask(t.Context(), map[string]any{"process": "x"}, []Question{
		{ID: "malicious", Type: "noul", Instructions: "i", AskAbove: 0.7},
		{ID: "kind", Type: "choice", Instructions: "i", AskOn: []string{"exfiltration"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if answers["malicious"].Noul != 0.91 || answers["kind"].Choice != "exfiltration" || answers["kind"].Confidence != 0.6 {
		t.Errorf("%+v", answers)
	}
	var disabled *Client
	if disabled.Enabled() {
		t.Error("nil client enabled")
	}
}
