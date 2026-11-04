// Package classifier is the second decision tier: typed questions answered by a local
// "System One" model over the /v1/systemone contract (Kev, or Laya behind a shim). It can raise
// an ask or, for agent calls above a separate threshold, a deny. It can never allow.
package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/echtermeyer/overlord/internal/rules"
)

// Question is one typed question from rules/questions.yaml. `on` and `when` gate which events
// it is asked about, exactly like a rule; its pseudo-rule id is "classifier.<id>".
type Question struct {
	ID           string         `yaml:"id"`
	Threat       string         `yaml:"threat"`
	On           rules.KindList `yaml:"on"`
	When         string         `yaml:"when"`
	Type         string         `yaml:"type"` // noul | choice | score
	Instructions string         `yaml:"instructions"`
	Criteria     any            `yaml:"criteria"`
	// AskAbove: noul probability or score level at which the question raises an ask.
	AskAbove float64 `yaml:"ask_above"`
	// AskOn: choice options that raise an ask.
	AskOn []string `yaml:"ask_on"`
	// DenyAbove: noul probability or score level at which an agent tool call is denied
	// (stage enforce only). Zero disables it.
	DenyAbove float64  `yaml:"deny_above"`
	DenyOn    []string `yaml:"deny_on"`
	Explain   string   `yaml:"explain"`
}

func (q Question) RuleID() string { return "classifier." + q.ID }

var funcs = template.FuncMap{"pct": func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }}

// Render fills the question's explain text with the answer: {{.Choice}}, {{.Noul}}, {{.Score}},
// {{pct .Noul}}.
func (q Question) Render(a Answer) string {
	if q.Explain == "" {
		return fmt.Sprintf("classifier %s: %s%.2f", q.ID, a.Choice, a.Noul+a.Score)
	}
	t, err := template.New(q.ID).Funcs(funcs).Parse(q.Explain)
	if err != nil {
		return q.Explain
	}
	var sb strings.Builder
	if err := t.Execute(&sb, a); err != nil {
		return q.Explain
	}
	return sb.String()
}

func (q Question) validate() error {
	if q.ID == "" {
		return errors.New("question without id")
	}
	if len(q.On) == 0 {
		return fmt.Errorf("question %s: no event kinds", q.ID)
	}
	switch q.Type {
	case "noul":
		if q.AskAbove <= 0 || q.AskAbove > 1 {
			return fmt.Errorf("question %s: ask_above must be in (0, 1]", q.ID)
		}
	case "choice":
		if len(q.AskOn) == 0 {
			return fmt.Errorf("question %s: ask_on is required for choice", q.ID)
		}
	case "score":
		if q.AskAbove <= 0 {
			return fmt.Errorf("question %s: ask_above (level index) is required for score", q.ID)
		}
	default:
		return fmt.Errorf("question %s: type %q is not noul, choice or score", q.ID, q.Type)
	}
	if q.Instructions == "" {
		return fmt.Errorf("question %s: instructions are required", q.ID)
	}
	if q.Explain != "" {
		if _, err := template.New(q.ID).Funcs(funcs).Parse(q.Explain); err != nil {
			return fmt.Errorf("question %s: explain: %w", q.ID, err)
		}
	}
	return nil
}

func ParseQuestions(raw []byte) ([]Question, error) {
	var list []Question
	if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, q := range list {
		list[i].Criteria = stringKeys(q.Criteria)
		if err := q.validate(); err != nil {
			return nil, err
		}
		if seen[q.ID] {
			return nil, fmt.Errorf("duplicate question id %s", q.ID)
		}
		seen[q.ID] = true
	}
	return list, nil
}

// stringKeys turns YAML's {true: ..., false: ...} and other non-string map keys into strings,
// which JSON needs.
func stringKeys(v any) any {
	switch m := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = stringKeys(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = stringKeys(val)
		}
		return out
	case []any:
		out := make([]any, len(m))
		for i, val := range m {
			out[i] = stringKeys(val)
		}
		return out
	}
	return v
}

func LoadQuestions(path string) ([]Question, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseQuestions(raw)
}

// Gate turns questions into rules with no actions, so the rules engine decides when a question
// applies, with the same variables, stages and repeat suppression.
func Gate(questions []Question) []rules.Rule {
	out := make([]rules.Rule, 0, len(questions))
	for _, q := range questions {
		out = append(out, rules.Rule{ID: q.RuleID(), Threat: q.Threat, On: q.On, When: q.When, Confidence: rules.Possible, Actions: []rules.Action{rules.AskAction, rules.Alert}})
	}
	return out
}

type Answer struct {
	Type          string          `json:"type"`
	Noul          float64         `json:"noul,omitempty"`
	Choice        string          `json:"choice,omitempty"`
	Score         float64         `json:"score,omitempty"`
	Probabilities json.RawMessage `json:"probabilities,omitempty"`
	Confidence    float64         `json:"confidence,omitempty"`
}

// Outcome is what a question's answer means for the event.
type Outcome struct {
	Ask  bool
	Deny bool
}

func (q Question) Judge(a Answer) Outcome {
	switch q.Type {
	case "noul":
		return Outcome{Ask: a.Noul >= q.AskAbove, Deny: q.DenyAbove > 0 && a.Noul >= q.DenyAbove}
	case "score":
		return Outcome{Ask: a.Score >= q.AskAbove, Deny: q.DenyAbove > 0 && a.Score >= q.DenyAbove}
	case "choice":
		return Outcome{Ask: contains(q.AskOn, a.Choice), Deny: contains(q.DenyOn, a.Choice)}
	}
	return Outcome{}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type Client struct {
	URL     string
	Model   string
	Key     string
	Timeout time.Duration
	HTTP    *http.Client
}

func (c *Client) Enabled() bool { return c != nil && c.URL != "" }

type request struct {
	State     any                        `json:"state"`
	Model     string                     `json:"model,omitempty"`
	Questions map[string]requestQuestion `json:"questions"`
}

type requestQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions,omitempty"`
	Criteria     any    `json:"criteria,omitempty"`
}

type response struct {
	Answers   map[string]Answer `json:"answers"`
	LatencyMS float64           `json:"latency_ms"`
	Error     any               `json:"error,omitempty"`
	Detail    any               `json:"detail,omitempty"`
}

// Ask sends one state with every question at once and returns the answers keyed by question id.
func (c *Client) Ask(ctx context.Context, state any, questions []Question) (map[string]Answer, error) {
	if !c.Enabled() {
		return nil, errors.New("classifier disabled")
	}
	req := request{State: state, Model: c.Model, Questions: map[string]requestQuestion{}}
	for _, q := range questions {
		req.Questions[q.ID] = requestQuestion{Type: q.Type, Instructions: q.Instructions, Criteria: q.Criteria}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+"/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "overlord/1.0")
	if c.Key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Key)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("classifier: %s: %w", resp.Status, err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("classifier: %s: %v%v", resp.Status, out.Error, out.Detail)
	}
	return out.Answers, nil
}
