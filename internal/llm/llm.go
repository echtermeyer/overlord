// Package llm asks a model to explain an ask and, for agent tool calls only, to raise it to a
// deny. It can never allow: a model's "fine" changes nothing.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Case struct {
	Rule      string           `json:"rule"`
	Explain   string           `json:"explain"`
	Process   map[string]any   `json:"process"`
	Ancestors []map[string]any `json:"ancestors,omitempty"`
	Reads     []string         `json:"reads,omitempty"`
	Outbound  []string         `json:"outbound,omitempty"`
	Call      map[string]any   `json:"call,omitempty"`
	Calls     []string         `json:"recent_calls,omitempty"`
}

type Result struct {
	Explanation string `json:"explanation"`
	Verdict     string `json:"verdict"` // keep | deny
}

type Explainer struct {
	Provider string
	Model    string
	URL      string
	Key      string
	Timeout  time.Duration
	Client   *http.Client
}

const system = `You are the explainer inside Overlord, a security daemon on a developer's Mac. You get one
suspicious event with its process context. Answer with JSON only: {"explanation": "...", "verdict": "keep"|"deny"}.
"explanation" is one or two plain sentences for the person at the keyboard: what happened and why it looks risky
or harmless. "verdict" is "deny" only when the evidence clearly shows data leaving the machine, credentials being
collected, persistence being installed, or protections being switched off; otherwise "keep". You cannot allow
anything; "keep" leaves the decision to the person.`

func (e *Explainer) Enabled() bool { return e != nil && e.Provider != "" && e.Provider != "none" }

func (e *Explainer) Explain(ctx context.Context, c Case) (Result, error) {
	if !e.Enabled() {
		return Result{}, errors.New("llm disabled")
	}
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	payload, err := json.Marshal(c)
	if err != nil {
		return Result{}, err
	}
	var text string
	switch e.Provider {
	case "ollama":
		text, err = e.ollama(ctx, string(payload))
	case "anthropic":
		text, err = e.anthropic(ctx, string(payload))
	default:
		return Result{}, fmt.Errorf("unknown provider %q", e.Provider)
	}
	if err != nil {
		return Result{}, err
	}
	return parse(text)
}

func parse(text string) (Result, error) {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return Result{}, fmt.Errorf("no JSON in model answer: %q", text)
	}
	var r Result
	if err := json.Unmarshal([]byte(text[start:end+1]), &r); err != nil {
		return Result{}, err
	}
	if r.Verdict != "deny" {
		r.Verdict = "keep"
	}
	return r, nil
}

func (e *Explainer) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	return http.DefaultClient
}

func (e *Explainer) ollama(ctx context.Context, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":  e.Model,
		"stream": false,
		"format": "json",
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(e.URL, "/")+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Message.Content, nil
}

func (e *Explainer) anthropic(ctx context.Context, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":      e.Model,
		"max_tokens": 300,
		"system":     system,
		"messages":   []map[string]string{{"role": "user", "content": user}},
	})
	url := e.URL
	if url == "" {
		url = "https://api.anthropic.com/v1/messages"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", e.Key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("User-Agent", "overlord/1.0")
	resp, err := e.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", errors.New(out.Error.Message)
	}
	var sb strings.Builder
	for _, c := range out.Content {
		sb.WriteString(c.Text)
	}
	return sb.String(), nil
}
