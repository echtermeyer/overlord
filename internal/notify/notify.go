// Package notify carries asks to the person at the keyboard and alerts to a webhook.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Ask is one question for the person. Options are the buttons; Answer is what they chose.
type Ask struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Text     string    `json:"text"`
	Rule     string    `json:"rule"`
	Process  string    `json:"process,omitempty"`
	PID      int       `json:"pid,omitempty"`
	Chain    []string  `json:"chain,omitempty"`
	Options  []string  `json:"options"`
	Deadline time.Time `json:"deadline"`
}

type Answer struct {
	ID     string `json:"id"`
	Choice string `json:"choice"`
	UID    int    `json:"uid,omitempty"`
}

const (
	Block       = "Block"
	AllowOnce   = "Allow once"
	AllowAlways = "Allow always"
)

// Dialog shows the ask with osascript in the logged-in user's session and returns the button.
func Dialog(ctx context.Context, a Ask) (string, error) {
	body := a.Text
	if len(a.Chain) > 0 {
		body += "\n\nProcess chain: " + strings.Join(a.Chain, " → ")
	}
	buttons := make([]string, 0, len(a.Options))
	for _, o := range a.Options {
		buttons = append(buttons, quote(o))
	}
	timeout := int(time.Until(a.Deadline).Seconds())
	if timeout < 5 {
		timeout = 5
	}
	script := fmt.Sprintf(`display dialog %s with title %s buttons {%s} default button %s cancel button %s with icon caution giving up after %d`,
		quote(body), quote(a.Title), strings.Join(buttons, ", "), quote(a.Options[0]), quote(a.Options[0]), timeout)
	out, err := exec.CommandContext(ctx, "osascript", "-e", script, "-e", "button returned of result").Output()
	if err != nil {
		// Cancel and time-out both come back as an error from osascript; both mean Block.
		return a.Options[0], nil
	}
	choice := strings.TrimSpace(string(out))
	for _, o := range a.Options {
		if o == choice {
			return o, nil
		}
	}
	return a.Options[0], nil
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Webhook posts a Slack-compatible {"text": ...} JSON message.
type Webhook struct {
	URL    string
	Token  string
	Client *http.Client
}

func (w Webhook) Send(ctx context.Context, text string) error {
	if w.URL == "" {
		return nil
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "overlord/1.0")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: %s", resp.Status)
	}
	return nil
}
