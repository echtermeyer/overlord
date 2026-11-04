package hooks

import (
	"encoding/json"
	"fmt"
)

// claude speaks Claude Code's hook protocol: JSON on stdin, JSON on stdout with
// hookSpecificOutput.permissionDecision for PreToolUse.
type claude struct{}

func (claude) Name() string { return "claude" }

func (claude) Parse(stdin []byte) (Call, error) {
	var in struct {
		SessionID      string         `json:"session_id"`
		TranscriptPath string         `json:"transcript_path"`
		CWD            string         `json:"cwd"`
		HookEventName  string         `json:"hook_event_name"`
		ToolName       string         `json:"tool_name"`
		ToolInput      map[string]any `json:"tool_input"`
		ToolResponse   any            `json:"tool_response"`
	}
	if err := json.Unmarshal(stdin, &in); err != nil {
		return Call{}, fmt.Errorf("claude hook input: %w", err)
	}
	c := Call{Info: normalize(in.ToolName, in.ToolInput, in.CWD)}
	c.Info.Session = in.SessionID
	c.Info.Transcript = in.TranscriptPath
	switch in.HookEventName {
	case "PreToolUse":
		c.Phase = "pre"
	case "PostToolUse":
		c.Phase = "post"
	case "PostToolUseFailure":
		c.Phase = "post"
		c.Error = fmt.Sprint(in.ToolResponse)
	default:
		c.Phase = "other"
		c.Info.Tool = in.HookEventName
	}
	return c, nil
}

func (claude) Render(c Call, d Decision) ([]byte, int) {
	if c.Phase != "pre" || d.Permission == Allow {
		return nil, 0
	}
	reason := d.Reason
	if reason == "" {
		reason = "Overlord: this call needs a person's decision."
	}
	return mustJSON(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       string(d.Permission),
			"permissionDecisionReason": "Overlord (" + joinRules(d.Rules) + "): " + reason,
		},
	}), 0
}

func joinRules(rules []string) string {
	seen := map[string]bool{}
	out := ""
	for _, r := range rules {
		if seen[r] {
			continue
		}
		seen[r] = true
		if out != "" {
			out += ", "
		}
		out += r
	}
	return out
}
