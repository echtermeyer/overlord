package hooks

import (
	"encoding/json"
	"fmt"
)

// gemini speaks Gemini CLI's BeforeTool / AfterTool hook protocol. Its decision field mirrors
// Claude Code's older "decision"/"reason" shape.
type gemini struct{}

func (gemini) Name() string { return "gemini" }

func (gemini) Parse(stdin []byte) (Call, error) {
	var in struct {
		SessionID     string         `json:"session_id"`
		CWD           string         `json:"cwd"`
		HookEventName string         `json:"hook_event_name"`
		ToolName      string         `json:"tool_name"`
		ToolInput     map[string]any `json:"tool_input"`
	}
	if err := json.Unmarshal(stdin, &in); err != nil {
		return Call{}, fmt.Errorf("gemini hook input: %w", err)
	}
	tool := in.ToolName
	switch tool {
	case "run_shell_command":
		tool = "Bash"
	case "read_file", "read_many_files":
		tool = "Read"
	case "write_file":
		tool = "Write"
	case "replace", "edit":
		tool = "Edit"
	}
	c := Call{Info: normalize(tool, in.ToolInput, in.CWD)}
	c.Info.Session = in.SessionID
	switch in.HookEventName {
	case "BeforeTool":
		c.Phase = "pre"
	case "AfterTool":
		c.Phase = "post"
	default:
		c.Phase = "other"
	}
	return c, nil
}

func (gemini) Render(c Call, d Decision) ([]byte, int) {
	if c.Phase != "pre" || d.Permission == Allow {
		return nil, 0
	}
	decision := "deny"
	if d.Permission == Ask {
		decision = "ask"
	}
	return mustJSON(map[string]any{
		"decision": decision,
		"reason":   "Overlord (" + joinRules(d.Rules) + "): " + d.Reason,
	}), 0
}
