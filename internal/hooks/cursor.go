package hooks

import (
	"encoding/json"
	"fmt"
)

// cursor speaks Cursor's hooks.json protocol (beforeShellExecution, beforeReadFile,
// beforeMCPExecution): JSON in, {"permission": allow|deny|ask} out.
type cursor struct{}

func (cursor) Name() string { return "cursor" }

func (cursor) Parse(stdin []byte) (Call, error) {
	var in struct {
		ConversationID string   `json:"conversation_id"`
		HookEventName  string   `json:"hook_event_name"`
		WorkspaceRoots []string `json:"workspace_roots"`
		Command        string   `json:"command"`
		CWD            string   `json:"cwd"`
		FilePath       string   `json:"file_path"`
		ToolName       string   `json:"tool_name"`
		ToolInput      string   `json:"tool_input"`
		URL            string   `json:"url"`
	}
	if err := json.Unmarshal(stdin, &in); err != nil {
		return Call{}, fmt.Errorf("cursor hook input: %w", err)
	}
	cwd := in.CWD
	if cwd == "" && len(in.WorkspaceRoots) > 0 {
		cwd = in.WorkspaceRoots[0]
	}
	c := Call{Phase: "pre"}
	switch in.HookEventName {
	case "beforeShellExecution":
		c.Info = normalize("Bash", map[string]any{"command": in.Command}, cwd)
	case "beforeReadFile":
		c.Info = normalize("Read", map[string]any{"file_path": in.FilePath}, cwd)
	case "beforeMCPExecution":
		c.Info = normalize("mcp:"+in.ToolName, map[string]any{"command": in.ToolInput}, cwd)
	case "afterFileEdit":
		c.Phase = "post"
		c.Info = normalize("Edit", map[string]any{"file_path": in.FilePath}, cwd)
	default:
		c.Phase = "other"
		c.Info = normalize(in.HookEventName, nil, cwd)
	}
	c.Info.Session = in.ConversationID
	if len(in.WorkspaceRoots) > 0 {
		c.Info.Project = in.WorkspaceRoots[0]
	}
	return c, nil
}

func (cursor) Render(c Call, d Decision) ([]byte, int) {
	if c.Phase != "pre" {
		return nil, 0
	}
	out := map[string]any{"permission": string(d.Permission)}
	if d.Permission != Allow {
		out["user_message"] = "Overlord (" + joinRules(d.Rules) + "): " + d.Reason
		out["agent_message"] = "Overlord blocked or held this call: " + d.Reason
	}
	return mustJSON(out), 0
}
