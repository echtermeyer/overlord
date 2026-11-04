package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Install wires the hook into an agent's per-user settings without touching anything else in
// the file. Running it twice changes nothing.
func Install(agent, binary string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	command := binary + " hook " + agent
	switch agent {
	case "claude":
		path := filepath.Join(home, ".claude", "settings.json")
		return path, patch(path, func(root map[string]any) {
			hooks := child(root, "hooks")
			for _, event := range []string{"PreToolUse", "PostToolUse"} {
				entry := map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": command, "timeout": 10}}}
				hooks[event] = appendUnique(hooks[event], entry, command)
			}
		})
	case "cursor":
		path := filepath.Join(home, ".cursor", "hooks.json")
		return path, patch(path, func(root map[string]any) {
			root["version"] = 1
			hooks := child(root, "hooks")
			for _, event := range []string{"beforeShellExecution", "beforeReadFile", "beforeMCPExecution"} {
				hooks[event] = appendUnique(hooks[event], map[string]any{"command": command}, command)
			}
		})
	case "gemini":
		path := filepath.Join(home, ".gemini", "settings.json")
		return path, patch(path, func(root map[string]any) {
			hooks := child(root, "hooks")
			for _, event := range []string{"BeforeTool", "AfterTool"} {
				entry := map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": command}}}
				hooks[event] = appendUnique(hooks[event], entry, command)
			}
		})
	}
	return "", fmt.Errorf("no installer for agent %q", agent)
}

func child(root map[string]any, key string) map[string]any {
	m, ok := root[key].(map[string]any)
	if !ok {
		m = map[string]any{}
		root[key] = m
	}
	return m
}

func appendUnique(existing any, entry map[string]any, command string) []any {
	list, _ := existing.([]any)
	raw, _ := json.Marshal(list)
	if containsCommand(raw, command) {
		return list
	}
	return append(list, entry)
}

func containsCommand(raw []byte, command string) bool {
	quoted, _ := json.Marshal(command)
	return len(raw) > 0 && len(quoted) > 0 && indexOf(raw, quoted) >= 0
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func patch(path string, edit func(root map[string]any)) error {
	root := map[string]any{}
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	edit(root)
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}
