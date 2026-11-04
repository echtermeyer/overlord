package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallClaudeIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	settings := filepath.Join(home, ".claude", "settings.json")
	_ = os.MkdirAll(filepath.Dir(settings), 0o755)
	_ = os.WriteFile(settings, []byte(`{"permissions":{"allow":["Bash(ls)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other"}]}]}}`), 0o600)
	for i := 0; i < 2; i++ {
		if _, err := Install("claude", "/usr/local/bin/overlord"); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(settings)
	var root map[string]any
	_ = json.Unmarshal(raw, &root)
	if _, ok := root["permissions"]; !ok {
		t.Error("existing keys lost")
	}
	hooks := root["hooks"].(map[string]any)
	if len(hooks["PreToolUse"].([]any)) != 2 || len(hooks["PostToolUse"].([]any)) != 1 {
		t.Errorf("hooks: %s", raw)
	}
	if strings.Count(string(raw), "overlord hook claude") != 2 {
		t.Errorf("command count: %s", raw)
	}
}

func TestInstallCursorAndGemini(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, agent := range []string{"cursor", "gemini"} {
		path, err := Install(agent, "/x/overlord")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		if !strings.Contains(string(raw), "/x/overlord hook "+agent) {
			t.Errorf("%s: %s", agent, raw)
		}
	}
	if _, err := Install("codex", "/x"); err == nil {
		t.Error("unknown agent accepted")
	}
}
