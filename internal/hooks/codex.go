package hooks

import "fmt"

// codex speaks OpenAI Codex CLI's hooks: the same stdin and hookSpecificOutput shape as Claude
// Code, but "ask" is not supported, so an ask becomes a deny with the reason.
type codex struct{}

func (codex) Name() string { return "codex" }

func (codex) Parse(stdin []byte) (Call, error) {
	c, err := claude{}.Parse(stdin)
	if err != nil {
		return Call{}, fmt.Errorf("codex hook input: %w", err)
	}
	if c.Info.Tool == "apply_patch" {
		c.Info.Tool = "Edit"
	}
	return c, nil
}

func (codex) Render(c Call, d Decision) ([]byte, int) {
	if d.Permission == Ask {
		d.Permission = Deny
	}
	return claude{}.Render(c, d)
}
