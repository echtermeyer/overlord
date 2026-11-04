// Package hooks adapts the agents' hook interfaces to one tool-call shape and back. The hook
// binary embeds the certain rules, so the worst calls are denied even while the daemon is down.
package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	overlord "github.com/echtermeyer/overlord"
	"github.com/echtermeyer/overlord/internal/events"
	"github.com/echtermeyer/overlord/internal/graph"
	"github.com/echtermeyer/overlord/internal/ipc"
	"github.com/echtermeyer/overlord/internal/rules"
)

type Permission string

const (
	Allow Permission = "allow"
	Ask   Permission = "ask"
	Deny  Permission = "deny"
)

type Decision struct {
	Permission Permission `json:"permission"`
	Reason     string     `json:"reason,omitempty"`
	Rules      []string   `json:"rules,omitempty"`
}

// Merge keeps the stricter decision.
func Merge(a, b Decision) Decision {
	rank := map[Permission]int{Allow: 0, Ask: 1, Deny: 2}
	out := a
	if rank[b.Permission] > rank[a.Permission] {
		out = b
	}
	out.Rules = append(append([]string{}, a.Rules...), b.Rules...)
	if out.Reason == "" {
		out.Reason = a.Reason + b.Reason
	}
	return out
}

// Call is what the hook sends the daemon: the normalized tool call and its phase.
type Call struct {
	Phase string              `json:"phase"` // pre | post
	Info  events.ToolCallInfo `json:"info"`
	Error string              `json:"error,omitempty"` // post only: the tool's failure text
}

type Adapter interface {
	Name() string
	Parse(stdin []byte) (Call, error)
	Render(c Call, d Decision) (stdout []byte, exit int)
}

var adapters = map[string]Adapter{
	"claude": claude{},
	"cursor": cursor{},
	"gemini": gemini{},
}

func Adapters() []string {
	out := make([]string, 0, len(adapters))
	for name := range adapters {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func Get(name string) (Adapter, error) {
	a, ok := adapters[name]
	if !ok {
		return nil, fmt.Errorf("unknown agent %q; known: %s", name, strings.Join(Adapters(), ", "))
	}
	return a, nil
}

// Embedded evaluates the certain rules without a daemon. Allowlists and graph context are
// absent, so only rules that need nothing but the call itself can fire.
type Embedded struct {
	engine *rules.Engine
}

type noContext struct{ table *graph.PathTable }

func (noContext) Reads(string, time.Duration) []graph.Read        { return nil }
func (noContext) Outbound(string, time.Duration) []graph.Dest     { return nil }
func (noContext) SessionReads(string, time.Duration) []graph.Read { return nil }
func (noContext) InAllowlist(string, string) bool                 { return false }
func (n noContext) Category(path string) string                   { return n.table.Match(path) }

func NewEmbedded() (*Embedded, error) {
	raw, err := overlord.Files.ReadFile("rules/sensitive_paths.yaml")
	if err != nil {
		return nil, err
	}
	table, err := graph.ParsePathTable(raw)
	if err != nil {
		return nil, err
	}
	raw, err = overlord.Files.ReadFile("rules/agent.yaml")
	if err != nil {
		return nil, err
	}
	list, err := rules.ParseRules(raw)
	if err != nil {
		return nil, err
	}
	var certain []rules.Rule
	for _, r := range list {
		if r.Confidence == rules.Certain {
			certain = append(certain, r)
		}
	}
	engine, err := rules.New(noContext{table: table}, certain, rules.Policy{DefaultStage: rules.Enforce}, 0)
	if err != nil {
		return nil, err
	}
	return &Embedded{engine: engine}, nil
}

func (e *Embedded) Decide(info events.ToolCallInfo) Decision {
	ev := &events.Event{Kind: events.ToolCall, At: time.Now(), Source: "hook", Call: &info}
	verdicts, err := e.engine.Evaluate(rules.Input{Event: ev})
	if err != nil {
		return Decision{Permission: Allow}
	}
	return FromVerdicts(verdicts)
}

// FromVerdicts turns verdicts into one decision: deny beats ask beats allow.
func FromVerdicts(verdicts []rules.Verdict) Decision {
	d := Decision{Permission: Allow}
	for _, v := range verdicts {
		next := Decision{Permission: Allow, Rules: []string{v.RuleID}}
		switch {
		case v.Has(rules.Deny):
			next.Permission = Deny
			next.Reason = v.Explain
		case v.Has(rules.AskAction):
			next.Permission = Ask
			next.Reason = v.Explain
		}
		d = Merge(d, next)
	}
	return d
}

// Run is the hook entry point: parse stdin, decide locally, ask the daemon, print the answer.
func Run(agent string, stdin []byte, socket string, timeout time.Duration) ([]byte, int, error) {
	adapter, err := Get(agent)
	if err != nil {
		return nil, 1, err
	}
	call, err := adapter.Parse(stdin)
	if err != nil {
		return nil, 1, err
	}
	call.Info.Agent = agent
	if call.Info.AgentPID == 0 {
		call.Info.AgentPID = os.Getppid()
	}
	decision := Decision{Permission: Allow}
	if call.Phase == "pre" {
		embedded, err := NewEmbedded()
		if err != nil {
			return nil, 1, err
		}
		decision = embedded.Decide(call.Info)
	}
	var fromDaemon Decision
	client := ipc.Client{Path: socket, Timeout: timeout}
	if err := client.Call("tool_call", call, &fromDaemon); err == nil {
		decision = Merge(decision, fromDaemon)
	}
	out, exit := adapter.Render(call, decision)
	return out, exit, nil
}

func project(cwd string) string {
	dir := cwd
	for dir != "/" && dir != "." && dir != "" {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return cwd
}

func stringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func normalize(tool string, input map[string]any, cwd string) events.ToolCallInfo {
	info := events.ToolCallInfo{Tool: tool, CWD: cwd, Project: project(cwd), Input: input}
	switch tool {
	case "Bash":
		info.Command = stringField(input, "command")
	case "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "LS":
		if p := stringField(input, "file_path", "notebook_path", "path"); p != "" {
			info.Paths = []string{absolute(p, cwd)}
		}
	default:
		if p := stringField(input, "file_path", "path"); p != "" {
			info.Paths = []string{absolute(p, cwd)}
		}
		if c := stringField(input, "command"); c != "" {
			info.Command = c
		}
	}
	return info
}

func absolute(p, cwd string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(cwd, p)
}

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
