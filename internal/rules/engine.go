package rules

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"

	"github.com/echtermeyer/overlord/internal/events"
	"github.com/echtermeyer/overlord/internal/graph"
)

// Context is what rules may ask the graph while they evaluate.
type Context interface {
	Reads(processKey string, within time.Duration) []graph.Read
	Outbound(processKey string, within time.Duration) []graph.Dest
	SessionReads(sessionID string, within time.Duration) []graph.Read
	InAllowlist(processKey, list string) bool
	Category(path string) string
}

type Input struct {
	Event     *events.Event
	Process   *graph.Node
	Ancestors []*graph.Node
	Target    *graph.Node
	Session   *graph.Session
}

type compiled struct {
	rule     Rule
	when     cel.Program
	escalate cel.Program
	explain  *template.Template
	kinds    map[events.Kind]bool
}

type Engine struct {
	ctx    Context
	policy Policy
	rules  []*compiled
	repeat time.Duration
	mu     sync.Mutex
	fired  map[string]time.Time
	now    func() time.Time
}

// New compiles the rules. repeat is how long one rule stays quiet for one process after firing.
func New(ctx Context, rules []Rule, policy Policy, repeat time.Duration) (*Engine, error) {
	e := &Engine{ctx: ctx, policy: policy, repeat: repeat, fired: map[string]time.Time{}, now: time.Now}
	env, err := e.env()
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		c := &compiled{rule: r, kinds: map[events.Kind]bool{}}
		for _, k := range r.On {
			c.kinds[k] = true
		}
		if r.When != "" {
			if c.when, err = compile(env, r.ID, r.When); err != nil {
				return nil, err
			}
		}
		if r.EscalateWhen != "" {
			if c.escalate, err = compile(env, r.ID, r.EscalateWhen); err != nil {
				return nil, err
			}
		}
		if r.Explain != "" {
			c.explain, err = template.New(r.ID).Option("missingkey=zero").Parse(r.Explain)
			if err != nil {
				return nil, fmt.Errorf("rule %s explain: %w", r.ID, err)
			}
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

func (e *Engine) SetClock(now func() time.Time) { e.now = now }

func (e *Engine) Rules() []Rule {
	out := make([]Rule, 0, len(e.rules))
	for _, c := range e.rules {
		out = append(out, c.rule)
	}
	return out
}

func compile(env *cel.Env, id, expr string) (cel.Program, error) {
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("rule %s: %w", id, issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("rule %s: condition is %s, not bool", id, ast.OutputType())
	}
	return env.Program(ast)
}

var mapType = cel.MapType(cel.StringType, cel.DynType)

func (e *Engine) env() (*cel.Env, error) {
	return cel.NewEnv(
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
		cel.Variable("event", mapType),
		cel.Variable("process", mapType),
		cel.Variable("target", mapType),
		cel.Variable("call", mapType),
		cel.Variable("session", mapType),
		cel.Variable("dest", mapType),
		cel.Variable("path", cel.StringType),
		cel.Function("tag",
			cel.MemberOverload("map_tag", []*cel.Type{mapType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(m, name ref.Val) ref.Val {
					tags, _ := lookup(m, "tags").(map[string]string)
					return types.String(tags[string(name.(types.String))])
				}))),
		cel.Function("reads",
			cel.MemberOverload("map_reads", []*cel.Type{mapType, cel.StringType}, cel.ListType(cel.DynType),
				cel.BinaryBinding(func(m, within ref.Val) ref.Val {
					return toCEL(readMaps(e.reads(m, within)))
				}))),
		cel.Function("readCategories",
			cel.MemberOverload("map_read_categories", []*cel.Type{mapType, cel.StringType}, cel.ListType(cel.StringType),
				cel.BinaryBinding(func(m, within ref.Val) ref.Val {
					return toCEL(categories(e.reads(m, within)))
				}))),
		cel.Function("outbound",
			cel.MemberOverload("map_outbound", []*cel.Type{mapType, cel.StringType}, cel.ListType(cel.DynType),
				cel.BinaryBinding(func(m, within ref.Val) ref.Val {
					key, _ := lookup(m, "key").(string)
					var out []map[string]any
					for _, d := range e.ctx.Outbound(key, duration(within)) {
						out = append(out, map[string]any{"address": d.Address, "port": d.Port, "seenBefore": d.SeenBefore})
					}
					return toCEL(out)
				}))),
		cel.Function("inAllowlist",
			cel.MemberOverload("map_in_allowlist", []*cel.Type{mapType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(m, list ref.Val) ref.Val {
					key, _ := lookup(m, "key").(string)
					return types.Bool(e.ctx.InAllowlist(key, string(list.(types.String))))
				}))),
		cel.Function("category",
			cel.MemberOverload("string_category", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					return types.String(e.ctx.Category(string(s.(types.String))))
				}))),
		cel.Function("matchesAny",
			cel.MemberOverload("string_matches_any", []*cel.Type{cel.StringType, cel.ListType(cel.StringType)}, cel.BoolType,
				cel.BinaryBinding(func(s, list ref.Val) ref.Val {
					var patterns []string
					it := list.(traits.Lister).Iterator()
					for it.HasNext() == types.True {
						patterns = append(patterns, string(it.Next().(types.String)))
					}
					return types.Bool(graph.MatchAny(string(s.(types.String)), patterns))
				}))),
	)
}

func (e *Engine) reads(m, within ref.Val) []graph.Read {
	if key, ok := lookup(m, "key").(string); ok && key != "" {
		return e.ctx.Reads(key, duration(within))
	}
	if id, ok := lookup(m, "id").(string); ok && id != "" {
		return e.ctx.SessionReads(id, duration(within))
	}
	return nil
}

func lookup(m ref.Val, key string) any {
	mapper, ok := m.(traits.Mapper)
	if !ok {
		return nil
	}
	v, found := mapper.Find(types.String(key))
	if !found {
		return nil
	}
	return v.Value()
}

func duration(v ref.Val) time.Duration {
	d, err := time.ParseDuration(string(v.(types.String)))
	if err != nil {
		return 0
	}
	return d
}

func toCEL(v any) ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(v)
}

func readMaps(reads []graph.Read) []map[string]any {
	out := make([]map[string]any, 0, len(reads))
	for _, r := range reads {
		out = append(out, map[string]any{"path": r.Path, "category": r.Category})
	}
	return out
}

func categories(reads []graph.Read) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reads {
		if !seen[r.Category] {
			seen[r.Category] = true
			out = append(out, r.Category)
		}
	}
	return out
}

// Evaluate runs every rule that listens to the event's kind and returns the verdicts, including
// shadow ones with no permitted actions so the log and the label store see them.
func (e *Engine) Evaluate(in Input) ([]Verdict, error) {
	if in.Event == nil {
		return nil, nil
	}
	act := activation(in)
	var out []Verdict
	for _, c := range e.rules {
		if !c.kinds[in.Event.Kind] {
			continue
		}
		hit, err := eval(c.when, act)
		if err != nil {
			return out, fmt.Errorf("rule %s: %w", c.rule.ID, err)
		}
		if !hit {
			continue
		}
		escalated := false
		if c.escalate != nil {
			if escalated, err = eval(c.escalate, act); err != nil {
				return out, fmt.Errorf("rule %s escalate: %w", c.rule.ID, err)
			}
		}
		if !e.shouldFire(c.rule.ID, processKey(in), escalated) {
			continue
		}
		requested := c.rule.Actions
		if escalated {
			requested = c.rule.EscalateActions
		}
		stage := e.policy.Stage(c.rule.ID)
		v := Verdict{
			RuleID:     c.rule.ID,
			Threat:     c.rule.Threat,
			Stage:      stage,
			Confidence: c.rule.Confidence,
			Escalated:  escalated,
			Requested:  sortedActions(requested),
			Actions:    permitted(stage, c.rule.Confidence, escalated, sortedActions(requested)),
			At:         e.now(),
		}
		if c.explain != nil {
			var buf bytes.Buffer
			if err := c.explain.Execute(&buf, act); err == nil {
				v.Explain = buf.String()
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func eval(p cel.Program, act map[string]any) (bool, error) {
	if p == nil {
		return true, nil
	}
	v, _, err := p.Eval(act)
	if err != nil {
		if strings.Contains(err.Error(), "no such key") {
			return false, nil
		}
		return false, err
	}
	b, ok := v.(types.Bool)
	return ok && bool(b), nil
}

func (e *Engine) shouldFire(rule, key string, escalated bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	id := rule + "|" + key
	if escalated {
		id += "|escalated"
	}
	now := e.now()
	if last, ok := e.fired[id]; ok && now.Sub(last) < e.repeat {
		return false
	}
	e.fired[id] = now
	if len(e.fired) > 10000 {
		for k, t := range e.fired {
			if now.Sub(t) >= e.repeat {
				delete(e.fired, k)
			}
		}
	}
	return true
}

func processKey(in Input) string {
	if in.Process != nil {
		return in.Process.Key
	}
	if in.Event.Call != nil {
		return in.Event.Call.Session
	}
	return ""
}

func activation(in Input) map[string]any {
	ev := in.Event
	act := map[string]any{
		"event":   eventMap(ev),
		"process": ProcessMap(in.Process, in.Ancestors),
		"target":  ProcessMap(in.Target, nil),
		"call":    callMap(ev.Call),
		"session": sessionMap(in.Session, ev.Call),
		"dest":    map[string]any{},
		"path":    ev.Path,
	}
	if ev.Dest != nil {
		act["dest"] = map[string]any{"address": ev.Dest.Address, "port": ev.Dest.Port, "seenBefore": ev.Dest.SeenBefore}
	}
	return act
}

func eventMap(ev *events.Event) map[string]any {
	m := map[string]any{
		"kind":       string(ev.Kind),
		"path":       ev.Path,
		"destPath":   ev.DestPath,
		"write":      ev.Write,
		"detail":     map[string]string{},
		"exitStatus": ev.ExitStatus,
	}
	if ev.Detail != nil {
		m["detail"] = ev.Detail
	}
	if ev.LaunchItem != nil {
		m["launchItem"] = map[string]any{
			"type": ev.LaunchItem.Type, "itemURL": ev.LaunchItem.ItemURL,
			"executable": ev.LaunchItem.Executable, "legacy": ev.LaunchItem.Legacy,
		}
	}
	return m
}

// ProcessMap is the shape rules see as `process` and `target`.
func ProcessMap(n *graph.Node, ancestors []*graph.Node) map[string]any {
	if n == nil {
		return map[string]any{"key": "", "name": "", "path": "", "cmdline": "", "trusted": false, "untrustedChain": false, "firstSeen": false, "tags": map[string]string{}, "args": []string{}, "ancestors": []map[string]any{}}
	}
	chain := make([]map[string]any, 0, len(ancestors))
	// untrustedChain: the process or an ancestor below the terminal or editor is not trusted,
	// so "something unknown started this", however many shells sit in between.
	untrustedChain := !n.Trusted && n.Tags["terminal"] == "" && n.Tags["editor"] == ""
	for _, a := range ancestors {
		chain = append(chain, map[string]any{"name": a.Name(), "path": a.Path, "pid": a.PID, "tags": a.Tags, "trusted": a.Trusted})
		if a.Tags["terminal"] != "" || a.Tags["editor"] != "" {
			break
		}
		if !a.Trusted {
			untrustedChain = true
		}
	}
	args := n.Args
	if args == nil {
		args = []string{}
	}
	return map[string]any{
		"key":            n.Key,
		"pid":            n.PID,
		"name":           n.Name(),
		"path":           n.Path,
		"args":           args,
		"cmdline":        strings.Join(args, " "),
		"cwd":            n.CWD,
		"uid":            n.UID,
		"signingId":      n.SigningID,
		"teamId":         n.TeamID,
		"cdhash":         n.CDHash,
		"platform":       n.Platform,
		"trusted":        n.Trusted,
		"firstSeen":      n.FirstSeen,
		"untrustedChain": untrustedChain,
		"tty":            n.TTY,
		"tags":           n.Tags,
		"ancestors":      chain,
		"persistence":    len(n.Persistence),
	}
}

func callMap(c *events.ToolCallInfo) map[string]any {
	if c == nil {
		return map[string]any{"tool": "", "command": "", "paths": []string{}, "agent": "", "session": "", "cwd": ""}
	}
	paths := c.Paths
	if paths == nil {
		paths = []string{}
	}
	return map[string]any{
		"agent":   c.Agent,
		"session": c.Session,
		"tool":    c.Tool,
		"command": c.Command,
		"paths":   paths,
		"cwd":     c.CWD,
		"project": c.Project,
	}
}

func sessionMap(s *graph.Session, c *events.ToolCallInfo) map[string]any {
	m := map[string]any{"id": "", "agent": "", "project": "", "calls": []map[string]any{}}
	if c != nil {
		m["id"] = c.Session
		m["agent"] = c.Agent
		m["project"] = c.Project
	}
	if s == nil {
		return m
	}
	m["id"] = s.ID
	m["agent"] = s.Agent
	m["project"] = s.Project
	calls := make([]map[string]any, 0, len(s.Calls))
	for _, call := range s.Calls {
		calls = append(calls, map[string]any{"tool": call.Tool, "command": call.Command})
	}
	m["calls"] = calls
	return m
}
