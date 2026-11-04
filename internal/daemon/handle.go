package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/echtermeyer/overlord/internal/classifier"
	"github.com/echtermeyer/overlord/internal/events"
	"github.com/echtermeyer/overlord/internal/graph"
	"github.com/echtermeyer/overlord/internal/hooks"
	"github.com/echtermeyer/overlord/internal/llm"
	"github.com/echtermeyer/overlord/internal/notify"
	"github.com/echtermeyer/overlord/internal/rules"
)

// Handle folds one host event into the graph, evaluates the rules and carries out verdicts.
func (d *Daemon) Handle(ev *events.Event) {
	d.count(func(s *Stats) { s.Events++ })
	if !ev.At.IsZero() {
		d.mu.Lock()
		if ev.At.After(d.lastAt) {
			d.lastAt = ev.At
		}
		d.mu.Unlock()
	}
	actor, created := d.graph.Apply(ev)
	if ev.Kind == events.Exit || ev.Kind == events.Fork {
		return
	}
	in := rules.Input{Event: ev, Process: actor, Ancestors: d.graph.Ancestors(actor)}
	if created != nil {
		in.Target = created
	}
	if ev.Kind == events.RemoteThread && ev.Target != nil {
		in.Target = d.graph.Node(ev.Target.Key())
	}
	if session := actor.Tags["agent"]; session != "" {
		in.Session = d.graph.Session(session)
	}
	verdicts, err := d.engine.Evaluate(in)
	if err != nil {
		d.count(func(s *Stats) { s.Errors++ })
		d.log("rule_error", map[string]string{"error": err.Error(), "kind": string(ev.Kind)})
	}
	subject := actor
	if ev.Kind == events.Exec && created != nil {
		subject = created
	}
	if gated := d.gated(in); len(gated) > 0 {
		go d.classify(context.Background(), gated, ev, subject, in.Ancestors, nil)
	}
	if len(verdicts) == 0 {
		d.noteBlockedDestination(ev, actor)
		return
	}
	for _, v := range verdicts {
		d.count(func(s *Stats) { s.Verdicts++ })
		if d.allow.Allowed(v.RuleID, subject) {
			d.log("verdict", verdictRecord(v, ev, subject, in.Ancestors, "allowed_always"))
			continue
		}
		d.log("verdict", verdictRecord(v, ev, subject, in.Ancestors, ""))
		if d.Dry || len(v.Actions) == 0 {
			continue
		}
		go d.dispatch(context.Background(), v, ev, subject, in.Ancestors)
	}
}

func verdictRecord(v rules.Verdict, ev *events.Event, n *graph.Node, ancestors []*graph.Node, note string) map[string]any {
	chain := make([]string, 0, len(ancestors))
	for _, a := range ancestors {
		chain = append(chain, a.Name())
	}
	return map[string]any{
		"verdict": v, "event": ev, "process": rules.ProcessMap(n, nil), "chain": chain, "note": note,
	}
}

// dispatch carries out one verdict's actions in the order that keeps the most options open:
// freeze first, then ask, then whatever the answer or the escalation calls for.
func (d *Daemon) dispatch(ctx context.Context, v rules.Verdict, ev *events.Event, n *graph.Node, ancestors []*graph.Node) {
	pid := n.PID
	if v.Has(rules.Freeze) && pid > 0 {
		d.act("freeze", pid, v.RuleID, d.actions.Freeze(pid))
	}
	if v.Has(rules.BlockNewDestinations) {
		d.mu.Lock()
		d.blockNew[n.Key] = time.Now().Add(d.cfg.Ask.FreezeTimeout)
		d.mu.Unlock()
		d.log("action", map[string]any{"action": "block_new_destinations", "pid": pid, "rule": v.RuleID})
	}
	if v.Has(rules.Alert) {
		d.alert(ctx, v, n, ancestors)
	}
	if v.Has(rules.Kill) && pid > 0 {
		d.act("kill", pid, v.RuleID, d.actions.Kill(pid))
	}
	if v.Has(rules.Quarantine) && n.Path != "" {
		d.quarantine(n.Path, v.RuleID)
	}
	if v.Has(rules.DisableLaunchItem) && ev.Path != "" {
		m, err := d.actions.DisableLaunchItem(ev.Path, n.UID, v.RuleID)
		d.actResult("disable_launch_item", ev.Path, v.RuleID, m, err)
	}
	if v.Has(rules.SantaBlock) && d.santa != nil && n.CDHash != "" {
		d.actResult("santa_block", n.CDHash, v.RuleID, nil, d.santa.Block("CDHASH", n.CDHash, "Blocked by Overlord: "+v.RuleID))
	}
	if !v.Has(rules.AskAction) {
		return
	}
	choice := d.askPerson(ctx, v, ev, n, ancestors)
	switch choice {
	case notify.AllowOnce:
		if d.frozen(n.PID) {
			d.act("resume", pid, v.RuleID, d.actions.Resume(pid))
		}
	case notify.AllowAlways:
		kind, value := Identity(n)
		if err := d.allow.Add(AllowEntry{Rule: v.RuleID, Kind: kind, Value: value}); err != nil {
			d.log("error", map[string]string{"component": "allow", "error": err.Error()})
		}
		d.log("action", map[string]any{"action": "allow_always", "rule": v.RuleID, "kind": kind, "value": value})
		if d.frozen(n.PID) {
			d.act("resume", pid, v.RuleID, d.actions.Resume(pid))
		}
	case notify.Block:
		if d.frozen(n.PID) {
			d.act("kill", pid, v.RuleID, d.actions.Kill(pid))
		}
		if v.Has(rules.QuarantineIfBlocked) {
			target := ev.Path
			if ev.DestPath != "" {
				target = ev.DestPath
			}
			if ev.Kind == events.LaunchItemAdd || strings.Contains(target, "/Launch") {
				m, err := d.actions.DisableLaunchItem(target, n.UID, v.RuleID)
				d.actResult("disable_launch_item", target, v.RuleID, m, err)
			} else if target != "" {
				d.quarantine(target, v.RuleID)
			}
			if !n.Trusted && n.Path != "" && d.frozen(n.PID) {
				d.quarantine(n.Path, v.RuleID)
			}
		}
	default:
		// No answer: the process stays frozen until the freeze timeout policy decides.
		d.log("ask_timeout", map[string]any{"rule": v.RuleID, "pid": pid, "frozen": d.frozen(n.PID)})
	}
}

func (d *Daemon) askPerson(ctx context.Context, v rules.Verdict, ev *events.Event, n *graph.Node, ancestors []*graph.Node) string {
	d.count(func(s *Stats) { s.Asks++ })
	text := v.Explain
	if text == "" {
		text = fmt.Sprintf("%s matched rule %s", n.Name(), v.RuleID)
	}
	if d.explain.Enabled() {
		if r, err := d.explain.Explain(ctx, d.llmCase(v, n, ancestors, nil)); err == nil && r.Explanation != "" {
			text = r.Explanation
		}
	}
	chain := []string{n.Name()}
	for _, a := range ancestors {
		chain = append(chain, a.Name())
	}
	ask := notify.Ask{
		Title: "Overlord: " + v.RuleID, Text: text, Rule: v.RuleID, Process: n.Path, PID: n.PID, Chain: chain,
		Options: []string{notify.Block, notify.AllowOnce, notify.AllowAlways},
	}
	choice, answered := d.broker.Ask(ctx, ask)
	if !answered {
		_ = d.webhook.Send(ctx, "Overlord on "+d.hostname+" is waiting for an answer: "+text)
		return ""
	}
	d.label(v, n, ancestors, nil, "dialog", choice)
	return choice
}

func (d *Daemon) alert(ctx context.Context, v rules.Verdict, n *graph.Node, ancestors []*graph.Node) {
	text := v.Explain
	if text == "" {
		text = v.RuleID + ": " + n.Path
	}
	if err := d.webhook.Send(ctx, "Overlord on "+d.hostname+": "+text); err != nil {
		d.log("error", map[string]string{"component": "webhook", "error": err.Error()})
	}
}

func (d *Daemon) quarantine(path, rule string) {
	m, err := d.actions.Quarantine(path, rule)
	d.actResult("quarantine", path, rule, m, err)
}

func (d *Daemon) act(action string, pid int, rule string, err error) {
	d.actResult(action, fmt.Sprint(pid), rule, nil, err)
}

func (d *Daemon) actResult(action, target, rule string, manifest any, err error) {
	d.count(func(s *Stats) { s.Actions++ })
	rec := map[string]any{"action": action, "target": target, "rule": rule}
	if manifest != nil {
		rec["manifest"] = manifest
	}
	if err != nil {
		rec["error"] = err.Error()
		d.count(func(s *Stats) { s.Errors++ })
	}
	d.log("action", rec)
}

// noteBlockedDestination enforces block_new_destinations on later connections of a process.
func (d *Daemon) noteBlockedDestination(ev *events.Event, n *graph.Node) {
	if ev.Kind != events.NetConnect || ev.Dest == nil || d.Dry {
		return
	}
	d.mu.Lock()
	until, ok := d.blockNew[n.Key]
	d.mu.Unlock()
	if !ok || time.Now().After(until) || ev.Dest.SeenBefore {
		return
	}
	m, err := d.actions.BlockDestination(ev.Dest.Address, "block_new_destinations "+n.Key, d.cfg.Ask.FreezeTimeout)
	d.actResult("block_destination", ev.Dest.Address, "", m, err)
}

// ToolCall answers a hook synchronously. Asks go back to the agent's own permission prompt;
// the LLM may raise an ask to a deny, never lower anything.
func (d *Daemon) ToolCall(ctx context.Context, call hooks.Call) hooks.Decision {
	info := call.Info
	if call.Phase == "post" {
		d.resolvePending(info)
		return hooks.Decision{Permission: hooks.Allow}
	}
	if call.Phase != "pre" {
		return hooks.Decision{Permission: hooks.Allow}
	}
	session := d.graph.TagSession(info.AgentPID, info)
	ev := &events.Event{Kind: events.ToolCall, At: time.Now(), Source: "hook", Call: &info}
	if n := d.graph.ByPID(info.AgentPID); n != nil {
		ev.Process = n.Process
	}
	d.graph.Apply(ev)
	d.count(func(s *Stats) { s.Events++ })
	verdicts, err := d.engine.Evaluate(rules.Input{Event: ev, Process: d.graph.ByPID(info.AgentPID), Session: session})
	if err != nil {
		d.log("rule_error", map[string]string{"error": err.Error(), "kind": "tool_call"})
	}
	for _, v := range verdicts {
		d.count(func(s *Stats) { s.Verdicts++ })
		d.log("verdict", map[string]any{"verdict": v, "call": info, "note": ""})
	}
	if gated := d.gated(rules.Input{Event: ev, Process: d.graph.ByPID(info.AgentPID), Session: session}); len(gated) > 0 {
		verdicts = append(verdicts, d.classify(ctx, gated, ev, nil, nil, &info)...)
	}
	decision := hooks.FromVerdicts(verdicts)
	if decision.Permission == hooks.Ask && d.explain.Enabled() {
		c := d.llmCase(verdicts[0], nil, nil, &info)
		if r, err := d.explain.Explain(ctx, c); err == nil {
			if r.Explanation != "" {
				decision.Reason = r.Explanation
			}
			if r.Verdict == "deny" {
				decision.Permission = hooks.Deny
				d.log("llm_escalation", map[string]any{"call": info, "explanation": r.Explanation})
			}
		}
	}
	if decision.Permission == hooks.Ask {
		d.mu.Lock()
		d.pendingUI[callKey(info)] = pendingAsk{rules: decision.Rules, at: time.Now(), call: info}
		d.mu.Unlock()
		d.count(func(s *Stats) { s.Asks++ })
	}
	for _, v := range verdicts {
		if v.Has(rules.Alert) {
			go d.alert(context.Background(), v, &graph.Node{Process: events.Process{Path: info.Agent}, Tags: map[string]string{}}, nil)
		}
	}
	return decision
}

// resolvePending labels an agent ask as allowed when the tool later ran.
func (d *Daemon) resolvePending(info events.ToolCallInfo) {
	key := callKey(info)
	d.mu.Lock()
	p, ok := d.pendingUI[key]
	delete(d.pendingUI, key)
	d.mu.Unlock()
	if !ok {
		return
	}
	for _, rule := range p.rules {
		_ = d.labels.Write("label", map[string]any{"rule": rule, "choice": notify.AllowOnce, "source": "agent_ui", "call": p.call})
	}
}

func callKey(info events.ToolCallInfo) string {
	sum := sha256.Sum256([]byte(info.Session + "|" + info.Tool + "|" + info.Command + "|" + strings.Join(info.Paths, ",")))
	return hex.EncodeToString(sum[:12])
}

func (d *Daemon) label(v rules.Verdict, n *graph.Node, ancestors []*graph.Node, call *events.ToolCallInfo, source, choice string) {
	rec := map[string]any{"rule": v.RuleID, "choice": choice, "source": source, "verdict": v}
	if n != nil {
		rec["process"] = rules.ProcessMap(n, ancestors)
		rec["reads"] = d.graph.ReadsWithin(n, 10*time.Minute)
		rec["outbound"] = d.graph.OutboundWithin(n, 10*time.Minute)
	}
	if call != nil {
		rec["call"] = call
	}
	_ = d.labels.Write("label", rec)
}

func (d *Daemon) llmCase(v rules.Verdict, n *graph.Node, ancestors []*graph.Node, call *events.ToolCallInfo) llm.Case {
	c := llm.Case{Rule: v.RuleID, Explain: v.Explain, Process: map[string]any{}}
	if n != nil {
		c.Process = rules.ProcessMap(n, nil)
		for _, a := range ancestors {
			c.Ancestors = append(c.Ancestors, map[string]any{"name": a.Name(), "path": a.Path, "tags": a.Tags})
		}
		for _, r := range d.graph.ReadsWithin(n, 10*time.Minute) {
			c.Reads = append(c.Reads, r.Category+": "+r.Path)
		}
		for _, o := range d.graph.OutboundWithin(n, 10*time.Minute) {
			c.Outbound = append(c.Outbound, fmt.Sprintf("%s:%d seen_before=%v", o.Address, o.Port, o.SeenBefore))
		}
	}
	if call != nil {
		c.Call = map[string]any{"agent": call.Agent, "tool": call.Tool, "command": call.Command, "paths": call.Paths, "cwd": call.CWD}
		if s := d.graph.Session(call.Session); s != nil {
			for _, prev := range s.Calls {
				c.Calls = append(c.Calls, prev.Tool+": "+prev.Command+strings.Join(prev.Paths, " "))
			}
		}
	}
	return c
}

func (d *Daemon) frozen(pid int) bool {
	_, ok := d.actions.Frozen()[pid]
	return ok
}

// gated returns the questions whose gate rule matches this event, with the stage each runs in.
func (d *Daemon) gated(in rules.Input) map[string]rules.Verdict {
	if d.clf == nil || !d.clf.Enabled() {
		return nil
	}
	verdicts, err := d.gate.Evaluate(in)
	if err != nil {
		d.log("rule_error", map[string]string{"error": err.Error(), "kind": "classifier_gate"})
		return nil
	}
	out := map[string]rules.Verdict{}
	for _, v := range verdicts {
		out[v.RuleID] = v
	}
	return out
}

// classify asks the classifier the gated questions and turns answers past their thresholds
// into verdicts: ask (and alert) in stage ask or enforce; deny only for agent calls in enforce.
// Every answer is logged, so shadow stage still produces data to compare with labels.
func (d *Daemon) classify(ctx context.Context, gated map[string]rules.Verdict, ev *events.Event, n *graph.Node, ancestors []*graph.Node, call *events.ToolCallInfo) []rules.Verdict {
	var questions []classifier.Question
	for _, q := range d.questions {
		if _, ok := gated[q.RuleID()]; ok {
			questions = append(questions, q)
		}
	}
	state := d.llmCase(rules.Verdict{}, n, ancestors, call)
	answers, err := d.clf.Ask(ctx, state, questions)
	if err != nil {
		d.count(func(s *Stats) { s.Errors++ })
		d.log("classifier_error", map[string]string{"error": err.Error()})
		return nil
	}
	var out []rules.Verdict
	for _, q := range questions {
		a, ok := answers[q.ID]
		if !ok {
			continue
		}
		gate := gated[q.RuleID()]
		outcome := q.Judge(a)
		rec := map[string]any{"question": q.ID, "answer": a, "ask": outcome.Ask, "deny": outcome.Deny, "stage": gate.Stage, "kind": ev.Kind}
		if n != nil {
			rec["process"] = rules.ProcessMap(n, nil)
		}
		if call != nil {
			rec["call"] = call
		}
		d.log("classifier", rec)
		if !outcome.Ask && !outcome.Deny {
			continue
		}
		v := gate
		v.Explain = q.Render(a)
		v.Requested = []rules.Action{rules.AskAction, rules.Alert}
		if outcome.Deny && call != nil {
			v.Requested = []rules.Action{rules.Deny, rules.Alert}
			v.Confidence = rules.Likely
		}
		v.Actions = nil
		if gate.Stage != rules.Shadow {
			v.Actions = v.Requested
		}
		if gate.Stage == rules.Ask && outcome.Deny && call != nil {
			v.Actions = []rules.Action{rules.AskAction, rules.Alert}
		}
		d.count(func(s *Stats) { s.Verdicts++ })
		if n != nil {
			d.log("verdict", verdictRecord(v, ev, n, ancestors, "classifier"))
			if !d.Dry && len(v.Actions) > 0 && !d.allow.Allowed(v.RuleID, n) {
				go d.dispatch(context.Background(), v, ev, n, ancestors)
			}
			continue
		}
		d.log("verdict", map[string]any{"verdict": v, "call": call, "note": "classifier"})
		out = append(out, v)
	}
	return out
}
