// Package daemon wires sensors, graph, rules, actions, asks and logs into the root service.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	overlord "github.com/echtermeyer/overlord"
	"github.com/echtermeyer/overlord/internal/actions"
	"github.com/echtermeyer/overlord/internal/config"
	"github.com/echtermeyer/overlord/internal/eslogger"
	"github.com/echtermeyer/overlord/internal/events"
	"github.com/echtermeyer/overlord/internal/graph"
	"github.com/echtermeyer/overlord/internal/llm"
	"github.com/echtermeyer/overlord/internal/logs"
	"github.com/echtermeyer/overlord/internal/netmon"
	"github.com/echtermeyer/overlord/internal/notify"
	"github.com/echtermeyer/overlord/internal/rules"
	"github.com/echtermeyer/overlord/internal/santa"
)

type Daemon struct {
	cfg       *config.Config
	graph     *graph.Graph
	engine    *rules.Engine
	policy    rules.Policy
	actions   *actions.Store
	logger    *logs.Logger
	shipper   *logs.Shipper
	allow     *AllowStore
	broker    *Broker
	webhook   notify.Webhook
	explain   *llm.Explainer
	santa     *santa.Server
	es        *eslogger.Runner
	sensitive *graph.PathTable
	labels    *logs.Logger
	hashes    map[string]string
	started   time.Time
	hostname  string

	// Dry disables every action: replay and tests observe verdicts only.
	Dry bool

	mu        sync.Mutex
	lastAt    time.Time
	blockNew  map[string]time.Time
	pendingUI map[string]pendingAsk
	stats     Stats
}

type pendingAsk struct {
	rules []string
	at    time.Time
	call  events.ToolCallInfo
}

type Stats struct {
	Events   uint64 `json:"events"`
	Verdicts uint64 `json:"verdicts"`
	Asks     uint64 `json:"asks"`
	Actions  uint64 `json:"actions"`
	Errors   uint64 `json:"errors"`
}

func New(cfg *config.Config) (*Daemon, error) {
	d := &Daemon{cfg: cfg, hashes: map[string]string{}, started: time.Now(), blockNew: map[string]time.Time{}, pendingUI: map[string]pendingAsk{}}
	d.hostname, _ = os.Hostname()
	sensitive, err := d.table("sensitive_paths.yaml")
	if err != nil {
		return nil, err
	}
	d.sensitive = sensitive
	tags, err := d.table("tags.yaml")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	known, err := graph.OpenSet(filepath.Join(cfg.DataDir, "known-binaries"))
	if err != nil {
		return nil, err
	}
	dests, err := graph.OpenSet(filepath.Join(cfg.DataDir, "known-destinations"))
	if err != nil {
		return nil, err
	}
	d.graph = graph.New(graph.Options{
		Sensitive: sensitive, Tags: tags, TrustedTeams: cfg.Graph.TrustedTeams,
		KnownBinaries: known, KnownDests: dests, Retention: cfg.Graph.Retention, MaxPerNode: cfg.Graph.MaxPerProcess,
	})
	policyRaw, err := d.read(cfg.Rules.Policy, "policy.yaml")
	if err != nil {
		return nil, err
	}
	if d.policy, err = rules.ParsePolicy(policyRaw); err != nil {
		return nil, err
	}
	var all []rules.Rule
	for _, name := range []string{"agent.yaml", "host.yaml"} {
		raw, err := d.read(filepath.Join(cfg.Rules.Dir, name), "rules/"+name)
		if err != nil {
			return nil, err
		}
		list, err := rules.ParseRules(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		all = append(all, list...)
	}
	if d.allow, err = OpenAllowStore(filepath.Join(cfg.DataDir, "allow.ndjson"), d.policy.Allowlists); err != nil {
		return nil, err
	}
	if d.engine, err = rules.New(ruleContext{d}, all, d.policy, cfg.Rules.RepeatAfter); err != nil {
		return nil, err
	}
	if d.actions, err = actions.New(cfg.DataDir, nil); err != nil {
		return nil, err
	}
	if d.logger, err = logs.Open(logs.Options{Dir: cfg.Logs.Dir, MaxSizeMB: cfg.Logs.MaxSizeMB, KeepFiles: cfg.Logs.KeepFiles, Redact: cfg.Logs.Redact}); err != nil {
		return nil, err
	}
	if d.labels, err = logs.Open(logs.Options{Dir: filepath.Join(cfg.DataDir, "labels"), Redact: cfg.Logs.Redact, Queue: 1}); err != nil {
		return nil, err
	}
	token, _ := readSecret(cfg.Logs.Ship.TokenFile)
	d.shipper = logs.NewShipper(d.logger, cfg.Logs.Ship.URL, token, d.hostname, cfg.Logs.Ship.Batch, cfg.Logs.Ship.Interval)
	d.broker = NewBroker(cfg.Ask.Timeout)
	webhookToken, _ := readSecret(cfg.Notify.WebhookTokenFile)
	d.webhook = notify.Webhook{URL: cfg.Notify.WebhookURL, Token: webhookToken}
	if cfg.LLM.Provider != "none" {
		key, _ := readSecret(cfg.LLM.AnthropicKeyFile)
		d.explain = &llm.Explainer{Provider: cfg.LLM.Provider, Model: cfg.LLM.Model, URL: cfg.LLM.OllamaURL, Key: key, Timeout: cfg.LLM.Timeout}
		if cfg.LLM.Provider == "anthropic" {
			d.explain.URL = ""
		}
	}
	if cfg.Sensors.Santa.Enabled {
		if d.santa, err = santa.New(cfg.DataDir, d.Handle); err != nil {
			return nil, err
		}
	}
	d.hashes["binary"] = fileHash(executable())
	return d, nil
}

func (d *Daemon) Graph() *graph.Graph   { return d.graph }
func (d *Daemon) Engine() *rules.Engine { return d.engine }
func (d *Daemon) Policy() rules.Policy  { return d.policy }
func (d *Daemon) Logger() *logs.Logger  { return d.logger }

// read returns the file at path when it exists, else the embedded fallback, and records a hash.
func (d *Daemon) read(path, embedded string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	source := path
	if err != nil {
		if raw, err = overlord.Files.ReadFile(embedded); err != nil {
			return nil, err
		}
		source = "embedded:" + embedded
	}
	sum := sha256.Sum256(raw)
	d.hashes[embedded] = hex.EncodeToString(sum[:8]) + "@" + source
	return raw, nil
}

func (d *Daemon) table(name string) (*graph.PathTable, error) {
	raw, err := d.read(filepath.Join(d.cfg.Rules.Dir, name), "rules/"+name)
	if err != nil {
		return nil, err
	}
	return graph.ParsePathTable(raw)
}

func readSecret(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func executable() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ruleContext is what rules may ask the graph.
type ruleContext struct{ d *Daemon }

func (r ruleContext) Reads(key string, within time.Duration) []graph.Read {
	if n := r.d.graph.Node(key); n != nil {
		return r.d.graph.ReadsWithin(n, within)
	}
	return nil
}

func (r ruleContext) Outbound(key string, within time.Duration) []graph.Dest {
	if n := r.d.graph.Node(key); n != nil {
		return r.d.graph.OutboundWithin(n, within)
	}
	return nil
}

func (r ruleContext) SessionReads(id string, within time.Duration) []graph.Read {
	return r.d.graph.SessionReadsWithin(id, within)
}

func (r ruleContext) InAllowlist(key, list string) bool {
	return r.d.allow.InList(list, r.d.graph.Node(key))
}

func (r ruleContext) Category(path string) string {
	return r.d.sensitive.Match(path)
}

// Run starts every sensor and loop and blocks until ctx ends.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	start := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				d.log("error", map[string]string{"component": name, "error": err.Error()})
				cancel()
			}
		}()
	}
	d.log("start", map[string]any{"version": overlord.Version, "hashes": d.hashes, "policy": d.policy.Stages})
	start("shipper", func(ctx context.Context) error { d.shipper.Run(ctx); return nil })
	start("ipc", d.serveIPC)
	if d.cfg.Sensors.ESLogger.Enabled {
		d.es = &eslogger.Runner{
			Binary: d.cfg.Sensors.ESLogger.Binary, Events: d.cfg.Sensors.ESLogger.Events, RestartAfter: d.cfg.Sensors.ESLogger.RestartAfter,
			Handle: d.handleLine,
			Health: func(state, detail string) {
				d.log("sensor_health", map[string]string{"sensor": "eslogger", "state": state, "detail": detail})
			},
		}
		start("eslogger", d.es.Run)
	}
	if d.cfg.Sensors.Netmon.Enabled {
		mon := netmon.New(d.cfg.Sensors.Netmon.Interval, func(pid int) (events.Process, bool) {
			if n := d.graph.ByPID(pid); n != nil {
				return n.Process, true
			}
			return events.Process{}, false
		}, d.Handle)
		start("netmon", func(ctx context.Context) error { mon.Run(ctx); return nil })
	}
	if d.santa != nil {
		start("santa", func(ctx context.Context) error { return d.santa.ListenAndServe(ctx, d.cfg.Sensors.Santa.Listen) })
	}
	start("housekeeping", d.housekeeping)
	wg.Wait()
	d.log("stop", nil)
	d.logger.Close()
	return nil
}

func (d *Daemon) handleLine(line []byte) {
	ev, err := eslogger.Parse(line)
	if err != nil {
		d.count(func(s *Stats) { s.Errors++ })
		return
	}
	if ev != nil {
		d.Handle(ev)
	}
}

func (d *Daemon) housekeeping(ctx context.Context) error {
	heartbeat := time.NewTicker(d.cfg.Logs.Heartbeat)
	sweep := time.NewTicker(time.Minute)
	defer heartbeat.Stop()
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			d.log("heartbeat", d.Status())
		case <-sweep.C:
			d.graph.Evict()
			for _, addr := range d.actions.ExpireBlocks() {
				d.log("action", map[string]string{"action": "unblock_destination", "address": addr, "reason": "ttl"})
			}
			d.sweepFrozen()
			d.sweepPending()
		}
	}
}

func (d *Daemon) sweepFrozen() {
	for pid, since := range d.actions.Frozen() {
		if time.Since(since) < d.cfg.Ask.FreezeTimeout {
			continue
		}
		switch d.cfg.Ask.FrozenOnTimeout {
		case "kill":
			d.act("kill", pid, "", d.actions.Kill(pid))
		case "resume":
			d.act("resume", pid, "", d.actions.Resume(pid))
		}
	}
}

func (d *Daemon) sweepPending() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, p := range d.pendingUI {
		if time.Since(p.at) > 10*time.Minute {
			delete(d.pendingUI, key)
		}
	}
}

type StatusReport struct {
	Version     string            `json:"version"`
	Host        string            `json:"host"`
	Uptime      string            `json:"uptime"`
	Hashes      map[string]string `json:"hashes"`
	Processes   int               `json:"processes"`
	ESLogger    *eslogger.Stats   `json:"eslogger,omitempty"`
	Stats       Stats             `json:"stats"`
	LogSeq      uint64            `json:"log_seq"`
	LogDropped  uint64            `json:"log_dropped"`
	ShipFailed  uint64            `json:"ship_failures"`
	Frozen      []int             `json:"frozen"`
	Subscribers int               `json:"notify_subscribers"`
	Stages      map[string]string `json:"stages"`
}

func (d *Daemon) Status() StatusReport {
	d.mu.Lock()
	stats := d.stats
	d.mu.Unlock()
	r := StatusReport{
		Version: overlord.Version, Host: d.hostname, Uptime: time.Since(d.started).Round(time.Second).String(),
		Hashes: d.hashes, Processes: d.graph.Len(), Stats: stats, LogSeq: d.logger.Seq(), LogDropped: d.logger.Dropped(),
		ShipFailed: d.shipper.Failures(), Subscribers: d.broker.Subscribers(), Stages: map[string]string{},
	}
	if d.es != nil {
		s := d.es.Stats()
		r.ESLogger = &s
	}
	for pid := range d.actions.Frozen() {
		r.Frozen = append(r.Frozen, pid)
	}
	for _, rule := range d.engine.Rules() {
		r.Stages[rule.ID] = string(d.policy.Stage(rule.ID))
	}
	return r
}

func (d *Daemon) log(kind string, data any) {
	if err := d.logger.Write(kind, data); err != nil {
		fmt.Fprintln(os.Stderr, "log:", err)
	}
}

func (d *Daemon) count(fn func(*Stats)) {
	d.mu.Lock()
	fn(&d.stats)
	d.mu.Unlock()
}
