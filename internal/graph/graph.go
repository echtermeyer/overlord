package graph

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/echtermeyer/overlord/internal/events"
)

type Read struct {
	Path     string    `json:"path"`
	Category string    `json:"category"`
	At       time.Time `json:"at"`
}

type Dest struct {
	Address    string    `json:"address"`
	Port       int       `json:"port"`
	SeenBefore bool      `json:"seen_before"`
	At         time.Time `json:"at"`
}

type PersistenceWrite struct {
	Path string    `json:"path"`
	At   time.Time `json:"at"`
}

// Node is one process for its lifetime. Tags are inherited by descendants at fork and exec.
type Node struct {
	events.Process
	Key         string             `json:"key"`
	ParentKey   string             `json:"parent_key,omitempty"`
	Tags        map[string]string  `json:"tags"`
	Reads       []Read             `json:"reads,omitempty"`
	Outbound    []Dest             `json:"outbound,omitempty"`
	Persistence []PersistenceWrite `json:"persistence,omitempty"`
	Children    int                `json:"children"`
	FirstSeen   bool               `json:"first_seen"`
	Trusted     bool               `json:"trusted"`
	Exited      time.Time          `json:"exited,omitempty"`
}

func (n *Node) Name() string { return filepath.Base(n.Path) }

// Session groups every process an agent session caused.
type Session struct {
	ID      string
	Agent   string
	Project string
	Nodes   map[string]*Node
	Calls   []events.ToolCallInfo
	Started time.Time
}

type Options struct {
	Sensitive     *PathTable
	Tags          *PathTable
	TrustedTeams  []string
	KnownBinaries *Set
	KnownDests    *Set
	Retention     time.Duration
	// MaxPerNode bounds the reads and outbound slices kept per process.
	MaxPerNode int
}

type Graph struct {
	mu       sync.RWMutex
	opts     Options
	nodes    map[string]*Node
	latest   map[int]*Node
	children map[string][]string
	sessions map[string]*Session
	trusted  map[string]bool
	now      func() time.Time
}

func New(opts Options) *Graph {
	if opts.MaxPerNode == 0 {
		opts.MaxPerNode = 200
	}
	if opts.Retention == 0 {
		opts.Retention = 2 * time.Hour
	}
	g := &Graph{
		opts:     opts,
		nodes:    map[string]*Node{},
		latest:   map[int]*Node{},
		children: map[string][]string{},
		sessions: map[string]*Session{},
		trusted:  map[string]bool{},
		now:      time.Now,
	}
	for _, team := range opts.TrustedTeams {
		g.trusted[team] = true
	}
	return g
}

func (g *Graph) SetClock(now func() time.Time) { g.now = now }

// Apply folds an event into the graph and returns the node of the acting process and, for
// exec and fork, the node the event created.
func (g *Graph) Apply(ev *events.Event) (actor *Node, created *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	actor = g.ensure(ev.Process)
	switch ev.Kind {
	case events.Fork:
		if ev.Target != nil {
			created = g.ensure(*ev.Target)
			g.link(actor, created)
		}
	case events.Exec:
		if ev.Target != nil {
			created = g.ensure(*ev.Target)
			g.link(actor, created)
			if created != actor {
				g.inherit(actor, created)
			}
			created.Args = ev.Target.Args
			created.CWD = ev.Target.CWD
			g.tagByPath(created)
		}
	case events.Exit:
		actor.Exited = ev.At
	case events.FileOpen, events.FileCreate, events.FileWrite, events.FileRename, events.FileUnlink:
		if !ev.Write || ev.Kind == events.FileOpen {
			if cat := g.opts.Sensitive.Match(ev.Path); cat != "" {
				actor.Reads = appendBounded(actor.Reads, Read{Path: ev.Path, Category: cat, At: ev.At}, g.opts.MaxPerNode)
			}
		}
		if ev.Write && isPersistencePath(ev.Path) {
			actor.Persistence = append(actor.Persistence, PersistenceWrite{Path: ev.Path, At: ev.At})
		}
		if ev.DestPath != "" && isPersistencePath(ev.DestPath) {
			actor.Persistence = append(actor.Persistence, PersistenceWrite{Path: ev.DestPath, At: ev.At})
		}
	case events.LaunchItemAdd:
		actor.Persistence = append(actor.Persistence, PersistenceWrite{Path: ev.Path, At: ev.At})
	case events.NetConnect:
		if ev.Dest != nil {
			seen := g.opts.KnownDests != nil && g.opts.KnownDests.Has(ev.Dest.Address)
			ev.Dest.SeenBefore = seen
			actor.Outbound = appendBounded(actor.Outbound, Dest{Address: ev.Dest.Address, Port: ev.Dest.Port, SeenBefore: seen, At: ev.At}, g.opts.MaxPerNode)
			if g.opts.KnownDests != nil {
				g.opts.KnownDests.Add(ev.Dest.Address)
			}
		}
	case events.ToolCall:
		if ev.Call != nil {
			g.recordCall(actor, ev.Call)
		}
	}
	return actor, created
}

func (g *Graph) ensure(p events.Process) *Node {
	key := p.Key()
	if n, ok := g.nodes[key]; ok {
		if n.Path == "" && p.Path != "" {
			n.Process = p
			g.tagByPath(n)
		}
		return n
	}
	n := &Node{Process: p, Key: key, Tags: map[string]string{}}
	if p.PID != 0 {
		if parent := g.latest[p.PPID]; parent != nil && parent.PID != p.PID {
			g.link(parent, n)
			g.inherit(parent, n)
		}
	}
	n.Trusted = p.Platform || (p.TeamID != "" && g.trusted[p.TeamID])
	if g.opts.KnownBinaries != nil && p.CDHash != "" {
		n.FirstSeen = !g.opts.KnownBinaries.Has(p.CDHash)
		g.opts.KnownBinaries.Add(p.CDHash)
	}
	g.tagByPath(n)
	g.nodes[key] = n
	if old := g.latest[p.PID]; old == nil || old.PIDVersion <= p.PIDVersion {
		g.latest[p.PID] = n
	}
	return n
}

func (g *Graph) link(parent, child *Node) {
	if parent == child || child.ParentKey != "" {
		return
	}
	child.ParentKey = parent.Key
	parent.Children++
	g.children[parent.Key] = append(g.children[parent.Key], child.Key)
}

func (g *Graph) inherit(parent, child *Node) {
	for k, v := range parent.Tags {
		if _, set := child.Tags[k]; !set {
			child.Tags[k] = v
		}
	}
	for id, s := range g.sessions {
		if _, ok := s.Nodes[parent.Key]; ok {
			s.Nodes[child.Key] = child
			child.Tags["agent"] = id
		}
	}
}

func (g *Graph) tagByPath(n *Node) {
	if g.opts.Tags == nil || n.Path == "" {
		return
	}
	tag := g.opts.Tags.Match(n.Path)
	if tag == "" {
		return
	}
	key, value, found := strings.Cut(tag, ":")
	if !found {
		value = "true"
	}
	if _, set := n.Tags[key]; !set || key != "agent" {
		n.Tags[key] = value
	}
}

// TagSession marks the process with this pid, and every descendant, as part of an agent session.
func (g *Graph) TagSession(pid int, call events.ToolCallInfo) *Session {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.sessions[call.Session]
	if s == nil {
		s = &Session{ID: call.Session, Agent: call.Agent, Project: call.Project, Nodes: map[string]*Node{}, Started: g.now()}
		g.sessions[call.Session] = s
	}
	root := g.latest[pid]
	if root == nil {
		root = g.ensure(events.Process{PID: pid})
	}
	g.walk(root, func(n *Node) {
		s.Nodes[n.Key] = n
		n.Tags["agent"] = call.Session
		if call.Project != "" {
			n.Tags["project"] = call.Project
		}
	})
	return s
}

func (g *Graph) recordCall(actor *Node, call *events.ToolCallInfo) {
	s := g.sessions[call.Session]
	if s == nil {
		return
	}
	s.Calls = appendBounded(s.Calls, *call, g.opts.MaxPerNode)
}

func (g *Graph) walk(n *Node, fn func(*Node)) {
	fn(n)
	for _, key := range g.children[n.Key] {
		if c := g.nodes[key]; c != nil {
			g.walk(c, fn)
		}
	}
}

func (g *Graph) Node(key string) *Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[key]
}

func (g *Graph) ByPID(pid int) *Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.latest[pid]
}

func (g *Graph) Session(id string) *Session {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.sessions[id]
}

// Ancestors returns the chain from the parent up to the root, nearest first.
func (g *Graph) Ancestors(n *Node) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []*Node
	seen := map[string]bool{n.Key: true}
	for cur := g.nodes[n.ParentKey]; cur != nil && !seen[cur.Key]; cur = g.nodes[cur.ParentKey] {
		seen[cur.Key] = true
		out = append(out, cur)
	}
	return out
}

func (g *Graph) ReadsWithin(n *Node, within time.Duration) []Read {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return readsSince(n.Reads, g.now().Add(-within))
}

func (g *Graph) OutboundWithin(n *Node, within time.Duration) []Dest {
	g.mu.RLock()
	defer g.mu.RUnlock()
	cutoff := g.now().Add(-within)
	var out []Dest
	for _, d := range n.Outbound {
		if !d.At.Before(cutoff) {
			out = append(out, d)
		}
	}
	return out
}

func (g *Graph) SessionReadsWithin(id string, within time.Duration) []Read {
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := g.sessions[id]
	if s == nil {
		return nil
	}
	cutoff := g.now().Add(-within)
	var out []Read
	for _, n := range s.Nodes {
		out = append(out, readsSince(n.Reads, cutoff)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func readsSince(reads []Read, cutoff time.Time) []Read {
	var out []Read
	for _, r := range reads {
		if !r.At.Before(cutoff) {
			out = append(out, r)
		}
	}
	return out
}

// Evict drops processes that exited longer ago than the retention and are no longer referenced.
func (g *Graph) Evict() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := g.now().Add(-g.opts.Retention)
	dropped := 0
	for key, n := range g.nodes {
		if n.Exited.IsZero() || n.Exited.After(cutoff) || len(g.children[n.Key]) > 0 {
			continue
		}
		delete(g.nodes, key)
		delete(g.children, key)
		if g.latest[n.PID] == n {
			delete(g.latest, n.PID)
		}
		if n.ParentKey != "" {
			g.children[n.ParentKey] = remove(g.children[n.ParentKey], key)
		}
		for _, s := range g.sessions {
			delete(s.Nodes, key)
		}
		dropped++
	}
	return dropped
}

func (g *Graph) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

func remove(list []string, key string) []string {
	out := list[:0]
	for _, k := range list {
		if k != key {
			out = append(out, k)
		}
	}
	return out
}

func appendBounded[T any](list []T, item T, max int) []T {
	list = append(list, item)
	if len(list) > max {
		list = list[len(list)-max:]
	}
	return list
}

func isPersistencePath(path string) bool {
	tilde := Tilde(path)
	return strings.HasPrefix(tilde, "~/Library/LaunchAgents/") ||
		strings.HasPrefix(path, "/Library/LaunchAgents/") ||
		strings.HasPrefix(path, "/Library/LaunchDaemons/") ||
		strings.HasPrefix(path, "/Library/StartupItems/") ||
		strings.HasPrefix(path, "/etc/periodic/") ||
		strings.HasPrefix(path, "/usr/lib/cron/tabs/") ||
		strings.HasPrefix(path, "/var/at/tabs/") ||
		tilde == "~/.zshrc" || tilde == "~/.zprofile" || tilde == "~/.zshenv" ||
		tilde == "~/.bashrc" || tilde == "~/.bash_profile" || tilde == "~/.profile" ||
		strings.HasPrefix(tilde, "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/")
}
