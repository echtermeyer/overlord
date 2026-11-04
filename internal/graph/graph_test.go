package graph

import (
	"testing"
	"time"

	overlord "github.com/echtermeyer/overlord"
	"github.com/echtermeyer/overlord/internal/events"
)

func tables(t *testing.T) (*PathTable, *PathTable) {
	t.Helper()
	raw, err := overlord.Files.ReadFile("rules/sensitive_paths.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sensitive, err := ParsePathTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = overlord.Files.ReadFile("rules/tags.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tags, err := ParsePathTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	return sensitive, tags
}

func TestSensitiveMatch(t *testing.T) {
	sensitive, _ := tables(t)
	cases := []struct{ path, want string }{
		{"/Users/eric/Library/Application Support/Google/Chrome/Default/Cookies", "browser"},
		{"/Users/eric/Library/Application Support/Google/Chrome/Profile 2/Login Data", "browser"},
		{"/Users/eric/.ssh/id_ed25519", "ssh"},
		{"/Users/eric/.ssh/id_ed25519.pub", "ssh"},
		{"/Users/eric/.aws/credentials", "cloud"},
		{"/Users/eric/Developer/app/.env", "env"},
		{"/Users/eric/Developer/app/.env.local", "env"},
		{"/Users/eric/Library/Keychains/login.keychain-db", "keychain"},
		{"/var/root/.ssh/id_rsa", "ssh"},
		{"/Users/eric/Developer/app/main.go", ""},
		{"/usr/lib/libSystem.B.dylib", ""},
		{"/Library/Overlord/policy.yaml", "overlord"},
	}
	for _, c := range cases {
		if got := sensitive.Match(c.path); got != c.want {
			t.Errorf("%s: got %q, want %q", c.path, got, c.want)
		}
	}
}

func TestTagsAndInheritance(t *testing.T) {
	sensitive, tags := tables(t)
	g := New(Options{Sensitive: sensitive, Tags: tags, KnownBinaries: NewMemorySet(), KnownDests: NewMemorySet("1.1.1.1")})
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	g.SetClock(func() time.Time { return at.Add(10 * time.Second) })
	terminal := events.Process{PID: 100, PIDVersion: 1, Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Platform: false, CDHash: "term"}
	shell := events.Process{PID: 200, PIDVersion: 2, PPID: 100, Path: "/bin/zsh", Platform: true, CDHash: "zsh"}
	g.Apply(&events.Event{Kind: events.Fork, At: at, Process: terminal, Target: &shell})
	brew := events.Process{PID: 300, PIDVersion: 3, PPID: 200, Path: "/opt/homebrew/bin/brew", CDHash: "brew"}
	g.Apply(&events.Event{Kind: events.Fork, At: at, Process: shell, Target: &brew})
	g.Apply(&events.Event{Kind: events.Exec, At: at, Process: brew, Target: &brew})
	child := events.Process{PID: 400, PIDVersion: 4, PPID: 300, Path: "/tmp/postinstall", CDHash: "post"}
	g.Apply(&events.Event{Kind: events.Fork, At: at, Process: brew, Target: &child})

	n := g.ByPID(400)
	if n.Tags["terminal"] != "true" || n.Tags["installer"] != "brew" {
		t.Fatalf("tags not inherited: %v", n.Tags)
	}
	if !n.FirstSeen {
		t.Error("new cdhash should be first seen")
	}
	g.Apply(&events.Event{Kind: events.FileOpen, At: at, Process: child, Path: "/Users/eric/.ssh/id_rsa"})
	g.Apply(&events.Event{Kind: events.FileOpen, At: at, Process: child, Path: "/Users/eric/.aws/credentials"})
	g.Apply(&events.Event{Kind: events.NetConnect, At: at, Process: child, Dest: &events.Destination{Address: "1.1.1.1", Port: 443}})
	g.Apply(&events.Event{Kind: events.NetConnect, At: at, Process: child, Dest: &events.Destination{Address: "203.0.113.9", Port: 443}})
	if reads := g.ReadsWithin(n, time.Minute); len(reads) != 2 {
		t.Errorf("reads: %v", reads)
	}
	if reads := g.ReadsWithin(n, 5*time.Second); len(reads) != 0 {
		t.Errorf("reads outside the window: %v", reads)
	}
	out := g.OutboundWithin(n, time.Minute)
	if len(out) != 2 || !out[0].SeenBefore || out[1].SeenBefore {
		t.Errorf("outbound: %+v", out)
	}
	if anc := g.Ancestors(n); len(anc) != 3 || anc[0].PID != 300 || anc[2].PID != 100 {
		t.Errorf("ancestors: %v", anc)
	}
}

func TestSessionTagging(t *testing.T) {
	sensitive, tags := tables(t)
	g := New(Options{Sensitive: sensitive, Tags: tags})
	at := time.Now()
	agent := events.Process{PID: 500, PIDVersion: 5, Path: "/Users/eric/.local/bin/claude"}
	shell := events.Process{PID: 600, PIDVersion: 6, PPID: 500, Path: "/bin/zsh", Platform: true}
	g.Apply(&events.Event{Kind: events.Fork, At: at, Process: agent, Target: &shell})
	call := events.ToolCallInfo{Agent: "claude", Session: "s1", Project: "/Users/eric/app", AgentPID: 500}
	g.TagSession(500, call)
	curl := events.Process{PID: 700, PIDVersion: 7, PPID: 600, Path: "/usr/bin/curl", Platform: true}
	g.Apply(&events.Event{Kind: events.Fork, At: at, Process: shell, Target: &curl})
	n := g.ByPID(700)
	if n.Tags["agent"] != "s1" || n.Tags["project"] != "/Users/eric/app" {
		t.Fatalf("session tags: %v", n.Tags)
	}
	g.Apply(&events.Event{Kind: events.FileOpen, At: at, Process: curl, Path: "/Users/eric/app/.env"})
	if reads := g.SessionReadsWithin("s1", time.Minute); len(reads) != 1 || reads[0].Category != "env" {
		t.Errorf("session reads: %v", reads)
	}
	if g.ByPID(500).Tags["agent"] != "s1" {
		t.Errorf("agent process tag: %v", g.ByPID(500).Tags)
	}
}

func TestEvict(t *testing.T) {
	g := New(Options{Retention: time.Minute})
	at := time.Now()
	p := events.Process{PID: 1, PIDVersion: 1, Path: "/bin/ls"}
	g.Apply(&events.Event{Kind: events.Exec, At: at, Process: p, Target: &p})
	g.Apply(&events.Event{Kind: events.Exit, At: at.Add(-2 * time.Minute), Process: p})
	if g.Evict() != 1 || g.Len() != 0 {
		t.Errorf("exited process not evicted")
	}
}
