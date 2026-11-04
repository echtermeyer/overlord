package actions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuarantineAndUndo(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	s, err := New(dir, func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "Library", "LaunchAgents", "com.evil.plist")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := s.DisableLaunchItem(victim, 501, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("plist still in place")
	}
	if calls[0] != "launchctl bootout gui/501/com.evil" {
		t.Errorf("bootout call: %v", calls)
	}
	if len(s.List()) != 1 || s.List()[0].Kind != "launch_item" {
		t.Errorf("manifests: %+v", s.List())
	}
	if err := s.Undo(m.ID); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(victim)
	if err != nil || string(raw) != "<plist/>" {
		t.Fatalf("not restored: %v", err)
	}
	if calls[1] != "launchctl bootstrap gui/501 "+victim {
		t.Errorf("bootstrap call: %v", calls)
	}
	if err := s.Undo(m.ID); err == nil {
		t.Error("double undo accepted")
	}
}

func TestRefusals(t *testing.T) {
	s, _ := New(t.TempDir(), func(string, ...string) ([]byte, error) { return nil, nil })
	if _, err := s.Quarantine("/usr/bin/curl", "x"); err == nil {
		t.Error("quarantined a system binary")
	}
	if err := s.Freeze(1); err == nil {
		t.Error("froze launchd")
	}
	if err := s.Kill(os.Getpid()); err == nil {
		t.Error("killed self")
	}
}

func TestBlockExpiry(t *testing.T) {
	var calls []string
	s, _ := New(t.TempDir(), func(name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	})
	now := time.Now()
	s.now = func() time.Time { return now }
	if _, err := s.BlockDestination("203.0.113.9", "x", time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := s.ExpireBlocks(); len(got) != 0 {
		t.Error("expired early")
	}
	now = now.Add(2 * time.Minute)
	if got := s.ExpireBlocks(); len(got) != 1 || calls[1] != "-a overlord -t blocked -T delete 203.0.113.9" {
		t.Errorf("expiry: %v %v", got, calls)
	}
}
