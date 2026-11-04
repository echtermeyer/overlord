// Package actions carries out verdicts. Everything here is either reversible with Undo or needs
// certain confidence, see docs/DESIGN.md section 3.5.
package actions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Runner executes a system command; tests swap it out.
type Runner func(name string, args ...string) ([]byte, error)

func ExecRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type Manifest struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"` // quarantine | launch_item | pf_block
	Original string    `json:"original,omitempty"`
	Stored   string    `json:"stored,omitempty"`
	Mode     uint32    `json:"mode,omitempty"`
	UID      int       `json:"uid,omitempty"`
	GID      int       `json:"gid,omitempty"`
	Label    string    `json:"label,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	Address  string    `json:"address,omitempty"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
	Expires  time.Time `json:"expires,omitempty"`
	Undone   time.Time `json:"undone,omitempty"`
}

type Store struct {
	dir    string
	run    Runner
	mu     sync.Mutex
	frozen map[int]time.Time
	now    func() time.Time
}

func New(dataDir string, run Runner) (*Store, error) {
	if run == nil {
		run = ExecRunner
	}
	for _, sub := range []string{"quarantine", "manifests"} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dataDir, run: run, frozen: map[int]time.Time{}, now: time.Now}, nil
}

func (s *Store) Freeze(pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("refusing to freeze pid %d", pid)
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return err
	}
	s.mu.Lock()
	s.frozen[pid] = s.now()
	s.mu.Unlock()
	return nil
}

func (s *Store) Resume(pid int) error {
	s.mu.Lock()
	delete(s.frozen, pid)
	s.mu.Unlock()
	return syscall.Kill(pid, syscall.SIGCONT)
}

func (s *Store) Kill(pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	s.mu.Lock()
	delete(s.frozen, pid)
	s.mu.Unlock()
	return syscall.Kill(pid, syscall.SIGKILL)
}

func (s *Store) Frozen() map[int]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]time.Time, len(s.frozen))
	for k, v := range s.frozen {
		out[k] = v
	}
	return out
}

// Quarantine moves a file into the store, mode 000, and records how to put it back.
func (s *Store) Quarantine(path, reason string) (*Manifest, error) {
	path = filepath.Clean(path)
	if path == "/" || strings.HasPrefix(path, "/System/") || strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/sbin/") {
		return nil, fmt.Errorf("refusing to quarantine %s", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("refusing to quarantine a directory: %s", path)
	}
	stat, _ := info.Sys().(*syscall.Stat_t)
	m := &Manifest{ID: id(path, s.now()), Kind: "quarantine", Original: path, Mode: uint32(info.Mode().Perm()), Reason: reason, At: s.now()}
	if stat != nil {
		m.UID = int(stat.Uid)
		m.GID = int(stat.Gid)
	}
	m.Stored = filepath.Join(s.dir, "quarantine", m.ID)
	if err := os.Rename(path, m.Stored); err != nil {
		return nil, err
	}
	_ = os.Chmod(m.Stored, 0)
	return m, s.save(m)
}

// DisableLaunchItem unloads a LaunchAgent or LaunchDaemon plist and quarantines it.
func (s *Store) DisableLaunchItem(plist string, uid int, reason string) (*Manifest, error) {
	label := strings.TrimSuffix(filepath.Base(plist), ".plist")
	domain := "system"
	if strings.Contains(plist, "/LaunchAgents/") {
		domain = fmt.Sprintf("gui/%d", uid)
	}
	if out, err := s.run("launchctl", "bootout", domain+"/"+label); err != nil && !strings.Contains(string(out), "No such process") && !strings.Contains(string(out), "not find") {
		return nil, fmt.Errorf("launchctl bootout: %s: %w", strings.TrimSpace(string(out)), err)
	}
	m, err := s.Quarantine(plist, reason)
	if err != nil {
		return nil, err
	}
	m.Kind = "launch_item"
	m.Label = label
	m.Domain = domain
	return m, s.save(m)
}

// BlockDestination adds an address to the pf table "blocked" in anchor "overlord" until ttl.
func (s *Store) BlockDestination(address, reason string, ttl time.Duration) (*Manifest, error) {
	if out, err := s.run("pfctl", "-a", "overlord", "-t", "blocked", "-T", "add", address); err != nil {
		return nil, fmt.Errorf("pfctl add: %s: %w", strings.TrimSpace(string(out)), err)
	}
	m := &Manifest{ID: id(address, s.now()), Kind: "pf_block", Address: address, Reason: reason, At: s.now(), Expires: s.now().Add(ttl)}
	return m, s.save(m)
}

// Undo reverses one manifest. It is the only way quarantined files come back.
func (s *Store) Undo(manifestID string) error {
	m, err := s.load(manifestID)
	if err != nil {
		return err
	}
	if !m.Undone.IsZero() {
		return fmt.Errorf("%s already undone", manifestID)
	}
	switch m.Kind {
	case "quarantine", "launch_item":
		if err := os.MkdirAll(filepath.Dir(m.Original), 0o755); err != nil {
			return err
		}
		if err := os.Rename(m.Stored, m.Original); err != nil {
			return err
		}
		_ = os.Chmod(m.Original, os.FileMode(m.Mode))
		_ = os.Chown(m.Original, m.UID, m.GID)
		if m.Kind == "launch_item" {
			if out, err := s.run("launchctl", "bootstrap", m.Domain, m.Original); err != nil {
				return fmt.Errorf("launchctl bootstrap: %s: %w", strings.TrimSpace(string(out)), err)
			}
		}
	case "pf_block":
		if out, err := s.run("pfctl", "-a", "overlord", "-t", "blocked", "-T", "delete", m.Address); err != nil {
			return fmt.Errorf("pfctl delete: %s: %w", strings.TrimSpace(string(out)), err)
		}
	default:
		return fmt.Errorf("unknown manifest kind %q", m.Kind)
	}
	m.Undone = s.now()
	return s.save(m)
}

// ExpireBlocks removes pf blocks whose ttl has passed.
func (s *Store) ExpireBlocks() []string {
	var expired []string
	for _, m := range s.List() {
		if m.Kind == "pf_block" && m.Undone.IsZero() && !m.Expires.IsZero() && s.now().After(m.Expires) {
			if err := s.Undo(m.ID); err == nil {
				expired = append(expired, m.Address)
			}
		}
	}
	return expired
}

func (s *Store) List() []Manifest {
	entries, err := os.ReadDir(filepath.Join(s.dir, "manifests"))
	if err != nil {
		return nil
	}
	var out []Manifest
	for _, e := range entries {
		if m, err := s.load(strings.TrimSuffix(e.Name(), ".json")); err == nil {
			out = append(out, *m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func (s *Store) save(m *Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "manifests", m.ID+".json"), raw, 0o600)
}

func (s *Store) load(manifestID string) (*Manifest, error) {
	if strings.ContainsAny(manifestID, "/\\") || manifestID == "" {
		return nil, errors.New("bad manifest id")
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "manifests", manifestID+".json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func id(seed string, at time.Time) string {
	sum := sha256.Sum256([]byte(seed + at.Format(time.RFC3339Nano)))
	return at.UTC().Format("20060102T150405") + "-" + hex.EncodeToString(sum[:6])
}
