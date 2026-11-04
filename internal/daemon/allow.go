package daemon

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/echtermeyer/overlord/internal/graph"
	"github.com/echtermeyer/overlord/internal/rules"
)

// AllowEntry is one "Allow always" answer: this rule stays quiet for this identity.
type AllowEntry struct {
	Rule  string    `json:"rule"`
	Kind  string    `json:"kind"` // team_id | signing_id | cdhash | path
	Value string    `json:"value"`
	At    time.Time `json:"at"`
	UID   int       `json:"uid"`
}

type AllowStore struct {
	mu      sync.RWMutex
	path    string
	entries []AllowEntry
	policy  map[string][]string
}

func OpenAllowStore(path string, policyLists map[string][]string) (*AllowStore, error) {
	s := &AllowStore{path: path, policy: policyLists}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e AllowEntry
		if json.Unmarshal(scanner.Bytes(), &e) == nil {
			s.entries = append(s.entries, e)
		}
	}
	return s, scanner.Err()
}

// Identity picks the narrowest stable identity of a process for an allow entry.
func Identity(n *graph.Node) (kind, value string) {
	switch {
	case n == nil:
		return "", ""
	case n.TeamID != "":
		return "team_id", n.TeamID
	case n.SigningID != "":
		return "signing_id", n.SigningID
	case n.CDHash != "":
		return "cdhash", n.CDHash
	default:
		return "path", n.Path
	}
}

func (s *AllowStore) Add(e AllowEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.At = time.Now()
	s.entries = append(s.entries, e)
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	return err
}

func (s *AllowStore) Entries() []AllowEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]AllowEntry{}, s.entries...)
}

// Allowed reports whether an "Allow always" covers this rule for this process.
func (s *AllowStore) Allowed(rule string, n *graph.Node) bool {
	if n == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.Rule != rule && e.Rule != "*" {
			continue
		}
		if matches(e.Kind, e.Value, n) {
			return true
		}
	}
	return false
}

// InList reports whether a process is in a named policy allowlist. Items are team ids, signing
// ids, cdhashes or path globs; the kind is inferred from the item itself.
func (s *AllowStore) InList(list string, n *graph.Node) bool {
	if n == nil {
		return false
	}
	for _, item := range s.policy[list] {
		if strings.HasPrefix(item, "/") || strings.HasPrefix(item, "~") || strings.HasPrefix(item, "*") {
			if graph.MatchAny(n.Path, []string{item}) {
				return true
			}
			continue
		}
		if item == n.TeamID || item == n.SigningID || item == n.CDHash {
			return true
		}
	}
	return false
}

func matches(kind, value string, n *graph.Node) bool {
	switch kind {
	case "team_id":
		return n.TeamID == value
	case "signing_id":
		return n.SigningID == value
	case "cdhash":
		return n.CDHash == value
	case "path":
		return n.Path == value || graph.MatchAny(n.Path, []string{value})
	}
	return false
}

var _ = rules.Shadow
