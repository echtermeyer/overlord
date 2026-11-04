package graph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// PathTable maps categories (or tags) to path globs. "~" stands for any user's home directory.
type PathTable struct {
	rows []pathRow
}

type pathRow struct {
	name    string
	pattern string
}

func LoadPathTable(path string) (*PathTable, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePathTable(raw)
}

func ParsePathTable(raw []byte) (*PathTable, error) {
	var table map[string][]string
	if err := yaml.Unmarshal(raw, &table); err != nil {
		return nil, fmt.Errorf("path table: %w", err)
	}
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	t := &PathTable{}
	for _, name := range names {
		for _, pattern := range table[name] {
			if !doublestar.ValidatePattern(pattern) {
				return nil, fmt.Errorf("path table %s: bad pattern %q", name, pattern)
			}
			t.rows = append(t.rows, pathRow{name: name, pattern: pattern})
		}
	}
	return t, nil
}

// Match returns the first category whose glob matches the path, or "".
func (t *PathTable) Match(path string) string {
	if t == nil || path == "" {
		return ""
	}
	tilde := Tilde(path)
	for _, row := range t.rows {
		candidate := path
		if strings.HasPrefix(row.pattern, "~") {
			candidate = tilde
		}
		if ok, _ := doublestar.Match(row.pattern, candidate); ok {
			return row.name
		}
	}
	return ""
}

// MatchAny reports whether any of the globs matches the path, with "~" expanded as in the table.
func MatchAny(path string, patterns []string) bool {
	tilde := Tilde(path)
	for _, pattern := range patterns {
		candidate := path
		if strings.HasPrefix(pattern, "~") {
			candidate = tilde
		}
		if ok, _ := doublestar.Match(pattern, candidate); ok {
			return true
		}
	}
	return false
}

// Tilde replaces a user's home directory prefix with "~" so one glob covers every user.
func Tilde(path string) string {
	if strings.HasPrefix(path, "/Users/") {
		rest := strings.TrimPrefix(path, "/Users/")
		if i := strings.IndexByte(rest, '/'); i > 0 {
			return "~" + rest[i:]
		}
		if rest != "" {
			return "~"
		}
	}
	if strings.HasPrefix(path, "/var/root/") {
		return "~" + strings.TrimPrefix(path, "/var/root")
	}
	return filepath.Clean(path)
}
