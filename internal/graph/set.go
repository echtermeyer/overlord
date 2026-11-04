package graph

import (
	"bufio"
	"os"
	"sync"
)

// Set is a persistent set of strings: binaries and destinations this host has seen before.
// Every add is appended to the file, so a crash loses nothing.
type Set struct {
	mu    sync.Mutex
	items map[string]bool
	file  *os.File
}

func OpenSet(path string) (*Set, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s := &Set{items: map[string]bool{}, file: f}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s.items[scanner.Text()] = true
	}
	return s, scanner.Err()
}

func NewMemorySet(items ...string) *Set {
	s := &Set{items: map[string]bool{}}
	for _, item := range items {
		s.items[item] = true
	}
	return s
}

func (s *Set) Has(item string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[item]
}

func (s *Set) Add(item string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items[item] {
		return
	}
	s.items[item] = true
	if s.file != nil {
		_, _ = s.file.WriteString(item + "\n")
	}
}

func (s *Set) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func (s *Set) Close() error {
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}
