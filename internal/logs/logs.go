// Package logs writes the tamper-evident record stream: NDJSON, hash-chained, rotated locally
// and shipped in batches to an append-only sink.
package logs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Record struct {
	Seq  uint64          `json:"seq"`
	At   time.Time       `json:"at"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
	Prev string          `json:"prev"`
	Hash string          `json:"hash,omitempty"`
}

type Options struct {
	Dir       string
	MaxSizeMB int
	KeepFiles int
	Redact    bool
	// Queue bounds how many records wait for the shipper before the oldest are dropped.
	Queue int
}

type Logger struct {
	opts    Options
	mu      sync.Mutex
	file    *os.File
	size    int64
	seq     uint64
	prev    string
	queue   chan []byte
	dropped atomic.Uint64
	now     func() time.Time
}

// Secrets that must never leave the machine even inside a command line.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[A-Za-z0-9_\-]*(api[_-]?key|secret|token|password|passwd|authorization)[A-Za-z0-9_\-]*\s*[=:]\s*["']?[^\s"']{8,}`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9_\-./+=]{8,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
}

// Redact keeps the key and separator of a key=value secret and replaces the value.
func Redact(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			lower := strings.ToLower(m)
			if strings.HasPrefix(lower, "bearer ") {
				return m[:7] + "[redacted]"
			}
			i := strings.IndexAny(m, "=:")
			if i < 0 || i > 64 {
				return "[redacted]"
			}
			j := i + 1
			for j < len(m) && (m[j] == ' ' || m[j] == '\t' || m[j] == '"' || m[j] == '\'') {
				j++
			}
			return m[:j] + "[redacted]"
		})
	}
	return s
}

func Open(opts Options) (*Logger, error) {
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	if opts.Queue == 0 {
		opts.Queue = 10000
	}
	if opts.MaxSizeMB == 0 {
		opts.MaxSizeMB = 100
	}
	if opts.KeepFiles == 0 {
		opts.KeepFiles = 10
	}
	l := &Logger{opts: opts, queue: make(chan []byte, opts.Queue), now: time.Now}
	if err := l.open(); err != nil {
		return nil, err
	}
	l.seq, l.prev = l.tail()
	return l, nil
}

func (l *Logger) path() string { return filepath.Join(l.opts.Dir, "overlord.ndjson") }

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.file = f
	l.size = info.Size()
	return nil
}

// tail recovers the last seq and hash so the chain continues across restarts.
func (l *Logger) tail() (uint64, string) {
	raw, err := os.ReadFile(l.path())
	if err != nil || len(raw) == 0 {
		return 0, ""
	}
	raw = bytes.TrimRight(raw, "\n")
	i := bytes.LastIndexByte(raw, '\n')
	var r Record
	if err := json.Unmarshal(raw[i+1:], &r); err != nil {
		return 0, ""
	}
	return r.Seq, r.Hash
}

// Write appends one record and queues it for shipping.
func (l *Logger) Write(kind string, data any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if l.opts.Redact {
		payload = []byte(Redact(string(payload)))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r := Record{Seq: l.seq, At: l.now(), Kind: kind, Data: payload, Prev: l.prev}
	unsigned, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(unsigned)
	r.Hash = hex.EncodeToString(sum[:])
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		return err
	}
	l.prev = r.Hash
	l.size += int64(len(line))
	if l.size > int64(l.opts.MaxSizeMB)<<20 {
		l.rotate()
	}
	select {
	case l.queue <- line:
	default:
		l.dropped.Add(1)
	}
	return nil
}

func (l *Logger) rotate() {
	l.file.Close()
	rotated := filepath.Join(l.opts.Dir, "overlord-"+l.now().UTC().Format("20060102T150405")+".ndjson")
	_ = os.Rename(l.path(), rotated)
	_ = l.open()
	entries, _ := filepath.Glob(filepath.Join(l.opts.Dir, "overlord-*.ndjson"))
	sort.Strings(entries)
	for len(entries) > l.opts.KeepFiles {
		_ = os.Remove(entries[0])
		entries = entries[1:]
	}
}

func (l *Logger) Dropped() uint64 { return l.dropped.Load() }

func (l *Logger) Seq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// Verify walks a log file and reports the first record whose hash or chain is wrong.
func Verify(path string) (records int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	prev := ""
	for i, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return i, fmt.Errorf("line %d: %w", i+1, err)
		}
		if i > 0 && r.Prev != prev {
			return i, fmt.Errorf("line %d: chain broken", i+1)
		}
		want := r.Hash
		r.Hash = ""
		unsigned, _ := json.Marshal(r)
		sum := sha256.Sum256(unsigned)
		if hex.EncodeToString(sum[:]) != want {
			return i, fmt.Errorf("line %d: hash mismatch", i+1)
		}
		prev = want
		records++
	}
	return records, nil
}

// Shipper posts batches of records to the sink. A failed batch is retried next interval; the
// sink deduplicates on (host, seq).
type Shipper struct {
	URL      string
	Token    string
	Host     string
	Batch    int
	Interval time.Duration
	Client   *http.Client
	logger   *Logger
	pending  [][]byte
	failures atomic.Uint64
}

func NewShipper(l *Logger, url, token, host string, batch int, interval time.Duration) *Shipper {
	if batch <= 0 {
		batch = 500
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Shipper{URL: url, Token: token, Host: host, Batch: batch, Interval: interval, Client: &http.Client{Timeout: 15 * time.Second}, logger: l}
}

func (s *Shipper) Failures() uint64 { return s.failures.Load() }

func (s *Shipper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flush(context.Background())
			return
		case line := <-s.logger.queue:
			s.pending = append(s.pending, line)
			if len(s.pending) >= s.Batch {
				s.flush(ctx)
			}
		case <-ticker.C:
			s.flush(ctx)
		}
	}
}

func (s *Shipper) flush(ctx context.Context) {
	if len(s.pending) == 0 || s.URL == "" {
		s.pending = nil
		return
	}
	body := bytes.Join(s.pending, nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		s.failures.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("User-Agent", "overlord/1.0")
	req.Header.Set("X-Overlord-Host", s.Host)
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	resp, err := s.Client.Do(req)
	if err != nil || resp.StatusCode/100 != 2 {
		s.failures.Add(1)
		if resp != nil {
			resp.Body.Close()
		}
		if len(s.pending) > s.Batch*4 {
			s.pending = s.pending[len(s.pending)-s.Batch*4:]
		}
		return
	}
	resp.Body.Close()
	s.pending = nil
}
