package daemon

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/echtermeyer/overlord/internal/eslogger"
)

// Replay feeds recorded eslogger lines through the graph and rules and counts verdicts per rule.
func (d *Daemon) Replay(r io.Reader) (map[string]int, int, error) {
	d.Dry = true
	// Recorded events carry their own time; rule windows must follow it, not the wall clock.
	recorded := func() time.Time {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.lastAt
	}
	d.graph.SetClock(recorded)
	d.engine.SetClock(recorded)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1<<20), 64<<20)
	lines := 0
	for scanner.Scan() {
		lines++
		ev, err := eslogger.Parse(scanner.Bytes())
		if err != nil || ev == nil {
			continue
		}
		d.Handle(ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, lines, err
	}
	counts := map[string]int{}
	f, err := os.Open(filepath.Join(d.cfg.Logs.Dir, "overlord.ndjson"))
	if err != nil {
		return counts, lines, err
	}
	defer f.Close()
	logScanner := bufio.NewScanner(f)
	logScanner.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for logScanner.Scan() {
		var rec struct {
			Kind string `json:"kind"`
			Data struct {
				Verdict struct {
					Rule string `json:"rule"`
				} `json:"verdict"`
			} `json:"data"`
		}
		if json.Unmarshal(logScanner.Bytes(), &rec) == nil && rec.Kind == "verdict" {
			counts[rec.Data.Verdict.Rule]++
		}
	}
	return counts, lines, nil
}
