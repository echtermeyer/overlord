package eslogger

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

// Runner keeps one eslogger child alive and hands every line to Handle.
type Runner struct {
	Binary       string
	Events       []string
	RestartAfter time.Duration
	Handle       func(line []byte)
	Health       func(state string, detail string)

	lines    atomic.Uint64
	restarts atomic.Uint64
	alive    atomic.Bool
}

type Stats struct {
	Alive    bool   `json:"alive"`
	Lines    uint64 `json:"lines"`
	Restarts uint64 `json:"restarts"`
}

func (r *Runner) Stats() Stats {
	return Stats{Alive: r.alive.Load(), Lines: r.lines.Load(), Restarts: r.restarts.Load()}
}

func (r *Runner) Run(ctx context.Context) error {
	backoff := r.RestartAfter
	for {
		started := time.Now()
		err := r.once(ctx)
		if ctx.Err() != nil {
			return nil
		}
		r.restarts.Add(1)
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		r.Health("restarting", detail)
		// A child that dies at once is misconfigured (not root, no Full Disk Access); back off
		// so a broken install does not spin.
		if time.Since(started) < 5*time.Second {
			backoff = min(backoff*2, time.Minute)
		} else {
			backoff = r.RestartAfter
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}

func (r *Runner) once(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, r.Binary, r.Events...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	r.alive.Store(true)
	r.Health("running", "")
	defer r.alive.Store(false)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for scanner.Scan() {
		r.lines.Add(1)
		r.Handle(scanner.Bytes())
	}
	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil && !errors.Is(scanErr, io.EOF) {
		return scanErr
	}
	if waitErr != nil {
		return errors.New(strings.TrimSpace(stderr.String()) + ": " + waitErr.Error())
	}
	return errors.New("eslogger exited")
}
