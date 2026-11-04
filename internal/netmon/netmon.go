// Package netmon reports new outbound connections per process by polling lsof. It is the
// coarse sensor until the Network Extension exists: no blocking, one-second resolution.
package netmon

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/echtermeyer/overlord/internal/events"
)

type Monitor struct {
	Interval time.Duration
	Resolve  func(pid int) (events.Process, bool)
	Emit     func(*events.Event)
	List     func(ctx context.Context) ([]byte, error)
	seen     map[string]time.Time
}

func New(interval time.Duration, resolve func(int) (events.Process, bool), emit func(*events.Event)) *Monitor {
	return &Monitor{Interval: interval, Resolve: resolve, Emit: emit, List: lsof, seen: map[string]time.Time{}}
}

func lsof(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "lsof", "-i", "-nP", "-F", "pPn").Output()
}

func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			raw, err := m.List(ctx)
			if err != nil {
				continue
			}
			m.Scan(raw, time.Now())
		}
	}
}

type Connection struct {
	PID      int
	Protocol string
	Address  string
	Port     int
}

// ParseLSOF reads lsof -F pPn output: one "p<pid>" line, then "P<proto>" and "n<src->dst>" pairs.
func ParseLSOF(raw []byte) []Connection {
	var out []Connection
	pid := 0
	proto := ""
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'P':
			proto = strings.ToLower(line[1:])
		case 'n':
			_, remote, ok := strings.Cut(line[1:], "->")
			if !ok {
				continue
			}
			host, portText, err := net.SplitHostPort(remote)
			if err != nil {
				continue
			}
			port, _ := strconv.Atoi(portText)
			out = append(out, Connection{PID: pid, Protocol: proto, Address: host, Port: port})
		}
	}
	return out
}

// Scan emits one net_connect per connection not seen in the last interval window.
func (m *Monitor) Scan(raw []byte, now time.Time) int {
	emitted := 0
	current := map[string]bool{}
	for _, c := range ParseLSOF(raw) {
		key := strconv.Itoa(c.PID) + "|" + c.Address + "|" + strconv.Itoa(c.Port)
		current[key] = true
		if _, ok := m.seen[key]; ok {
			m.seen[key] = now
			continue
		}
		m.seen[key] = now
		proc, ok := m.Resolve(c.PID)
		if !ok {
			proc = events.Process{PID: c.PID}
		}
		m.Emit(&events.Event{
			Kind: events.NetConnect, At: now, Source: "netmon", Process: proc,
			Dest: &events.Destination{Address: c.Address, Port: c.Port, Protocol: c.Protocol},
		})
		emitted++
	}
	for key, at := range m.seen {
		if !current[key] && now.Sub(at) > 2*m.Interval {
			delete(m.seen, key)
		}
	}
	return emitted
}
