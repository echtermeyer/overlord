package netmon

import (
	"testing"
	"time"

	"github.com/echtermeyer/overlord/internal/events"
)

const sample = "p4000\nPTCP\nn127.0.0.1:52000->203.0.113.9:443\nPTCP\nn*:8080\np4001\nPUDP\nn192.168.1.5:5353->224.0.0.251:5353\nPTCP\nn[fe80::1]:50000->[2001:db8::1]:443\n"

func TestParse(t *testing.T) {
	got := ParseLSOF([]byte(sample))
	want := []Connection{{4000, "tcp", "203.0.113.9", 443}, {4001, "udp", "224.0.0.251", 5353}, {4001, "tcp", "2001:db8::1", 443}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestScanEmitsOnce(t *testing.T) {
	var emitted []*events.Event
	m := New(time.Second, func(pid int) (events.Process, bool) {
		return events.Process{PID: pid, PIDVersion: 7}, true
	}, func(e *events.Event) { emitted = append(emitted, e) })
	now := time.Now()
	if n := m.Scan([]byte(sample), now); n != 3 {
		t.Errorf("first scan emitted %d", n)
	}
	if n := m.Scan([]byte(sample), now.Add(time.Second)); n != 0 {
		t.Errorf("second scan emitted %d", n)
	}
	if n := m.Scan([]byte("p1\n"), now.Add(5*time.Second)); n != 0 {
		t.Errorf("empty scan emitted %d", n)
	}
	if n := m.Scan([]byte(sample), now.Add(6*time.Second)); n != 3 {
		t.Errorf("after expiry emitted %d", n)
	}
	if emitted[0].Process.PIDVersion != 7 || emitted[0].Dest.Address != "203.0.113.9" {
		t.Errorf("event: %+v", emitted[0])
	}
}
