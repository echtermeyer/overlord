package eslogger

import (
	"bufio"
	"os"
	"testing"

	"github.com/echtermeyer/overlord/internal/events"
)

func TestParseSample(t *testing.T) {
	f, err := os.Open("../../testdata/eslogger_sample.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []*events.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for scanner.Scan() {
		ev, err := Parse(scanner.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	want := []struct {
		kind events.Kind
		path string
		pid  int
	}{
		{events.Exec, "", 4000},
		{events.FileOpen, "/Users/eric/Library/Application Support/Google/Chrome/Default/Cookies", 4000},
		{events.FileOpen, "/Users/eric/.ssh/id_ed25519", 4000},
		{events.FileCreate, "/Users/eric/Library/LaunchAgents/com.homebrew.brewupdater.plist", 4000},
		{events.LaunchItemAdd, "/Users/eric/Library/LaunchAgents/com.homebrew.brewupdater.plist", 4000},
		{events.Exit, "", 4000},
		{events.MalwareDetected, "/Users/eric/Downloads/updater", 77},
		{events.Sudo, "", 4100},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Kind != w.kind || got[i].Path != w.path || got[i].Process.PID != w.pid {
			t.Errorf("event %d: got %s %q pid %d, want %s %q pid %d", i, got[i].Kind, got[i].Path, got[i].Process.PID, w.kind, w.path, w.pid)
		}
	}
	exec := got[0]
	if exec.Target == nil || exec.Target.Path != "/Users/eric/Downloads/updater" || exec.Target.PIDVersion != 3001 || exec.Target.CWD != "/Users/eric" || len(exec.Target.Args) != 2 {
		t.Errorf("exec target not filled: %+v", exec.Target)
	}
	if got[4].LaunchItem == nil || got[4].LaunchItem.Type != "agent" || !got[4].LaunchItem.Legacy {
		t.Errorf("launch item: %+v", got[4].LaunchItem)
	}
	if got[6].Detail["malware"] != "MACOS.AMOS" {
		t.Errorf("malware detail: %v", got[6].Detail)
	}
	if got[7].Detail["command"] != "/bin/ls" || got[7].Detail["success"] != "true" {
		t.Errorf("sudo detail: %v", got[7].Detail)
	}
}

func TestParseIgnoresUnknownEvents(t *testing.T) {
	ev, err := Parse([]byte(`{"time":"2026-11-04T10:00:00Z","process":{"audit_token":{"pid":1,"pidversion":1}},"event":{"stat":{}}}`))
	if err != nil || ev != nil {
		t.Fatalf("got %v, %v", ev, err)
	}
	if _, err := Parse([]byte(`{not json`)); err == nil {
		t.Fatal("bad json accepted")
	}
}
