package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	overlord "github.com/echtermeyer/overlord"
	"github.com/echtermeyer/overlord/internal/config"
	"github.com/echtermeyer/overlord/internal/daemon"
	"github.com/echtermeyer/overlord/internal/ipc"
)

const (
	installDir  = "/Library/Overlord"
	daemonPlist = "/Library/LaunchDaemons/com.overlord.daemon.plist"
	notifyPlist = "/Library/LaunchAgents/com.overlord.notify.plist"
	pfAnchor    = "/etc/pf.anchors/overlord"
)

func sh(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func consoleUID() int {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return -1
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}

// runInstall puts the binary, rules, policy, pf anchor and launchd jobs in place from the files
// embedded in this binary. Existing config, policy and rules are kept.
func runInstall(cfg *config.Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo overlord install")
	}
	for _, dir := range []string{installDir + "/bin", installDir + "/rules", cfg.DataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	_ = os.Chmod(cfg.DataDir, 0o700)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target := installDir + "/bin/overlord"
	if filepath.Clean(self) != target {
		if err := copyFile(self, target, 0o755); err != nil {
			return err
		}
		fmt.Println("binary   ", target)
	}
	kept := 0
	_ = fs.WalkDir(overlord.Files, "rules", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if writeIfAbsent(installDir+"/"+path, path, 0o644) {
			kept++
		}
		return nil
	})
	if writeIfAbsent(installDir+"/policy.yaml", "policy.yaml", 0o644) {
		kept++
	}
	if _, err := os.Stat(installDir + "/config.yaml"); os.IsNotExist(err) {
		_ = os.WriteFile(installDir+"/config.yaml", []byte("# Overrides of the embedded defaults. Unknown keys stop the daemon.\n"), 0o644)
	}
	fmt.Printf("rules    %s/rules, policy.yaml, config.yaml (%d existing files kept)\n", installDir, kept)

	anchor, _ := overlord.Files.ReadFile("packaging/pf.anchor")
	if err := os.WriteFile(pfAnchor, anchor, 0o644); err != nil {
		return err
	}
	pfconf, _ := os.ReadFile("/etc/pf.conf")
	if !strings.Contains(string(pfconf), `anchor "overlord"`) {
		f, err := os.OpenFile("/etc/pf.conf", os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, _ = f.WriteString("\nanchor \"overlord\"\nload anchor \"overlord\" from \"/etc/pf.anchors/overlord\"\n")
		f.Close()
	}
	if out, err := sh("pfctl", "-f", "/etc/pf.conf"); err != nil {
		fmt.Println("warning  pf rules not loaded:", out)
	}
	_, _ = sh("pfctl", "-e")
	fmt.Println("firewall  anchor overlord loaded")

	for _, job := range []struct{ embedded, path, domain string }{
		{"packaging/com.overlord.daemon.plist", daemonPlist, "system"},
		{"packaging/com.overlord.notify.plist", notifyPlist, ""},
	} {
		raw, _ := overlord.Files.ReadFile(job.embedded)
		if err := os.WriteFile(job.path, raw, 0o644); err != nil {
			return err
		}
		_ = os.Chown(job.path, 0, 0)
	}
	_, _ = sh("launchctl", "bootout", "system/com.overlord.daemon")
	if out, err := sh("launchctl", "bootstrap", "system", daemonPlist); err != nil {
		return fmt.Errorf("launchctl bootstrap: %s", out)
	}
	fmt.Println("daemon    com.overlord.daemon running")
	if uid := consoleUID(); uid > 0 {
		domain := "gui/" + strconv.Itoa(uid)
		_, _ = sh("launchctl", "bootout", domain+"/com.overlord.notify")
		if out, err := sh("launchctl", "bootstrap", domain, notifyPlist); err != nil {
			fmt.Println("warning   notify agent not started:", out)
		} else {
			fmt.Println("notify    com.overlord.notify running for uid", uid)
		}
	}
	fmt.Println()
	fmt.Println("Next:")
	fmt.Println("  1. Give /usr/bin/eslogger Full Disk Access: System Settings > Privacy & Security > Full Disk Access,")
	fmt.Println("     press + then Cmd-Shift-G and type /usr/bin/eslogger. (MDM: packaging/overlord-fda.mobileconfig)")
	fmt.Println("  2. As yourself: overlord install-hooks claude   (also codex, cursor, gemini)")
	fmt.Println("  3. sudo overlord doctor")
	return nil
}

func runUninstall(cfg *config.Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo overlord uninstall")
	}
	_, _ = sh("launchctl", "bootout", "system/com.overlord.daemon")
	if uid := consoleUID(); uid > 0 {
		_, _ = sh("launchctl", "bootout", "gui/"+strconv.Itoa(uid)+"/com.overlord.notify")
	}
	_ = os.Remove(daemonPlist)
	_ = os.Remove(notifyPlist)
	_, _ = sh("pfctl", "-a", "overlord", "-F", "all")
	_ = os.Remove(pfAnchor)
	if pfconf, err := os.ReadFile("/etc/pf.conf"); err == nil {
		var keep []string
		for _, line := range strings.Split(string(pfconf), "\n") {
			if strings.HasPrefix(line, `anchor "overlord"`) || strings.HasPrefix(line, `load anchor "overlord"`) {
				continue
			}
			keep = append(keep, line)
		}
		_ = os.WriteFile("/etc/pf.conf", []byte(strings.Join(keep, "\n")), 0o644)
		_, _ = sh("pfctl", "-f", "/etc/pf.conf")
	}
	_ = os.RemoveAll(installDir)
	_ = os.Remove(cfg.Socket)
	fmt.Printf("removed; %s kept (logs, labels, quarantine)\n", cfg.DataDir)
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	return os.Rename(tmp, dst)
}

func writeIfAbsent(dst, embedded string, mode os.FileMode) (kept bool) {
	if _, err := os.Stat(dst); err == nil {
		return true
	}
	raw, _ := overlord.Files.ReadFile(embedded)
	_ = os.WriteFile(dst, raw, mode)
	return false
}

type check struct {
	ok   bool
	warn bool
	text string
}

// runDoctor checks an installation from the outside in and says what to fix.
func runDoctor(cfg *config.Config) error {
	var checks []check
	add := func(ok bool, text string) { checks = append(checks, check{ok: ok, text: text}) }
	warn := func(text string) { checks = append(checks, check{ok: true, warn: true, text: text}) }
	root := os.Geteuid() == 0

	if _, err := os.Stat(installDir + "/bin/overlord"); err == nil {
		add(true, "binary installed at "+installDir+"/bin/overlord")
	} else {
		add(false, "binary not installed: sudo overlord install")
	}
	if out, err := sh("launchctl", "print", "system/com.overlord.daemon"); err == nil {
		add(true, "daemon job loaded (launchd)")
	} else if root {
		add(false, "daemon job not loaded: "+firstLine(out))
	} else {
		warn("daemon job check needs root (sudo overlord doctor)")
	}
	client := ipc.Client{Path: cfg.Socket, Timeout: 3 * time.Second}
	var status daemon.StatusReport
	if err := client.Call("status", nil, &status); err != nil {
		add(false, "daemon not answering on "+cfg.Socket+": "+err.Error())
	} else {
		add(true, fmt.Sprintf("daemon %s up %s, %d processes in the graph", status.Version, status.Uptime, status.Processes))
		switch {
		case status.ESLogger == nil:
			warn("eslogger disabled in config: no host events")
		case status.ESLogger.Alive && status.ESLogger.Lines > 0:
			add(true, fmt.Sprintf("eslogger alive, %d events, %d restarts", status.ESLogger.Lines, status.ESLogger.Restarts))
		case status.ESLogger.Restarts > 1 && status.ESLogger.Lines == 0:
			add(false, "eslogger keeps dying: /usr/bin/eslogger needs Full Disk Access (System Settings > Privacy & Security)")
		default:
			warn("eslogger started but no events yet; check again in a minute")
		}
		if status.Subscribers > 0 {
			add(true, "notify agent connected: asks will show a dialog")
		} else {
			add(false, "no notify agent connected: launchctl bootstrap gui/$(id -u) "+notifyPlist)
		}
		if status.LogDropped > 0 || status.ShipFailed > 0 {
			warn(fmt.Sprintf("log: %d records dropped, %d shipments failed", status.LogDropped, status.ShipFailed))
		}
		stages := map[string]int{}
		for _, s := range status.Stages {
			stages[s]++
		}
		add(true, fmt.Sprintf("rules: %d enforce, %d ask, %d shadow", stages["enforce"], stages["ask"], stages["shadow"]))
	}
	if root {
		if out, err := sh("pfctl", "-s", "Anchors"); err == nil && strings.Contains(out, "overlord") {
			add(true, "firewall anchor loaded")
		} else {
			add(false, "firewall anchor missing: sudo overlord install")
		}
	}
	home, _ := os.UserHomeDir()
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		home = "/Users/" + sudoUser
	}
	for agent, file := range map[string]string{"claude": ".claude/settings.json", "codex": ".codex/hooks.json", "cursor": ".cursor/hooks.json", "gemini": ".gemini/settings.json"} {
		dir := filepath.Join(home, filepath.Dir(file))
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(home, file))
		if strings.Contains(string(raw), "overlord hook "+agent) {
			add(true, agent+" hooks installed")
		} else {
			add(false, agent+" found but hooks missing: overlord install-hooks "+agent)
		}
	}
	if _, err := os.Stat("/Library/Application Support/ClaudeCode/managed-settings.json"); err == nil {
		add(true, "Claude Code managed settings present")
	}
	if cfg.Logs.Ship.URL == "" {
		warn("no external log sink configured (logs.ship.url): a wiped Mac takes its log with it")
	} else {
		resp, err := http.Get(strings.TrimSuffix(cfg.Logs.Ship.URL, "/ingest") + "/hosts")
		if err == nil {
			resp.Body.Close()
			add(true, "log sink reachable")
		} else {
			add(false, "log sink unreachable: "+err.Error())
		}
	}
	if cfg.Notify.WebhookURL == "" {
		warn("no webhook (notify.webhook_url): alerts stay on this Mac")
	}
	if cfg.Classifier.URL != "" {
		if resp, err := http.Get(cfg.Classifier.URL); err == nil {
			resp.Body.Close()
			add(true, "classifier reachable at "+cfg.Classifier.URL)
		} else {
			add(false, "classifier configured but unreachable: "+err.Error())
		}
	} else {
		warn("no classifier (classifier.url): rules only, see docs/OPERATIONS.md")
	}

	failed := 0
	for _, c := range checks {
		mark := "ok  "
		if c.warn {
			mark = "warn"
		} else if !c.ok {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("%s  %s\n", mark, c.text)
	}
	if failed > 0 {
		return fmt.Errorf("%d checks failed", failed)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

type logRecord struct {
	At   time.Time       `json:"at"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

func readLog(cfg *config.Config, since time.Time) ([]logRecord, error) {
	files, _ := filepath.Glob(filepath.Join(cfg.Logs.Dir, "overlord-*.ndjson"))
	sort.Strings(files)
	files = append(files, filepath.Join(cfg.Logs.Dir, "overlord.ndjson"))
	var out []logRecord
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 1<<20), 64<<20)
		for scanner.Scan() {
			var r logRecord
			if json.Unmarshal(scanner.Bytes(), &r) == nil && !r.At.Before(since) {
				out = append(out, r)
			}
		}
		f.Close()
	}
	if len(out) == 0 {
		if _, err := os.Stat(cfg.Logs.Dir); err != nil {
			return nil, fmt.Errorf("no log at %s (run as root, or point -config at a trial config)", cfg.Logs.Dir)
		}
	}
	return out, nil
}

// summarize renders one log record as a line a person can read.
func summarize(r logRecord) string {
	var d map[string]any
	_ = json.Unmarshal(r.Data, &d)
	when := r.At.Local().Format("15:04:05")
	get := func(path ...string) string {
		var cur any = d
		for _, p := range path {
			m, ok := cur.(map[string]any)
			if !ok {
				return ""
			}
			cur = m[p]
		}
		if cur == nil {
			return ""
		}
		return fmt.Sprint(cur)
	}
	switch r.Kind {
	case "verdict":
		subject := get("process", "name")
		if subject == "" {
			subject = get("call", "agent") + " " + get("call", "tool") + " " + get("call", "command")
		}
		note := get("note")
		if note != "" {
			note = " [" + note + "]"
		}
		return fmt.Sprintf("%s  %-8s %-34s %-7s %s%s", when, "rule", get("verdict", "rule"), get("verdict", "stage"), strings.TrimSpace(subject), note)
	case "action":
		return fmt.Sprintf("%s  %-8s %s %s (%s)", when, "action", get("action"), get("target"), get("rule"))
	case "ask_timeout":
		return fmt.Sprintf("%s  %-8s %s pid %s, nobody answered", when, "ask", get("rule"), get("pid"))
	case "classifier":
		return fmt.Sprintf("%s  %-8s %s -> %s%s ask=%s", when, "model", get("question"), get("answer", "choice"), get("answer", "noul"), get("ask"))
	case "sensor_health":
		return fmt.Sprintf("%s  %-8s %s %s %s", when, "sensor", get("sensor"), get("state"), get("detail"))
	case "error", "rule_error", "classifier_error":
		return fmt.Sprintf("%s  %-8s %s %s", when, "error", get("component"), get("error"))
	case "start", "stop", "llm_escalation", "notify_subscribed":
		return fmt.Sprintf("%s  %-8s %s", when, "daemon", r.Kind)
	}
	return ""
}

// runEvents prints the last n readable lines and, with follow, keeps printing.
func runEvents(cfg *config.Config, n int, follow bool) error {
	records, err := readLog(cfg, time.Time{})
	if err != nil {
		return err
	}
	var lines []string
	for _, r := range records {
		if line := summarize(r); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	if !follow {
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	seen := len(records)
	for ctx.Err() == nil {
		time.Sleep(time.Second)
		records, err = readLog(cfg, time.Time{})
		if err != nil {
			return err
		}
		for _, r := range records[min(seen, len(records)):] {
			if line := summarize(r); line != "" {
				fmt.Println(line)
			}
		}
		seen = len(records)
	}
	return nil
}

// runReport summarizes a period: which rules fired at which stage, asks and answers, actions.
func runReport(cfg *config.Config, period time.Duration) error {
	records, err := readLog(cfg, time.Now().Add(-period))
	if err != nil {
		return err
	}
	type key struct{ rule, stage string }
	rules := map[key]int{}
	actions := map[string]int{}
	var asks, timeouts, errors, classified, events int
	var heartbeat map[string]any
	for _, r := range records {
		var d map[string]any
		_ = json.Unmarshal(r.Data, &d)
		switch r.Kind {
		case "verdict":
			v, _ := d["verdict"].(map[string]any)
			rules[key{fmt.Sprint(v["rule"]), fmt.Sprint(v["stage"])}]++
			if acts, _ := v["actions"].([]any); containsAny(acts, "ask") {
				asks++
			}
		case "action":
			actions[fmt.Sprint(d["action"])]++
		case "ask_timeout":
			timeouts++
		case "error", "rule_error", "classifier_error":
			errors++
		case "classifier":
			classified++
		case "heartbeat":
			heartbeat = d
		}
	}
	fmt.Printf("Overlord report, last %s, %d log records\n\n", period, len(records))
	if heartbeat != nil {
		if stats, ok := heartbeat["stats"].(map[string]any); ok {
			events = int(toFloat(stats["events"]))
		}
		sensor := "eslogger disabled"
		if es, ok := heartbeat["eslogger"].(map[string]any); ok {
			sensor = fmt.Sprintf("eslogger alive=%v events=%v restarts=%v", es["alive"], es["lines"], es["restarts"])
		}
		fmt.Printf("sensors   %s; %d events seen since start, %v processes in the graph\n", sensor, events, heartbeat["processes"])
	} else {
		fmt.Println("sensors   no heartbeat in this period: the daemon was not running")
	}
	if len(rules) == 0 {
		fmt.Println("rules     nothing fired")
	} else {
		fmt.Println("rules     fired")
		keys := make([]key, 0, len(rules))
		for k := range rules {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return rules[keys[i]] > rules[keys[j]] })
		for _, k := range keys {
			fmt.Printf("          %5d  %-36s %s\n", rules[k], k.rule, k.stage)
		}
	}
	fmt.Printf("asks      %d asked, %d unanswered\n", asks, timeouts)
	if len(actions) > 0 {
		var parts []string
		for a, n := range actions {
			parts = append(parts, fmt.Sprintf("%s %d", a, n))
		}
		sort.Strings(parts)
		fmt.Println("actions  ", strings.Join(parts, ", "))
	}
	if classified > 0 {
		fmt.Printf("model     %d questions answered\n", classified)
	}
	if errors > 0 {
		fmt.Printf("errors    %d (overlord events shows them)\n", errors)
	}
	labels, _ := os.ReadFile(filepath.Join(cfg.DataDir, "labels", "overlord.ndjson"))
	if n := strings.Count(string(labels), "\n"); n > 0 {
		fmt.Printf("labels    %d decisions recorded in total\n", n)
	}
	return nil
}

func containsAny(list []any, s string) bool {
	for _, x := range list {
		if fmt.Sprint(x) == s {
			return true
		}
	}
	return false
}

func toFloat(v any) float64 {
	f, _ := v.(float64)
	return f
}

// runRecord writes raw eslogger output to a file for later replay. Root only.
func runRecord(cfg *config.Config, path string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo overlord record day.ndjson")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cmd := exec.CommandContext(ctx, cfg.Sensors.ESLogger.Binary, cfg.Sensors.ESLogger.Events...)
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	fmt.Fprintf(os.Stderr, "recording to %s; Ctrl-C to stop, then: overlord replay %s\n", path, path)
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	return err
}
