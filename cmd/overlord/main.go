// Command overlord is the daemon, the hook, the notifier and the operator's CLI in one binary.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	overlord "github.com/echtermeyer/overlord"
	"github.com/echtermeyer/overlord/internal/config"
	"github.com/echtermeyer/overlord/internal/daemon"
	"github.com/echtermeyer/overlord/internal/hooks"
	"github.com/echtermeyer/overlord/internal/ipc"
	"github.com/echtermeyer/overlord/internal/logs"
	"github.com/echtermeyer/overlord/internal/notify"
	"github.com/echtermeyer/overlord/internal/simulate"
)

const usage = `overlord <command> [flags]

  daemon                 run the root service (LaunchDaemon)
  hook <agent>           agent hook: claude | cursor | gemini (reads the agent's JSON on stdin)
  notify                 per-user agent that shows asks as dialogs (LaunchAgent)
  install-hooks <agent>  wire the hook into the agent's settings for this user
  status                 what the daemon sees and does
  replay <file.ndjson>   run recorded eslogger output through the rules, no actions
  simulate stealer       harmless stealer behaviour to test detection
  allow <rule> <kind> <value>   quiet a rule for a team_id | signing_id | cdhash | path
  allowlist              show allow entries
  manifests              show quarantines, disabled launch items and blocks
  undo <manifest-id>     put a quarantined file or launch item back, or lift a block
  resume <pid> | kill <pid>
  verify-log <file>      check a log file's hash chain
  version

Flags: -config <path> (default /Library/Overlord/config.yaml)
`

func main() {
	fs := flag.NewFlagSet("overlord", flag.ExitOnError)
	configPath := fs.String("config", config.DefaultPath, "configuration file")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		// Allow "overlord status -config x" as well as "overlord -config x status".
		cmd := args[0]
		_ = fs.Parse(args[1:])
		args = append([]string{cmd}, fs.Args()...)
	} else {
		_ = fs.Parse(args)
		args = fs.Args()
	}
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	if err := run(cfg, args); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "overlord:", err)
	os.Exit(1)
}

func run(cfg *config.Config, args []string) error {
	client := ipc.Client{Path: cfg.Socket, Timeout: 5 * time.Second}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Println(overlord.Version)
		return nil
	case "daemon":
		return runDaemon(cfg)
	case "hook":
		if len(rest) != 1 {
			return fmt.Errorf("usage: overlord hook <%s>", strings.Join(hooks.Adapters(), "|"))
		}
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		out, exit, err := hooks.Run(rest[0], stdin, cfg.Socket, cfg.Hook.DaemonTimeout)
		if err != nil {
			return err
		}
		if len(out) > 0 {
			os.Stdout.Write(out)
		}
		os.Exit(exit)
	case "install-hooks":
		if len(rest) != 1 {
			return fmt.Errorf("usage: overlord install-hooks <%s>", strings.Join(hooks.Adapters(), "|"))
		}
		path, err := hooks.Install(rest[0], executablePath())
		if err != nil {
			return err
		}
		fmt.Println("hooks written to", path)
		return nil
	case "notify":
		return runNotify(cfg)
	case "status":
		var status daemon.StatusReport
		if err := client.Call("status", nil, &status); err != nil {
			return err
		}
		return printJSON(status)
	case "replay":
		if len(rest) != 1 {
			return fmt.Errorf("usage: overlord replay <file.ndjson>")
		}
		return runReplay(cfg, rest[0])
	case "simulate":
		if len(rest) != 1 || rest[0] != "stealer" {
			return fmt.Errorf("usage: overlord simulate stealer")
		}
		return simulate.Stealer(os.Stdout)
	case "allow":
		if len(rest) != 3 {
			return fmt.Errorf("usage: overlord allow <rule> <team_id|signing_id|cdhash|path> <value>")
		}
		var entry daemon.AllowEntry
		if err := client.Call("allow", daemon.AllowEntry{Rule: rest[0], Kind: rest[1], Value: rest[2]}, &entry); err != nil {
			return err
		}
		return printJSON(entry)
	case "allowlist", "manifests":
		var out any
		if err := client.Call(cmd, nil, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "undo":
		if len(rest) != 1 {
			return fmt.Errorf("usage: overlord undo <manifest-id>")
		}
		return client.Call("undo", map[string]string{"id": rest[0]}, nil)
	case "resume", "kill":
		if len(rest) != 1 {
			return fmt.Errorf("usage: overlord %s <pid>", cmd)
		}
		pid, err := strconv.Atoi(rest[0])
		if err != nil {
			return err
		}
		return client.Call(cmd, map[string]int{"pid": pid}, nil)
	case "verify-log":
		if len(rest) != 1 {
			return fmt.Errorf("usage: overlord verify-log <file>")
		}
		n, err := logs.Verify(rest[0])
		if err != nil {
			return err
		}
		fmt.Printf("%d records, chain intact\n", n)
		return nil
	}
	return fmt.Errorf("unknown command %q\n%s", cmd, usage)
}

func executablePath() string {
	p, err := os.Executable()
	if err != nil {
		return "overlord"
	}
	return p
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runDaemon(cfg *config.Config) error {
	if os.Geteuid() != 0 && cfg.Sensors.ESLogger.Enabled {
		return fmt.Errorf("the daemon must run as root (eslogger needs it); for a hooks-only trial set sensors.eslogger.enabled: false")
	}
	d, err := daemon.New(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx)
}

func runReplay(cfg *config.Config, path string) error {
	tmp, err := os.MkdirTemp("", "overlord-replay-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	cfg.DataDir = tmp
	cfg.Logs.Dir = tmp + "/log"
	cfg.Socket = tmp + "/sock"
	d, err := daemon.New(cfg)
	if err != nil {
		return err
	}
	d.Dry = true
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	counts, lines, err := d.Replay(f)
	if err != nil {
		return err
	}
	fmt.Printf("%d lines, %d processes in the graph\n", lines, d.Graph().Len())
	if len(counts) == 0 {
		fmt.Println("no rule fired")
		return nil
	}
	for rule, n := range counts {
		fmt.Printf("%-40s %5d  stage=%s\n", rule, n, d.Policy().Stage(rule))
	}
	fmt.Println("verdict details:", cfg.Logs.Dir+"/overlord.ndjson (deleted with this temp dir; pass -config to keep logs elsewhere)")
	return nil
}

func runNotify(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client := ipc.Client{Path: cfg.Socket, Timeout: 5 * time.Second}
	for ctx.Err() == nil {
		err := client.Subscribe(ctx, "subscribe", nil, func(resp ipc.Response) (any, error) {
			var ask notify.Ask
			if err := json.Unmarshal(resp.Payload, &ask); err != nil || ask.ID == "" {
				return nil, nil // ping
			}
			choice, _ := notify.Dialog(ctx, ask)
			return notify.Answer{ID: ask.ID, Choice: choice}, nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "notify:", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

var _ = bufio.NewScanner
