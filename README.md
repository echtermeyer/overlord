# Overlord

A local security daemon for developer Macs. It watches what runs on the machine, attributes every
process, file access and connection to where it came from (which app, which coding-agent session,
which project), and stops the few things that are clearly dangerous: infostealers, data leaving the
machine, persistence, and coding agents that break out of their task.

Status: working, tested, not yet proven on a fleet. Read [docs/DESIGN.md](docs/DESIGN.md) for the
why and [docs/OPERATIONS.md](docs/OPERATIONS.md) for running it.

## Install

```sh
brew install go
go install github.com/echtermeyer/overlord/cmd/overlord@latest
sudo ~/go/bin/overlord install        # binary, rules, firewall anchor, daemon, notifier
overlord install-hooks claude         # per user; also codex, cursor, gemini
sudo overlord doctor                  # says what is left, usually Full Disk Access for eslogger
```

Then watch it work:

```sh
overlord simulate stealer             # a harmless stealer: freezes and asks within a second
sudo overlord events -f               # live, readable
sudo overlord report                  # the last 24 hours
```

## What it does out of the box

- **Denies** agents that pipe downloads into a shell, decode hidden scripts into a shell, switch
  off protections, or edit their own hooks and guard settings. These rules live inside the hook
  binary too, so they hold while the daemon is down.
- **Asks** through the agent's own permission prompt before sudo, credential reads, destructive
  commands, persistence, or sending data out after reading secrets.
- **Freezes and asks** when an unknown process reads credentials from two places, shows a password
  dialog, drives Finder with AppleScript, decodes a bootstrap, stages an archive and connects to a
  new host, or installs a launch item. Block kills and quarantines; Allow resumes; everything undoes.
- **Logs** every process, read, connection and decision in a hash-chained log you can ship off the
  Mac, with a heartbeat so switching Overlord off is itself an alert.

Everything else starts in log-only mode. `policy.yaml` holds one line per rule to change that.

## Why it exists

- A stealer got onto one of our Macs and was noticed by accident. Nothing on the machine connected
  "new unsigned binary reads browser cookies and SSH keys, then talks to a host nobody has seen".
- Coding agents run `curl | sh`, read `.env` files, push with `--force` and edit their own guard
  configuration. Hook-based guards see the command text; they do not see what the command then
  does to the machine.

## What makes it different

Existing tools cover one half each:

| Tool | Sees | Misses |
| --- | --- | --- |
| Hook guards (agentjail, omamori, dcg) | the tool call text | what the process does afterwards |
| Santa, osquery, LuLu, EDRs | processes, files, binaries, flows | which agent session and project caused them |

Overlord joins both in one process graph and reuses the host tools instead of replacing them. It never
writes its own kernel sensor: Apple's `eslogger` provides the events, Santa provides binary blocking,
the agents' hook interfaces provide synchronous denies, `pf` blocks destinations.

Decisions come in three tiers: deterministic rules (CEL in YAML, Sigma convertible), an optional
local decision model (Kev or Laya over the `/v1/systemone` contract) that answers typed questions
about what the rules let through, and an optional local LLM that explains asks. Neither model can
allow anything.

## Principles

- **Local.** Decisions and data stay on the Mac. Only tamper-evident logs and heartbeats leave it.
- **Monitor first.** Every rule starts in shadow mode and must prove a zero false-positive rate on
  recorded benign developer activity before it may ask, and must survive real asks before it may act.
- **Freeze, don't kill.** Suspicious processes are stopped with `SIGSTOP` and the person decides.
- **Asymmetric.** Automation may only take capabilities away. Nothing automated grants access, and
  the LLM can explain, escalate and deny, never allow.
- **Reversible by construction.** Every automatic action has an undo: resume the process, restore the
  quarantined file, drop the firewall rule, re-enable the launch item.
- **Small.** One static Go binary, a handful of dependencies, no listening network ports.

## What it does not do

It does not catch wrong code or wrong logic; tests, CI and review do that. It does not defend against
an attacker who already has root, physical access, or a kernel exploit.

## License

Apache-2.0. See [LICENSE](LICENSE).
