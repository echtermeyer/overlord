# Overlord

A local security daemon for developer Macs. It watches what runs on the machine, attributes every
process, file access and connection to where it came from (which app, which coding-agent session,
which project), and stops the few things that are clearly dangerous: infostealers, data leaving the
machine, persistence, and coding agents that break out of their task.

Status: phase 0 and 1 of [docs/ROADMAP.md](docs/ROADMAP.md) are implemented and tested; the host
rules run in shadow mode until they pass the false-positive gate. Read [docs/DESIGN.md](docs/DESIGN.md)
for the why, [docs/OPERATIONS.md](docs/OPERATIONS.md) to run it.

```sh
brew install go && git clone https://github.com/echtermeyer/overlord && cd overlord
make test && make install            # root daemon, pf anchor, notify agent
overlord install-hooks claude        # per user; also codex, cursor, gemini
overlord simulate stealer            # watch host.stealer-pattern fire in the log
```

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
