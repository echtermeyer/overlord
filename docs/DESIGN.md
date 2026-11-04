# Overlord design

Status: implemented as designed below, except where a section says otherwise. Checked against
macOS 15.7 on 2026-11-04. See docs/OPERATIONS.md to run it.

## 1. Threats it is built for

| | Threat | How it shows on the host |
| --- | --- | --- |
| T1 | Infostealer delivered by a fake installer page, a package post-install script, a poisoned cask or a cracked app | A process that is not an Apple platform binary and not a known notarized app reads browser cookie or login databases, Keychains, `~/.ssh`, cloud credentials or wallets, then opens an outbound connection to a host this machine has never contacted. Often `osascript` shows a password dialog first. Persistence as a LaunchAgent, LaunchDaemon or login item. |
| T2 | A coding agent that breaks out of its task, by mistake or by prompt injection | `curl \| sh`, reading secrets and sending them out, `rm -rf` outside the project, `git push --force`, writing to its own hook or settings files, installing persistence, calling `sudo`. |
| T3 | Supply chain inside developer tooling | npm, pip, cargo and brew post-install scripts, MCP servers, editor extensions that behave like T1 while running under a trusted parent. |

Out of scope: wrong code, wrong logic, an attacker who already has root, kernel exploits, physical access.

## 2. Constraints that shaped the design

1. **No own Endpoint Security client.** The `com.apple.developer.endpoint-security.client` entitlement
   must be requested from Apple; developers report waits of a year. Apple's built-in `/usr/bin/eslogger`
   streams the same notify events as JSON and needs only root plus Full Disk Access, which an MDM
   profile grants (`SystemPolicyAllFiles`). It carries no auth events, so it cannot block.
2. **Synchronous blocking exists at three points without special entitlements:** the agents' hook
   interfaces (Claude Code and Codex CLI `PreToolUse` with `permissionDecision: deny`, Cursor's
   `hooks.json`, Gemini CLI's `BeforeTool`; Copilot CLI once its hook interface is verified), Santa's blocklist (applies even in monitor mode; Overlord serves as its sync server),
   and the `pf` firewall.
3. **Per-process network attribution needs a Network Extension content filter.** That entitlement is
   routine for a paid developer account but needs Developer ID signing and notarization. It is a later
   phase. Until then, network visibility is socket polling with `lsof` once a second: coarse,
   enough for "new process talks to a never-seen host".
4. **Developer machines must stay usable.** Anything automatic must be reversible or have
   near-certain confidence. A guard that blocks `npm install` once is uninstalled the same day.

## 3. Architecture

```
            Claude Code / Codex / Cursor / Gemini CLI
                      │ hook (sync, unix socket)
                      ▼
 eslogger ─┐    ┌──────────────────────────────────────────┐
 Santa sync┼───▶│ overlordd (root LaunchDaemon, one Go binary)│
 pf log    │    │  events → process graph → rules (CEL)      │
 sockets  ─┘    │       → actions, asks, log shipper          │
                └───────┬──────────────┬───────────┬─────────┘
                        │ unix socket  │ loopback  │ HTTPS, append-only
                        ▼              ▼           ▼
                 overlord notify   LLM sidecar   log sink + heartbeat
                 (user LaunchAgent) (Ollama or    (object storage with
                 dialogs, webhook)   Claude, opt-in) retention lock)
```

One binary, `overlord`, with subcommands:

| Subcommand | Runs as | Does |
| --- | --- | --- |
| `daemon` | root, LaunchDaemon | sensors, graph, rules, actions, log shipping, Santa sync endpoint |
| `hook <agent>` | the developer, called by the agent | sends the tool call to the daemon, prints the agent's expected verdict JSON; embeds the hard rules so a dead daemon still denies the worst |
| `notify` | the developer, LaunchAgent | shows asks as dialogs, sends webhooks, returns decisions |
| `status`, `allow`, `undo`, `rules test`, `replay`, `simulate` | the developer or admin | operations and testing |

### 3.1 Sensors

| Sensor | Events | Blocking | Phase |
| --- | --- | --- | --- |
| `eslogger` child process | `exec fork exit open create rename unlink link setextattr mount kextload btm_launch_item_add btm_launch_item_remove sudo su tcc_modify profile_add openssh_login remote_thread_create proc_suspend_resume xp_malware_detected` | no | 0 |
| Agent hooks | tool calls with session id, cwd, project, agent pid, before and after execution | yes, synchronous | 1 |
| Santa (optional) | new binary executions with hash, signing id, team id; blocklist by hash, signing id or team id | yes, asynchronous (next execution) | 2 |
| socket polling (`lsof -i` each second) | outbound connections per process | destination block via `pf` anchor | 2 |
| Network Extension (Swift) | flows with process audit token | yes, synchronous | 3 |

`eslogger` output is parsed as NDJSON on a pipe. If it exits it is restarted and the gap is logged as a
sensor health event. Event volume during builds reaches thousands per second; the parser keeps only
the fields the graph needs and drops the rest before any allocation.

### 3.2 Process graph

Every process is a node keyed by pid and pidversion (from the audit token, so pid reuse never
merges two processes). A node holds:

- executable path, cdhash, signing id, team id, platform-binary flag, notarization known or not
- arguments, cwd, uid, start time, parent, responsible process
- tags, inherited by every descendant: `agent:<session>`, `project:<path>`, `installer:<brew|npm|pip|cargo>`, `terminal`
- counters with timestamps: sensitive reads by category, outbound destinations, persistence writes, children

The graph lives in memory; exited processes are evicted after the retention window. What this
Mac has seen before (binaries by cdhash, destinations) persists in append-only files under
`/var/db/overlord/`, and the log holds every verdict with its process snapshot for investigation. The hook reports the agent's pid and session id, which is what links agent
intent to host events: a `curl` whose ancestor is a tagged agent process is the agent's `curl`.

Sensitive paths are a table, not code (`rules/sensitive_paths.yaml`), with a category per row:
browser cookie and login databases, Keychains, `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`,
`~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.gnupg`, `.env*`, wallet directories,
`~/.claude`, `~/.codex`, `~/.cursor`, password-manager data.

### 3.3 Rules

Rules are YAML with [CEL](https://github.com/google/cel-go) conditions over a typed event and its graph
context. CEL is sandboxed, fast and already a language; Overlord does not invent one. Sigma's macOS
rules can be imported by a converter later; they are not the native format.

```yaml
- id: agent.pipe-to-shell
  threat: T2
  on: tool_call
  when: >
    call.tool == "Bash" &&
    call.command.matches("(curl|wget)[^|]*\\|\\s*(sudo\\s+)?(ba|z)?sh")
  confidence: certain
  actions: [deny]
  explain: "The agent wants to download a script and run it unseen."

- id: agent.secret-then-egress
  threat: T2
  on: tool_call
  when: >
    call.tool == "Bash" &&
    call.command.matches("\\b(curl|wget|nc|scp|rsync)\\b") &&
    session.reads(category: "secret", within: "10m").size() > 0
  confidence: likely
  actions: [ask]
  explain: "This session read {{session.reads}} and now wants to send data out."

- id: agent.self-tamper
  threat: T2
  on: [tool_call, file_write]
  when: >
    path.matchesAny(["~/.claude/settings*.json", "**/.claude/settings*.json",
                     "~/.codex/**", "/Library/Overlord/**", "/Library/LaunchDaemons/com.overlord.*"])
    && process.tag("agent") != ""
  confidence: certain
  actions: [deny, alert]

- id: host.stealer-pattern
  threat: T1
  on: file_open
  when: >
    !process.platform && !process.notarizedKnown &&
    process.reads(category: "secret", within: "60s").categories().size() >= 2
  confidence: likely
  actions: [freeze, ask, block_new_destinations]
  escalate_when: process.outbound(within: "60s").exists(d, !d.seenBefore)
  escalate_actions: [kill, quarantine]

- id: host.password-dialog
  threat: T1
  on: exec
  when: >
    process.name == "osascript" &&
    process.args.join(" ").contains("hidden answer")
  confidence: likely
  actions: [freeze, ask]

- id: host.persistence
  threat: T1
  on: [launch_item_add, file_create]
  when: >
    (event.kind == "launch_item_add" || path.matchesAny(["~/Library/LaunchAgents/*", "/Library/LaunchAgents/*", "/Library/LaunchDaemons/*"]))
    && !process.inAllowlist("installers")
  confidence: likely
  actions: [ask, quarantine_if_blocked]

- id: host.xprotect
  threat: T1
  on: xp_malware_detected
  confidence: certain
  actions: [alert]
```

Every rule has a **stage**: `shadow` (log only), `ask` (freeze and ask where possible, alert
otherwise) or `enforce` (its listed actions). The stage is set per rule in the installed policy, never in
the rule file, and the engine caps actions by stage. New rules always ship in `shadow`.

### 3.4 Decision tiers

1. **Rules** decide almost everything deterministically. They are the only tier that may kill or
   quarantine.
2. **LLM sidecar**, only for events a rule marked `ask`. It receives the subgraph (process chain, the
   last minute of its file and network activity, the agent's recent tool calls if any), returns a
   plain-language explanation for the dialog and may upgrade `ask` to `deny` for agent tool calls.
   It can never allow and never act on host processes. Default model is local through Ollama;
   the Claude API is an opt-in that sends only that subgraph. The hook waits at most a configured
   budget for it; after that the rule's own verdict stands.
3. **Classifier**: not in version 1. There are no labels yet, and the earlier plan's named
   classifiers are not something we could verify. Every Allow or Block click is stored from day one
   as a label with its subgraph snapshot. A classifier is built only if, after the shadow phase,
   there is a class of events the rules provably cannot separate.

### 3.5 Actions and their undo

| Action | Target | Reversible | Allowed from stage |
| --- | --- | --- | --- |
| `deny` | agent tool call | yes, the agent asks again or chooses another way | ask |
| `ask` | anything | yes | ask |
| `freeze` | process (`SIGSTOP`) | yes (`SIGCONT`), with a timeout that resumes or kills by policy | ask |
| `block_new_destinations` | process's new outbound IPs via `pf` anchor, TTL | yes, rule expires | ask |
| `kill` | process | no | enforce, `confidence: certain` or an escalation after `freeze` |
| `quarantine` | binary or plist moved to `/var/db/overlord/quarantine/<hash>`, mode 000, manifest | yes, `overlord undo` | enforce |
| `disable_launch_item` | `launchctl bootout` plus quarantine of the plist | yes | enforce |
| `santa_block` | hash, signing id or team id rule pushed to Santa | yes, rule removed | enforce |
| `alert` | webhook, dialog | n/a | shadow |

Token revocation is deliberately not an action: there is no safe generic way to revoke a credential
from a daemon. Instead the alert lists exactly which secret files the process read, so the person
rotates the right ones.

### 3.6 Asks and alerts

`overlord notify` runs as the logged-in user, connects to the daemon's unix socket and shows a
dialog: what happened in one sentence, the explanation, the process chain, and three buttons:
**Block**, **Allow once**, **Allow always**. "Allow always" writes an allowlist entry scoped to the
narrowest identity available: team id, else signing id, else cdhash, else path plus project. The
daemon accepts the entry only from the console user over the socket, checked with the peer's uid.

Asks nobody answers within the configured budget default to the safe side: `deny` for agent calls,
`freeze` stays frozen until answered or the timeout policy kills. A webhook (Slack, ntfy, any URL)
carries the same text for people away from the keyboard. There is no remote Allow.

### 3.7 Logs and heartbeat

Every event the rules looked at, every verdict, every click and every action is one NDJSON record.
Records form a hash chain (each carries the hash of the previous one), are kept in a local ring and
shipped over HTTPS with a write-only token to a sink that cannot delete or rewrite: the reference
sink is a small receiver writing to object storage with a retention lock. Command lines and paths
are shipped, file contents never; known secret patterns are redacted before shipping.

A heartbeat every minute carries the daemon's cdhash, config hash, rule-set hash, and sensor health.
The sink alerts when a heartbeat is missing. Switching Overlord off is therefore visible even though
a root attacker could do it.

### 3.8 Self-protection

- The daemon, its plist, its config and its rules are root-owned. Agents and users never run as root,
  and `agent.self-tamper` denies any agent tool call that touches them or calls `sudo`.
- No listening TCP port. The only inbound channel is a unix socket with peer uid checks. Santa's
  sync endpoint is bound to loopback only.
- The daemon watches its own paths with `eslogger` and logs every touch.
- Policies and rule sets are signed with minisign from phase 2; with a public key pinned in the
  config, unsigned policies are refused.
- The hook binary embeds the certain rules, so an agent sees the same denies while the daemon is
  down, and the gap is logged when it comes back.

### 3.9 Language and dependencies

Go. One static binary, no interpreter or site-packages in the root daemon's trust base, cheap
goroutines for the sensors, and the libraries it needs exist: `cel-go` for rules, a pure-Go SQLite,
YAML, minisign. Swift appears only in phase 3 for the Network Extension and a menu-bar app, which
talk to the daemon over the same socket. Dependencies are pinned, scanned with `govulncheck`,
built in GitHub Actions with provenance, and releases are signed and notarized.

### 3.10 Testing and the false-positive gate

- Asks for agent tool calls go back to the agent as `ask`, so the agent's own permission prompt
  shows the reason; the dialog is for host events. `PostToolUse` tells Overlord the person let
  it run, which becomes the label.
- `overlord replay` runs recorded `eslogger` NDJSON through the engine. Two corpora: benign developer
  days (brew upgrade, npm and pip installs, Xcode builds, Docker, pytest, git) recorded on our own
  machines and kept private, and attack days from Atomic Red Team's macOS tests plus
  `overlord simulate stealer`, a harmless script that reads the sensitive paths and posts to localhost.
- A rule moves from `shadow` to `ask` only with zero hits on the whole benign corpus. It moves from
  `ask` to `enforce` only when every answered ask in real use was Block.
- Unit tests for parsing, the graph, tag inheritance and each rule; an integration test that runs the
  daemon in a macOS VM.

## 4. What we deliberately do not build

- An Endpoint Security client of our own.
- A trained classifier before there are labels.
- Default-deny networking for the whole machine. Default-deny applies only to processes tagged as
  agent-driven, and only once the Network Extension exists.
- A native Sigma engine; Sigma rules are imported, not executed.
- Remote approval. Allowing happens at the keyboard.
- Token revocation.

## 5. Open questions to settle in phase 0

1. Whether Santa accepts a plain-HTTP sync server on loopback or needs a local TLS certificate.
2. Which code requirement the Full Disk Access profile must name for `eslogger` started by the daemon.
3. Whether GitHub's macOS runners allow `eslogger` with sudo, or the integration test needs a VM.
4. Which MDM rolls out the package and profiles.
5. Whether to write the Network Extension or fork LuLu's for phase 3.
