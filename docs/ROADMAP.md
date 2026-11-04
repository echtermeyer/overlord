# Roadmap

Phases end at a gate, not a date. A phase ships when its gate holds on our own machines.

## Phase 0: observe

- Go module, `overlord daemon` as a root LaunchDaemon, `eslogger` ingestion, process graph in memory
  and SQLite, tags for terminals and package managers.
- Log ring, hash chain, HTTPS shipper, heartbeat; reference sink on object storage with retention lock.
- Signed and notarized `.pkg`, MDM profile for Full Disk Access.
- All rules in shadow. `overlord replay`, `overlord simulate stealer`.

Gate: a week of our own machines in the graph, the stealer simulation fires `host.stealer-pattern`
with the right process chain, and the benign corpus is recorded.

## Phase 1: agent guard

- `overlord hook` for Claude Code, then Codex, Cursor and Gemini CLI; session and pid tagging.
- Certain rules embedded in the hook. `agent.*` rules to `ask`, `overlord notify` dialogs, webhook.
- Labels stored for every click.

Gate: an agent session's processes carry its tag in the graph; `agent.pipe-to-shell` and
`agent.self-tamper` deny without the daemon running; no benign-corpus hits for any rule in `ask`.

## Phase 2: host response

- Freeze and ask for `host.*` rules; quarantine and undo; launch-item disable; `pf` anchor blocks.
- Santa sync endpoint, block rules by team id, signing id and hash.
- Signed policies with minisign. Sigma macOS rule import. LLM sidecar with Ollama.

Gate: the stealer simulation is frozen within a second of its second secret category read, undo
restores everything, and the real asks of the previous phase were all Block.

## Phase 3: network and UI

- Network Extension content filter in Swift: flows with process identity, synchronous blocks,
  default-deny for agent-tagged processes with a per-project allowlist.
- Menu-bar app replacing the dialogs.

Gate: an agent-driven `curl` to an unlisted host is blocked before the connection opens.

## Later, only with evidence

- A classifier trained on the collected labels, if a class of events the rules cannot separate shows
  up in the data.
