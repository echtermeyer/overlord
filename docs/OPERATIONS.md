# Operations

## Install on one Mac from source

```sh
brew install go
git clone https://github.com/echtermeyer/overlord && cd overlord
make test
make install                       # sudo: binary, rules, policy, pf anchor, LaunchDaemon, LaunchAgent
overlord install-hooks claude      # as yourself; also: codex, cursor, gemini
```

Then give `eslogger` Full Disk Access, or the daemon sees no host events:

- with MDM: install `packaging/overlord-fda.mobileconfig`;
- by hand: System Settings, Privacy & Security, Full Disk Access, add `/usr/bin/eslogger`
  (press Cmd-Shift-G in the file dialog to type the path).

Check:

```sh
sudo overlord status               # eslogger.alive must be true, lines must grow
overlord simulate stealer          # should log host.stealer-pattern within a second
sudo tail -f /var/db/overlord/log/overlord.ndjson | grep '"verdict"'
```

Central rollout instead of per-user hooks: `packaging/claude-managed-settings.json` goes to
`/Library/Application Support/ClaudeCode/managed-settings.json` (its `allowManagedHooksOnly`
blocks every user and project hook, so developers cannot remove it), and
`packaging/cursor-hooks.json` to `/Library/Application Support/Cursor/hooks.json`. Both are
MDM-friendly files.

Codex and Gemini CLI have no "ask": a rule in stage `ask` denies there, with the reason. Codex
needs the hook trusted once with `/hooks` inside Codex. Cursor's `beforeReadFile` knows only
allow and deny, so an ask on a file read denies.

## Files

| Path | What |
| --- | --- |
| `/Library/Overlord/bin/overlord` | the binary (daemon, hook, notify, CLI) |
| `/Library/Overlord/config.yaml` | overrides of the embedded defaults; unknown keys stop the daemon |
| `/Library/Overlord/policy.yaml` | stage per rule and named allowlists |
| `/Library/Overlord/rules/*.yaml` | rules and tables; absent files fall back to the embedded copies |
| `/Library/Overlord/sink.token`, `anthropic.key` | secrets, root-only, never in YAML |
| `/var/db/overlord/log/overlord.ndjson` | the hash-chained log; `overlord verify-log <file>` checks it |
| `/var/db/overlord/labels/overlord.ndjson` | every Allow or Block with its snapshot |
| `/var/db/overlord/allow.ndjson` | "Allow always" entries |
| `/var/db/overlord/quarantine/`, `manifests/` | quarantined files and how to undo |
| `/var/db/overlord/known-binaries`, `known-destinations` | what this Mac has seen before |
| `/var/run/overlord.sock` | the only inbound channel |

## Moving a rule up a stage

Every rule starts in `shadow`. The log shows what it would have done. The gate:

1. Record benign days: `sudo eslogger exec fork exit open create rename unlink btm_launch_item_add sudo > day.ndjson`
   while you work as usual (installs, builds, tests, git). Keep these private; they contain paths.
2. `overlord replay day.ndjson` for every recorded day. A rule may go to `ask` only with zero
   hits across all of them.
3. In `ask`, every hit freezes or asks. When every answered ask in real use was Block, the rule
   may go to `enforce` in `policy.yaml`.
4. Edit `/Library/Overlord/policy.yaml` and `sudo launchctl kickstart -k system/com.overlord.daemon`.

## Answering asks

The notify agent shows a dialog with Block, Allow once and Allow always. No answer within
`ask.timeout` leaves a frozen process frozen until `ask.freeze_timeout`, then
`ask.frozen_on_timeout` decides (`keep`, `kill` or `resume`). Away from the keyboard, the
webhook gets the text; there is no remote Allow.

`overlord allow <rule> <team_id|signing_id|cdhash|path> <value>` adds an entry by hand.

## Undo

```sh
sudo overlord manifests            # quarantines, disabled launch items, pf blocks
sudo overlord undo <manifest-id>
sudo overlord resume <pid>
```

## External log sink

```sh
go build ./cmd/overlord-sink
./overlord-sink -listen 127.0.0.1:8760 -dir /srv/overlord -token-file /etc/overlord-sink.token -webhook https://hooks.slack.com/...
```

Put TLS in front (Caddy, a load balancer) and the directory on storage with a retention lock.
On each Mac: `logs.ship.url: https://sink.example/ingest` in `config.yaml`, the token in
`/Library/Overlord/sink.token`. The sink alerts when a host's heartbeat is older than five minutes.

## Classifier

Optional second tier. Run a `/v1/systemone` server on the Mac and point Overlord at it:

```sh
git clone https://github.com/jaredpalmer/kev && cd kev
uv sync --extra serve
uv run --extra serve python -m kev.serve --run jaredpalmer/kev-0.8b --port 8009   # Apple Silicon, any size
```

`config.yaml`:

```yaml
classifier:
  url: http://127.0.0.1:8009
  model: kev-latest
```

Questions live in `rules/questions.yaml`; each is a pseudo-rule `classifier.<id>` staged in
`policy.yaml` like any rule. In shadow, `kind: classifier` log records hold every answer; compare
them with `labels/overlord.ndjson` before moving a question to ask. Laya works through
laya.cpp's Jev-compatible server on the same URL.

## Sigma rules

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma
./overlord sigma sigma/rules/macos/process_creation/*.yml sigma/rules-emerging-threats/*/Malware/*MacOS*/*.yml > sigma.yaml
sudo install -m 644 sigma.yaml /Library/Overlord/rules/sigma.yaml
```

Unsupported rules are skipped with a reason. Converted rules are `alert` only and start in
shadow; stage them like any other rule.

## Santa

Install Santa, point its `SyncBaseURL` at `http://127.0.0.1:8750/` and set
`sensors.santa.enabled: true`. Overlord answers in MONITOR mode and pushes blocklist rules
for binaries the person blocked. Santa refuses the next execution of those even in monitor mode.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `eslogger.alive: false`, restarts climbing | no Full Disk Access for `/usr/bin/eslogger`, or the daemon is not root |
| hooks deny nothing | `overlord install-hooks <agent>` not run for this user, or the agent was started before |
| asks never appear | the notify LaunchAgent is not running for the console user: `launchctl print gui/$(id -u)/com.overlord.notify` |
| `overlord status` fails | daemon not running: `sudo launchctl print system/com.overlord.daemon`, `/var/db/overlord/daemon.err` |
| config error at start | an unknown key in `config.yaml`; the error names it |
