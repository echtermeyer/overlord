# Writing rules

A rule is YAML with a [CEL](https://github.com/google/cel-spec) condition. The engine evaluates
every rule whose `on` lists the event's kind.

```yaml
- id: host.password-dialog          # unique, "<area>.<name>"
  threat: T1                        # T1 stealer, T2 agent, T3 supply chain (docs/DESIGN.md)
  on: exec                          # one kind or a list
  when: >                           # CEL, must be bool; absent means always
    target.name == "osascript" && target.cmdline.contains("hidden answer") && !process.trusted
  confidence: likely                # certain | likely | possible
  actions: [freeze, ask]            # what the rule wants; the stage caps it
  escalate_when: ...                # optional second condition
  escalate_actions: [kill]          # used instead of actions when escalate_when holds
  explain: "{{.process.name}} ..."  # Go text/template over the same variables
```

## Event kinds

`exec fork exit file_open file_create file_write file_rename file_unlink launch_item_add
launch_item_remove sudo tcc_modify xp_malware_detected ssh_login remote_thread_create mount
kextload tool_call tool_result net_connect santa_exec`

## Variables

| Variable | Type | Content |
| --- | --- | --- |
| `event` | map | `kind`, `path`, `destPath`, `write`, `detail` (map of strings), `launchItem` (`type`, `itemURL`, `executable`, `legacy`), `exitStatus` |
| `path` | string | shortcut for `event.path` |
| `process` | map | the acting process: `key`, `pid`, `name`, `path`, `args`, `cmdline`, `cwd`, `uid`, `signingId`, `teamId`, `cdhash`, `platform`, `trusted`, `firstSeen`, `tty`, `tags` (map), `ancestors` (list of `name`, `path`, `pid`, `tags`), `persistence` (count) |
| `target` | map | same shape: the new image on `exec`, the victim on `remote_thread_create` |
| `call` | map | tool calls: `agent`, `session`, `tool`, `command`, `paths`, `cwd`, `project` |
| `session` | map | the agent session: `id`, `agent`, `project`, `calls` (list of `tool`, `command`) |
| `dest` | map | `net_connect`: `address`, `port`, `seenBefore` |

`trusted` is true for Apple platform binaries and for team ids in `graph.trusted_teams`.
`firstSeen` is true the first time this Mac runs a binary with this cdhash.

Tags come from `rules/tags.yaml` (by executable path) and from hooks (`agent`, `project`), and
every descendant inherits them. `process.tag("installer")` is `"brew"`, `"npm"` and so on, or `""`.

## Functions

| Call | Returns |
| --- | --- |
| `process.tag(name)` | the tag's value or `""` |
| `process.reads(within)` | sensitive reads in the window, each `path` and `category`; `within` like `"60s"`, `"10m"` |
| `process.readCategories(within)` | distinct categories in the window |
| `process.outbound(within)` | connections in the window, each `address`, `port`, `seenBefore` |
| `process.inAllowlist(name)` | whether the process is in that named list in `policy.yaml` |
| `session.reads(within)`, `session.readCategories(within)` | the same across every process of the agent session |
| `string.category()` | the sensitive category of a path, from `rules/sensitive_paths.yaml`, or `""` |
| `string.matchesAny(list)` | glob match with `**` and `~` for any home directory |
| `string.matches(re)` | RE2 regular expression (no look-around) |

The CEL `strings`, `lists` and `sets` extensions are loaded: `contains`, `startsWith`, `split`,
`join`, `filter`, `exists`, `size`, `in`.

Categories in `rules/sensitive_paths.yaml`: `browser keychain ssh cloud registry env gpg wallet
agent password_manager messaging overlord`. Rules usually exclude `env` and `agent`: every agent
session reads them.

## Stages and actions

| Stage | What the engine permits |
| --- | --- |
| `shadow` | nothing; the verdict is logged with what it would have done |
| `ask` | `ask`, `freeze`, `deny`, `alert`, `block_new_destinations`, `quarantine_if_blocked` |
| `enforce` | everything the rule lists; `kill` only with `confidence: certain` or after escalation |

Actions: `deny` (tool calls), `ask`, `freeze`, `kill`, `quarantine`, `quarantine_if_blocked`,
`block_new_destinations`, `disable_launch_item`, `santa_block`, `alert`.

A rule fires at most once per process per `rules.repeat_after`; an escalation fires once more.

## Testing a rule

```sh
go test ./internal/rules/                  # table of calls and expectations
./overlord replay recorded-day.ndjson      # counts per rule on real activity
```
