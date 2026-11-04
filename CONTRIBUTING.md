# Contributing

Read `docs/DESIGN.md` first; it says why things are the way they are and what we deliberately do
not build. A change that moves a decision there needs evidence, not preference.

## Rules

Rules are data in `rules/*.yaml`; see `docs/RULES.md` for the variables and functions. A new rule
needs:

1. a case in `internal/rules/engine_test.go` that fires it and one that must stay silent;
2. `confidence` and `explain` text a person at the keyboard understands;
3. shadow stage: never add it to `policy.yaml` with `ask` or `enforce` in the same change.

## Code

Go, one binary, no cgo. `make lint` and `make test` must pass. Keep it small: data over branches,
no pass-through layers, one home per setting (`config.yaml` for tunables, files for secrets).
No docstrings; a one-line comment only where the code cannot show the why.

## Pull requests

Rebase on `main`, one topic per pull request, a commit message that says what changed in the
behaviour. CI runs on macOS and must be green.

## What helps most right now

- Recorded benign `eslogger` days from different kinds of developer work, so rules can pass the
  false-positive gate. Paths contain usernames: share only what you are comfortable with, or
  share the replay summary.
- Verification of the Codex, Cursor and Gemini CLI hook shapes against real sessions.
- The phase 3 Network Extension.
