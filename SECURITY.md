# Security

Overlord runs as root and decides what other software may do. A bug here matters more than in
most projects.

**Reporting.** Email the maintainer address on the GitHub profile of `echtermeyer`, or open a
GitHub security advisory on this repository. Do not open a public issue for something exploitable.
You will get an answer, and a fix or a workaround, before anything is published.

**What counts.** A way for a non-root process or an agent to: change rules, policy or the allow
store; stop or blind the daemon without a heartbeat gap; answer an ask that is not theirs; make
the daemon act on a process it should not touch (kill, quarantine, block); or read secrets through
the socket. Also: a rule that can be bypassed by rewriting a command in an obvious way counts as
a bug, and so does a rule that fires on ordinary developer work.

**What does not.** An attacker who is already root, has physical access, or runs a kernel exploit.
The Endpoint Security notify stream can be delayed under load; a race between a stealer's first
read and the daemon's freeze is a known limit of the asynchronous host sensors.

**Supply chain.** Releases are built in GitHub Actions from a tag, with a checksum next to the
binary. Dependencies are pinned in `go.mod` and checked with `govulncheck` in CI.
