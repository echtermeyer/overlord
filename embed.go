// Package overlord embeds the rule tables, default policy and default configuration so the
// hook works without files on disk and the daemon has defaults when /Library/Overlord is empty.
package overlord

import "embed"

//go:embed rules/*.yaml policy.yaml config.yaml packaging/*.plist packaging/pf.anchor packaging/claude-managed-settings.json
var Files embed.FS

// Version is set at build time: -ldflags "-X github.com/echtermeyer/overlord.Version=v0.1.0".
var Version = "dev"
