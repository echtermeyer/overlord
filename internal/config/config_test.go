package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAndOverlay(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Socket != "/var/run/overlord.sock" || !c.Sensors.ESLogger.Enabled || c.Ask.FrozenOnTimeout != "keep" {
		t.Errorf("defaults: %+v", c)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(path, []byte("sensors:\n  eslogger:\n    enabled: false\nllm:\n  provider: ollama\n  model: m\n"), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sensors.ESLogger.Enabled || c.LLM.Provider != "ollama" || c.Sensors.Netmon.Interval == 0 || len(c.Sensors.ESLogger.Events) == 0 {
		t.Errorf("overlay lost defaults: %+v", c)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err != nil {
		t.Errorf("missing overlay should use defaults: %v", err)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "sockett: /x\n",
		"bad provider":     "llm:\n  provider: openai\n",
		"bad timeout mode": "ask:\n  frozen_on_timeout: explode\n",
		"long socket":      "socket: /" + strings.Repeat("a", 120) + "\n",
	}
	dir := t.TempDir()
	for name, raw := range cases {
		path := filepath.Join(dir, name+".yaml")
		_ = os.WriteFile(path, []byte(raw), 0o600)
		if _, err := Load(path); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
