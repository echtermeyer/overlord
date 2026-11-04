package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	overlord "github.com/echtermeyer/overlord"
)

type Config struct {
	DataDir string `yaml:"data_dir"`
	Socket  string `yaml:"socket"`
	Rules   struct {
		Dir         string        `yaml:"dir"`
		Policy      string        `yaml:"policy"`
		RepeatAfter time.Duration `yaml:"repeat_after"`
	} `yaml:"rules"`
	Graph struct {
		Retention     time.Duration `yaml:"retention"`
		MaxPerProcess int           `yaml:"max_per_process"`
		TrustedTeams  []string      `yaml:"trusted_teams"`
	} `yaml:"graph"`
	Sensors struct {
		ESLogger struct {
			Enabled      bool          `yaml:"enabled"`
			Binary       string        `yaml:"binary"`
			Events       []string      `yaml:"events"`
			RestartAfter time.Duration `yaml:"restart_after"`
		} `yaml:"eslogger"`
		Netmon struct {
			Enabled  bool          `yaml:"enabled"`
			Interval time.Duration `yaml:"interval"`
		} `yaml:"netmon"`
		Santa struct {
			Enabled       bool   `yaml:"enabled"`
			Listen        string `yaml:"listen"`
			MachineIDFile string `yaml:"machine_id_file"`
		} `yaml:"santa"`
	} `yaml:"sensors"`
	Ask struct {
		Timeout         time.Duration `yaml:"timeout"`
		FreezeTimeout   time.Duration `yaml:"freeze_timeout"`
		FrozenOnTimeout string        `yaml:"frozen_on_timeout"`
	} `yaml:"ask"`
	Hook struct {
		DaemonTimeout time.Duration `yaml:"daemon_timeout"`
	} `yaml:"hook"`
	Notify struct {
		WebhookURL       string `yaml:"webhook_url"`
		WebhookTokenFile string `yaml:"webhook_token_file"`
	} `yaml:"notify"`
	Logs struct {
		Dir       string        `yaml:"dir"`
		MaxSizeMB int           `yaml:"max_size_mb"`
		KeepFiles int           `yaml:"keep_files"`
		Redact    bool          `yaml:"redact"`
		Heartbeat time.Duration `yaml:"heartbeat"`
		Ship      struct {
			URL       string        `yaml:"url"`
			TokenFile string        `yaml:"token_file"`
			Batch     int           `yaml:"batch"`
			Interval  time.Duration `yaml:"interval"`
		} `yaml:"ship"`
	} `yaml:"logs"`
	LLM struct {
		Provider         string        `yaml:"provider"`
		Model            string        `yaml:"model"`
		OllamaURL        string        `yaml:"ollama_url"`
		AnthropicKeyFile string        `yaml:"anthropic_key_file"`
		Timeout          time.Duration `yaml:"timeout"`
	} `yaml:"llm"`
}

const DefaultPath = "/Library/Overlord/config.yaml"

// Load starts from the embedded defaults and overlays the file at path if it exists. Unknown
// keys are an error so a typo never silently keeps a default.
func Load(path string) (*Config, error) {
	raw, err := overlord.Files.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}
	var c Config
	if err := decodeStrict(raw, &c); err != nil {
		return nil, fmt.Errorf("embedded config: %w", err)
	}
	if path == "" {
		return &c, c.validate()
	}
	overlay, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &c, c.validate()
	}
	if err != nil {
		return nil, err
	}
	if err := decodeStrict(overlay, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, c.validate()
}

func decodeStrict(raw []byte, into *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	return dec.Decode(into)
}

func (c *Config) validate() error {
	switch c.Ask.FrozenOnTimeout {
	case "keep", "kill", "resume":
	default:
		return fmt.Errorf("ask.frozen_on_timeout: %q is not keep, kill or resume", c.Ask.FrozenOnTimeout)
	}
	switch c.LLM.Provider {
	case "none", "ollama", "anthropic":
	default:
		return fmt.Errorf("llm.provider: %q is not none, ollama or anthropic", c.LLM.Provider)
	}
	if c.Rules.RepeatAfter <= 0 || c.Ask.Timeout <= 0 || c.Hook.DaemonTimeout <= 0 {
		return fmt.Errorf("rules.repeat_after, ask.timeout and hook.daemon_timeout must be positive")
	}
	return nil
}
