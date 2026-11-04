package rules

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/echtermeyer/overlord/internal/events"
)

type Stage string

const (
	Shadow  Stage = "shadow"
	Ask     Stage = "ask"
	Enforce Stage = "enforce"
)

type Confidence string

const (
	Certain  Confidence = "certain"
	Likely   Confidence = "likely"
	Possible Confidence = "possible"
)

type Action string

const (
	Deny                 Action = "deny"
	AskAction            Action = "ask"
	Freeze               Action = "freeze"
	Kill                 Action = "kill"
	Quarantine           Action = "quarantine"
	QuarantineIfBlocked  Action = "quarantine_if_blocked"
	BlockNewDestinations Action = "block_new_destinations"
	DisableLaunchItem    Action = "disable_launch_item"
	SantaBlock           Action = "santa_block"
	Alert                Action = "alert"
)

var knownActions = map[Action]bool{
	Deny: true, AskAction: true, Freeze: true, Kill: true, Quarantine: true, QuarantineIfBlocked: true,
	BlockNewDestinations: true, DisableLaunchItem: true, SantaBlock: true, Alert: true,
}

// askAllowed lists what a rule in stage "ask" may do: nothing irreversible.
var askAllowed = map[Action]bool{
	Deny: true, AskAction: true, Freeze: true, Alert: true, BlockNewDestinations: true, QuarantineIfBlocked: true,
}

type Rule struct {
	ID              string     `yaml:"id"`
	Threat          string     `yaml:"threat"`
	On              KindList   `yaml:"on"`
	When            string     `yaml:"when"`
	Confidence      Confidence `yaml:"confidence"`
	Actions         []Action   `yaml:"actions"`
	EscalateWhen    string     `yaml:"escalate_when"`
	EscalateActions []Action   `yaml:"escalate_actions"`
	Explain         string     `yaml:"explain"`
}

// KindList accepts a single kind or a list in YAML.
type KindList []events.Kind

func (k *KindList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*k = KindList{events.Kind(value.Value)}
		return nil
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return err
	}
	for _, item := range list {
		*k = append(*k, events.Kind(item))
	}
	return nil
}

func (r Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule without id")
	}
	if len(r.On) == 0 {
		return fmt.Errorf("rule %s: no event kinds", r.ID)
	}
	switch r.Confidence {
	case Certain, Likely, Possible:
	default:
		return fmt.Errorf("rule %s: confidence %q", r.ID, r.Confidence)
	}
	for _, a := range append(append([]Action{}, r.Actions...), r.EscalateActions...) {
		if !knownActions[a] {
			return fmt.Errorf("rule %s: unknown action %q", r.ID, a)
		}
	}
	if len(r.EscalateActions) > 0 && r.EscalateWhen == "" {
		return fmt.Errorf("rule %s: escalate_actions without escalate_when", r.ID)
	}
	return nil
}

func ParseRules(raw []byte) ([]Rule, error) {
	var list []Rule
	if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	for _, r := range list {
		if err := r.validate(); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func LoadRules(paths ...string) ([]Rule, error) {
	var all []Rule
	seen := map[string]bool{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		list, err := ParseRules(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, r := range list {
			if seen[r.ID] {
				return nil, fmt.Errorf("%s: duplicate rule id %s", path, r.ID)
			}
			seen[r.ID] = true
		}
		all = append(all, list...)
	}
	return all, nil
}

// Policy sets each rule's stage. Rules it does not name run in DefaultStage.
type Policy struct {
	DefaultStage Stage            `yaml:"default_stage"`
	Stages       map[string]Stage `yaml:"stages"`
	// Allowlists are named sets of process identities (team id, signing id, cdhash or path glob)
	// that rules consult with process.inAllowlist(name).
	Allowlists map[string][]string `yaml:"allowlists"`
}

func ParsePolicy(raw []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	if p.DefaultStage == "" {
		p.DefaultStage = Shadow
	}
	for id, stage := range p.Stages {
		switch stage {
		case Shadow, Ask, Enforce:
		default:
			return p, fmt.Errorf("policy: rule %s has stage %q", id, stage)
		}
	}
	return p, nil
}

func LoadPolicy(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(raw)
}

func (p Policy) Stage(id string) Stage {
	if s, ok := p.Stages[id]; ok {
		return s
	}
	return p.DefaultStage
}

// Verdict is one rule's outcome for one event. Actions is what the engine permits after the
// stage cap; Requested is what the rule asked for, kept for the log.
type Verdict struct {
	RuleID     string     `json:"rule"`
	Threat     string     `json:"threat"`
	Stage      Stage      `json:"stage"`
	Confidence Confidence `json:"confidence"`
	Escalated  bool       `json:"escalated,omitempty"`
	Requested  []Action   `json:"requested"`
	Actions    []Action   `json:"actions"`
	Explain    string     `json:"explain,omitempty"`
	At         time.Time  `json:"at"`
}

func (v Verdict) Has(a Action) bool {
	for _, x := range v.Actions {
		if x == a {
			return true
		}
	}
	return false
}

func permitted(stage Stage, confidence Confidence, escalated bool, requested []Action) []Action {
	var out []Action
	for _, a := range requested {
		switch stage {
		case Shadow:
			continue
		case Ask:
			if !askAllowed[a] {
				continue
			}
		case Enforce:
			if a == Kill && confidence != Certain && !escalated {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func sortedActions(actions []Action) []Action {
	out := append([]Action{}, actions...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
