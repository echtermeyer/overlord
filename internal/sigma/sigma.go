// Package sigma converts Sigma process_creation and file_event rules for macOS into Overlord
// rules. Only the subset the sensors can answer is supported; everything else is reported.
package sigma

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/echtermeyer/overlord/internal/events"
	"github.com/echtermeyer/overlord/internal/rules"
)

type Rule struct {
	Title       string         `yaml:"title"`
	ID          string         `yaml:"id"`
	Description string         `yaml:"description"`
	Level       string         `yaml:"level"`
	Tags        []string       `yaml:"tags"`
	Logsource   Logsource      `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
}

type Logsource struct {
	Product  string `yaml:"product"`
	Category string `yaml:"category"`
}

// fields maps Sigma field names to CEL expressions per category.
var fields = map[string]map[string]string{
	"process_creation": {
		"Image":             "target.path",
		"CommandLine":       "target.cmdline",
		"ParentImage":       "process.path",
		"ParentCommandLine": "process.cmdline",
		"User":              "string(target.uid)",
		"CurrentDirectory":  "target.cwd",
	},
	"file_event": {
		"TargetFilename": "event.path",
		"Image":          "process.path",
	},
}

var kinds = map[string]rules.KindList{
	"process_creation": {events.Exec},
	"file_event":       {events.FileCreate, events.FileRename, events.FileWrite},
}

var levels = map[string]rules.Confidence{"critical": rules.Likely, "high": rules.Likely, "medium": rules.Possible, "low": rules.Possible, "informational": rules.Possible}

// Convert translates one Sigma YAML document. Unsupported constructs return an error naming them.
func Convert(raw []byte) (rules.Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return rules.Rule{}, err
	}
	if r.Logsource.Product != "macos" {
		return rules.Rule{}, fmt.Errorf("%s: product %q is not macos", r.Title, r.Logsource.Product)
	}
	fieldMap, ok := fields[r.Logsource.Category]
	if !ok {
		return rules.Rule{}, fmt.Errorf("%s: category %q not supported", r.Title, r.Logsource.Category)
	}
	condition, _ := r.Detection["condition"].(string)
	if condition == "" {
		return rules.Rule{}, fmt.Errorf("%s: no condition", r.Title)
	}
	selections := map[string]string{}
	var names []string
	for name, body := range r.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		expr, err := selection(body, fieldMap)
		if err != nil {
			return rules.Rule{}, fmt.Errorf("%s: %s: %w", r.Title, name, err)
		}
		selections[name] = expr
		names = append(names, name)
	}
	sort.Strings(names)
	when, err := parseCondition(condition, selections, names)
	if err != nil {
		return rules.Rule{}, fmt.Errorf("%s: condition %q: %w", r.Title, condition, err)
	}
	confidence, ok := levels[r.Level]
	if !ok {
		confidence = rules.Possible
	}
	threat := "T1"
	for _, tag := range r.Tags {
		if strings.HasPrefix(tag, "attack.t1059") || strings.HasPrefix(tag, "attack.t1547") || strings.HasPrefix(tag, "attack.t1543") {
			threat = "T1"
		}
	}
	return rules.Rule{
		ID:         "sigma." + slug(r.Title),
		Threat:     threat,
		On:         kinds[r.Logsource.Category],
		When:       when,
		Confidence: confidence,
		Actions:    []rules.Action{rules.Alert},
		Explain:    strings.TrimSpace(r.Title + ". " + r.Description),
	}, nil
}

func slug(s string) string {
	s = strings.ToLower(s)
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// selection renders one Sigma selection (a map of field|modifiers: value(s), or a list of maps)
// as a CEL boolean.
func selection(body any, fieldMap map[string]string) (string, error) {
	switch v := body.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			expr, err := fieldExpr(k, v[k], fieldMap)
			if err != nil {
				return "", err
			}
			parts = append(parts, expr)
		}
		return "(" + strings.Join(parts, " && ") + ")", nil
	case []any:
		var parts []string
		for _, item := range v {
			if _, isMap := item.(map[string]any); !isMap {
				return "", fmt.Errorf("list selections of bare values are not supported")
			}
			expr, err := selection(item, fieldMap)
			if err != nil {
				return "", err
			}
			parts = append(parts, expr)
		}
		return "(" + strings.Join(parts, " || ") + ")", nil
	}
	return "", fmt.Errorf("unsupported selection shape %T", body)
}

func fieldExpr(key string, value any, fieldMap map[string]string) (string, error) {
	parts := strings.Split(key, "|")
	field, ok := fieldMap[parts[0]]
	if !ok {
		return "", fmt.Errorf("field %q not supported", parts[0])
	}
	all := false
	op := "equals"
	for _, mod := range parts[1:] {
		switch mod {
		case "all":
			all = true
		case "contains", "startswith", "endswith", "re":
			op = mod
		case "windash", "cased":
			// windash is Windows-only; cased changes nothing, matching is case-sensitive here.
		default:
			return "", fmt.Errorf("modifier %q not supported", mod)
		}
	}
	var values []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			values = append(values, fmt.Sprint(item))
		}
	case nil:
		return "", fmt.Errorf("field %q has no value", parts[0])
	default:
		values = []string{fmt.Sprint(v)}
	}
	exprs := make([]string, 0, len(values))
	for _, val := range values {
		exprs = append(exprs, one(field, op, val))
	}
	join := " || "
	if all {
		join = " && "
	}
	return "(" + strings.Join(exprs, join) + ")", nil
}

func one(field, op, val string) string {
	if strings.ContainsAny(val, "*?") && op != "re" {
		re := "^" + wildcard(val) + "$"
		switch op {
		case "contains":
			re = wildcard(val)
		case "startswith":
			re = "^" + wildcard(val)
		case "endswith":
			re = wildcard(val) + "$"
		}
		return field + ".matches(" + quote(re) + ")"
	}
	switch op {
	case "contains":
		return field + ".contains(" + quote(val) + ")"
	case "startswith":
		return field + ".startsWith(" + quote(val) + ")"
	case "endswith":
		return field + ".endsWith(" + quote(val) + ")"
	case "re":
		return field + ".matches(" + quote(val) + ")"
	}
	return field + " == " + quote(val)
}

func wildcard(val string) string {
	var sb strings.Builder
	for _, r := range val {
		switch r {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return sb.String()
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// parseCondition handles the common Sigma grammar: identifiers, and/or/not, parentheses, and
// "1 of x*" / "all of x*" / "1 of them" / "all of them".
func parseCondition(cond string, selections map[string]string, names []string) (string, error) {
	tokens := tokenize(cond)
	p := &parser{tokens: tokens, selections: selections, names: names}
	expr, err := p.or()
	if err != nil {
		return "", err
	}
	if p.pos != len(p.tokens) {
		return "", fmt.Errorf("unexpected %q", p.tokens[p.pos])
	}
	return expr, nil
}

func tokenize(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

type parser struct {
	tokens     []string
	pos        int
	selections map[string]string
	names      []string
}

func (p *parser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) or() (string, error) {
	left, err := p.and()
	if err != nil {
		return "", err
	}
	for p.peek() == "or" {
		p.next()
		right, err := p.and()
		if err != nil {
			return "", err
		}
		left = "(" + left + " || " + right + ")"
	}
	return left, nil
}

func (p *parser) and() (string, error) {
	left, err := p.not()
	if err != nil {
		return "", err
	}
	for p.peek() == "and" {
		p.next()
		right, err := p.not()
		if err != nil {
			return "", err
		}
		left = "(" + left + " && " + right + ")"
	}
	return left, nil
}

func (p *parser) not() (string, error) {
	if p.peek() == "not" {
		p.next()
		inner, err := p.not()
		if err != nil {
			return "", err
		}
		return "!" + inner, nil
	}
	return p.atom()
}

func (p *parser) atom() (string, error) {
	t := p.next()
	switch t {
	case "":
		return "", fmt.Errorf("unexpected end")
	case "(":
		inner, err := p.or()
		if err != nil {
			return "", err
		}
		if p.next() != ")" {
			return "", fmt.Errorf("missing )")
		}
		return "(" + inner + ")", nil
	case "1", "all":
		if p.next() != "of" {
			return "", fmt.Errorf("expected 'of' after %s", t)
		}
		pattern := p.next()
		matched := p.match(pattern)
		if len(matched) == 0 {
			return "", fmt.Errorf("no selection matches %q", pattern)
		}
		join := " || "
		if t == "all" {
			join = " && "
		}
		return "(" + strings.Join(matched, join) + ")", nil
	}
	expr, ok := p.selections[t]
	if !ok {
		return "", fmt.Errorf("unknown selection %q", t)
	}
	return expr, nil
}

func (p *parser) match(pattern string) []string {
	var out []string
	for _, name := range p.names {
		if pattern == "them" || (strings.HasSuffix(pattern, "*") && strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))) || name == pattern {
			out = append(out, p.selections[name])
		}
	}
	return out
}
