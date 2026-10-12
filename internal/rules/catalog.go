package rules

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"keyguard/internal/finding"
)

//go:embed rules.json
var builtin []byte

// Catalogue is a loaded, validated rule file.
type Catalogue struct {
	// Patterns are the regex rules in file order. Order matters: when two
	// rules match the same text with equal severity, the earlier (more
	// specific) rule wins.
	Patterns []*Rule
	all      []Meta
	byID     map[string]Meta
}

// All returns every rule's metadata, in file order.
func (c *Catalogue) All() []Meta { return c.all }

// Lookup returns the rule with this ID.
func (c *Catalogue) Lookup(id string) (Meta, bool) {
	m, ok := c.byID[id]
	return m, ok
}

// Default returns the built-in catalogue. It is parsed and compiled once, on
// first use; sync.OnceValues caches both the result and the error.
var Default = sync.OnceValues(func() (*Catalogue, error) { return Load(builtin) })

// MustLookup returns a built-in rule's metadata. For IDs hard-coded in Go:
// an unknown ID is a programming error, caught by TestReferencedIDsExist.
func MustLookup(id string) Meta {
	c, err := Default()
	if err != nil {
		panic(err)
	}
	m, ok := c.Lookup(id)
	if !ok {
		panic("rules: unknown rule ID " + id)
	}
	return m
}

// ruleJSON is the on-disk shape of one rule.
type ruleJSON struct {
	ID          string           `json:"id"`
	Kind        Kind             `json:"kind"`
	Description string           `json:"description"`
	Severity    finding.Severity `json:"severity"`
	Keywords    []string         `json:"keywords"`
	Regex       string           `json:"regex"`
	SecretGroup int              `json:"secret_group"`
	Validators  []string         `json:"validators"`
	Fix         string           `json:"fix"`
}

// Load parses and validates a rule file. It reports every problem it finds,
// not just the first, so a broken edit is fixed in one go.
func Load(data []byte) (*Catalogue, error) {
	var file struct {
		Rules []ruleJSON `json:"rules"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // a typo like "secret_grop" must not be silently ignored
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}

	c := &Catalogue{byID: map[string]Meta{}}
	compiled := map[string]*regexp.Regexp{} // two JWT rules share one regex
	var errs []error
	for i, rj := range file.Rules {
		name := rj.ID
		if name == "" {
			name = fmt.Sprintf("#%d", i)
		}
		bad := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("rule %s: "+format, append([]any{name}, args...)...))
		}

		if rj.ID == "" {
			bad("missing id")
		} else if _, dup := c.byID[rj.ID]; dup {
			bad("duplicate id")
		}
		if rj.Description == "" {
			bad("missing description")
		}
		if rj.Fix == "" {
			bad("missing fix")
		}
		if rj.Severity == finding.None {
			bad("severity must be low, medium or high")
		}
		meta := Meta{ID: rj.ID, Kind: rj.Kind, Description: rj.Description, Severity: rj.Severity, Fix: rj.Fix}

		switch rj.Kind {
		case KindPattern:
			if r, err := compile(meta, rj, compiled); err != nil {
				bad("%v", err)
			} else {
				c.Patterns = append(c.Patterns, r)
			}
		case KindEntropy, KindConfig, KindHistory, KindLimit:
			if rj.Regex != "" || len(rj.Keywords) > 0 || len(rj.Validators) > 0 || rj.SecretGroup != 0 {
				bad("only pattern rules take regex, keywords, validators or secret_group")
			}
		default:
			bad("unknown kind %q", rj.Kind)
		}

		c.all = append(c.all, meta)
		if rj.ID != "" {
			c.byID[rj.ID] = meta
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

func compile(meta Meta, rj ruleJSON, cache map[string]*regexp.Regexp) (*Rule, error) {
	if rj.Regex == "" {
		return nil, errors.New("pattern rule has no regex")
	}
	re, ok := cache[rj.Regex]
	if !ok {
		var err error
		if re, err = regexp.Compile(rj.Regex); err != nil {
			return nil, err
		}
		cache[rj.Regex] = re
	}
	if rj.SecretGroup < 0 || rj.SecretGroup > re.NumSubexp() {
		return nil, fmt.Errorf("secret_group %d, but the regex has %d groups", rj.SecretGroup, re.NumSubexp())
	}
	for _, k := range rj.Keywords {
		// Lines are lowercased before the keyword check, so an uppercase
		// keyword would never match and would silently disable the rule.
		if k != strings.ToLower(k) {
			return nil, fmt.Errorf("keyword %q must be lowercase", k)
		}
	}
	validate, err := buildValidators(rj.Validators)
	if err != nil {
		return nil, err
	}
	return &Rule{Meta: meta, Keywords: rj.Keywords, Regex: re, SecretGroup: rj.SecretGroup, Validate: validate}, nil
}
