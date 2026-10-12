// Package rules is keyguard's rule catalogue: every finding keyguard can
// report, with its description, severity and fix advice, defined once in the
// embedded rules.json.
//
// Most entries are "pattern" rules: a regex plus optional named validators.
// Go's regexp package uses RE2: matching is guaranteed linear-time (no
// catastrophic backtracking on a hostile file), but there are no lookaheads or
// backreferences. Anything RE2 can't express goes in a validator.
//
// The other kinds (entropy, config, history, limit) are detected by Go code in
// other packages, which look their metadata up here by ID.
package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
)

// Kind says which part of keyguard produces a rule's findings.
type Kind string

const (
	KindPattern Kind = "pattern" // regex in rules.json, run by detect
	KindEntropy Kind = "entropy" // detect's high-entropy string check
	KindConfig  Kind = "config"  // checks / the scanner's .env exposure check
	KindHistory Kind = "history" // gitscan
	KindLimit   Kind = "limit"   // the scanner gave up on a file
)

// Meta is what every rule has, whatever produces it.
type Meta struct {
	ID          string
	Kind        Kind
	Description string
	Severity    finding.Severity
	Fix         string
}

// Finding starts a Finding pre-filled with this rule's metadata.
func (m Meta) Finding(src finding.Source) finding.Finding {
	return finding.Finding{RuleID: m.ID, Description: m.Description, Severity: m.Severity, Fix: m.Fix, Source: src}
}

// Rule is a compiled pattern rule.
type Rule struct {
	Meta
	// Keywords are cheap lowercase substrings checked before running the
	// regex. Most lines contain none of them, so most regexes never run.
	Keywords []string
	Regex    *regexp.Regexp
	// SecretGroup is the capture group holding the secret (0 = whole match).
	SecretGroup int
	// Validate rejects regex matches that aren't real secrets. Optional.
	Validate func(secret string) bool
	// Files limits the rule to matching paths (globs). Empty = every file.
	// This is how stack-specific rules work: a Dockerfile rule only runs on
	// Dockerfiles, an Angular rule only on environments/environment*.ts.
	Files []string
}

// AppliesTo reports whether the rule runs on the file at rel (slash-separated).
// A glob without "/" matches the file name; one with "/" matches the end of
// the path at a directory boundary, so "environments/environment*.ts"
// matches "src/environments/environment.prod.ts". rel == "" (unknown file)
// matches only unrestricted rules.
func (r *Rule) AppliesTo(rel string) bool {
	if len(r.Files) == 0 {
		return true
	}
	if rel == "" {
		return false
	}
	for _, g := range r.Files {
		if MatchFile(g, rel) {
			return true
		}
	}
	return false
}

// MatchFile matches one Files glob against a path; see AppliesTo.
func MatchFile(glob, rel string) bool {
	if !strings.Contains(glob, "/") {
		ok, _ := path.Match(glob, path.Base(rel))
		return ok
	}
	parts := strings.Split(rel, "/")
	for i := range parts {
		if ok, _ := path.Match(glob, strings.Join(parts[i:], "/")); ok {
			return true
		}
	}
	return false
}

// Match is one rule firing on one line.
type Match struct {
	Rule       *Rule
	Secret     string
	Start, End int // byte offsets of Secret in the line
}

// Find runs the rule against a line. lower must be strings.ToLower(line);
// it is passed in so the caller lowercases each line once, not once per rule.
func (r *Rule) Find(line, lower string) []Match {
	if len(r.Keywords) > 0 && !containsAny(lower, r.Keywords) {
		return nil
	}
	var out []Match
	for _, idx := range r.Regex.FindAllStringSubmatchIndex(line, -1) {
		g := r.SecretGroup
		start, end := idx[2*g], idx[2*g+1]
		if start < 0 {
			continue
		}
		secret := line[start:end]
		if r.Validate != nil && !r.Validate(secret) {
			continue
		}
		out = append(out, Match{Rule: r, Secret: secret, Start: start, End: end})
	}
	return out
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
