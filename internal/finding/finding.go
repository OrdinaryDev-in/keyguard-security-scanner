// Package finding holds the types every other package shares: a Finding,
// its Severity, and helpers for redacting secrets before they are shown.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Severity is ordered so findings can be compared with < and >=.
type Severity int

const (
	None Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "none"
}

// MarshalText makes Severity serialise as "high" instead of 3 in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity turns a CLI flag value into a Severity.
func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "low":
		return Low, nil
	case "medium", "med":
		return Medium, nil
	case "high":
		return High, nil
	case "none", "off", "never":
		return None, nil
	}
	return None, fmt.Errorf("unknown severity %q (want high, medium, low or none)", v)
}

// Source says which part of the scanner produced a finding.
type Source string

const (
	SourceCode    Source = "code"    // a secret in a file on disk
	SourceConfig  Source = "config"  // a risky configuration, not a secret value
	SourceHistory Source = "history" // a secret found in git history
)

// ContextLine is one line of source shown around a finding (already redacted).
type ContextLine struct {
	Number int    `json:"number"`
	Text   string `json:"text"`
	Hit    bool   `json:"hit,omitempty"`
}

// Commit identifies where in git history a secret was introduced.
type Commit struct {
	SHA    string `json:"sha"`
	Author string `json:"author"`
	Date   string `json:"date"`
	// InWorkingTree is true when the same secret is still in the current files.
	InWorkingTree bool `json:"in_working_tree"`
}

type Finding struct {
	RuleID      string        `json:"rule_id"`
	Description string        `json:"description"`
	Severity    Severity      `json:"severity"`
	Source      Source        `json:"source"`
	File        string        `json:"file"`
	Line        int           `json:"line,omitempty"`
	Column      int           `json:"column,omitempty"`
	Secret      string        `json:"secret,omitempty"` // always redacted
	Fix         string        `json:"fix,omitempty"`
	Context     []ContextLine `json:"context,omitempty"`
	Commit      *Commit       `json:"commit,omitempty"`

	// SecretHash identifies the raw secret without storing it. It is used
	// in memory to de-duplicate findings and is never written to any report
	// (an unsalted hash of a weak password could be brute-forced).
	SecretHash string `json:"-"`
}

// Redact keeps just enough of a secret to recognise it ("sk_l****").
// Short values are fully masked because 4 chars of an 8-char password is half of it.
func Redact(secret string) string {
	if len(secret) < 12 {
		return "****"
	}
	return secret[:4] + "****"
}

// Hash returns a short, non-reversible identifier for a secret.
func Hash(ruleID, secret string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + secret))
	return hex.EncodeToString(sum[:8])
}
