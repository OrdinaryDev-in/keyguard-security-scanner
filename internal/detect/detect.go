// Package detect combines regex rules and entropy into one line-level detector
// that the file scanner and the git-history scanner both use.
package detect

import (
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/entropy"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/rules"
)

// IgnoreMarker on a line suppresses every finding on that line.
const IgnoreMarker = "keyguard:ignore"

type Detector struct {
	Rules   []*rules.Rule
	Entropy bool
	entropy rules.Meta
}

// New builds a detector from the built-in rule catalogue.
func New(entropyOn bool) (*Detector, error) {
	cat, err := rules.Default()
	if err != nil {
		return nil, err
	}
	ent, ok := cat.Lookup(entropyRuleID)
	if !ok {
		return nil, errors.New("rules: built-in catalogue has no " + entropyRuleID + " rule")
	}
	// Clone: the catalogue is cached and shared; a caller replacing
	// d.Rules[i] must not change it for everyone else.
	return &Detector{Rules: slices.Clone(cat.Patterns), Entropy: entropyOn, entropy: ent}, nil
}

// Hit is a secret found on one line.
type Hit struct {
	Rule       rules.Meta
	Secret     string
	Start, End int
	order      int // rule index, used to break ties
}

// Finding turns a hit on line lineNo of file into a Finding. The secret is
// redacted; only its hash is kept, for de-duplication. Callers add Context.
func (h Hit) Finding(src finding.Source, file string, lineNo int) finding.Finding {
	f := h.Rule.Finding(src)
	f.File, f.Line, f.Column = file, lineNo, h.Start+1
	f.Secret = finding.Redact(h.Secret)
	f.SecretHash = finding.Hash(h.Rule.ID, h.Secret)
	return f
}

var base64Blob = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

const entropyRuleID = "high-entropy-string"

// minRuleEntropy is far below any real key (~4.5+) but above placeholders (~2).
const minRuleEntropy = 2.5

const maxEntropyPerLine = 20

// Line returns non-overlapping hits for one line of text from an unknown
// file. File-specific rules (Dockerfile, Angular environment, ...) are skipped;
// scanners should use LineIn.
func (d *Detector) Line(line string) []Hit { return d.LineIn("", line) }

// LineIn returns non-overlapping hits for one line of the file at rel
// (slash-separated, relative to the scan root).
func (d *Detector) LineIn(rel, line string) []Hit {
	if strings.Contains(line, IgnoreMarker) {
		return nil
	}
	return d.find(rel, line)
}

func (d *Detector) find(rel, line string) []Hit {
	lower := strings.ToLower(line)
	var hits []Hit
	for i, r := range d.Rules {
		if !r.AppliesTo(rel) {
			continue
		}
		for _, m := range r.Find(line, lower) {
			// "sk_live_xxxxxxxxxxxxxxxx" matches the Stripe regex but is a
			// docs placeholder. Real keys are random; placeholders repeat.
			if entropy.Shannon(m.Secret) < minRuleEntropy {
				continue
			}
			hits = append(hits, Hit{Rule: r.Meta, Secret: m.Secret, Start: m.Start, End: m.End, order: i})
		}
	}
	if d.Entropy {
		toks := entropy.Find(line)
		if len(toks) > maxEntropyPerLine { // bound the O(n²) dedupe on generated lines
			toks = toks[:maxEntropyPerLine]
		}
		for _, t := range toks {
			hits = append(hits, Hit{Rule: d.entropy, Secret: t.Value, Start: t.Start, End: t.End, order: len(d.Rules)})
		}
	}
	return dedupe(hits)
}

// dedupe drops hits that overlap a better one. "Better" = higher severity,
// then earlier rule. So `STRIPE_SECRET = "sk_live_..."` is reported once as
// a Stripe key, not also as a generic secret and a high-entropy string.
func dedupe(hits []Hit) []Hit {
	if len(hits) < 2 {
		return hits
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if a, b := hits[i].Rule.Severity, hits[j].Rule.Severity; a != b {
			return a > b
		}
		return hits[i].order < hits[j].order
	})
	var kept []Hit
	for _, h := range hits {
		overlaps := false
		for _, k := range kept {
			if h.Start < k.End && k.Start < h.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, h)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

// RedactLine masks every secret on a line from an unknown file; see RedactLineIn.
func (d *Detector) RedactLine(line string) string { return d.RedactLineIn("", line) }

// RedactLineIn masks every secret on a line of the file at rel so it can be
// shown as context. File-specific rules count too: an unquoted password in
// application.properties is masked even though no generic rule sees it.
// It ignores the ignore marker: an allowlisted secret is still never printed.
func (d *Detector) RedactLineIn(rel, line string) string {
	// The body of a PEM private key is bare base64 lines that no rule matches
	// on their own (only the BEGIN header does). Never echo such a blob.
	if t := strings.TrimSpace(line); len(t) >= 40 && base64Blob.MatchString(t) {
		return "[redacted base64 block]"
	}
	hits := d.find(rel, line)
	for i := len(hits) - 1; i >= 0; i-- { // right-to-left keeps offsets valid
		h := hits[i]
		line = line[:h.Start] + finding.Redact(h.Secret) + line[h.End:]
	}
	// Context lines are shown even when nothing on them matched, so be
	// stricter than detection: mask any long token mixing letters and digits.
	return longToken.ReplaceAllStringFunc(line, func(t string) string {
		if strings.ContainsAny(t, "0123456789") && strings.ToLower(t) != t {
			return finding.Redact(t)
		}
		return t
	})
}

var longToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`)
