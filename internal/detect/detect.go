// Package detect combines regex rules and entropy into one line-level detector
// that the file scanner and the git-history scanner both use.
package detect

import (
	"regexp"
	"sort"
	"strings"

	"keyguard/internal/entropy"
	"keyguard/internal/finding"
	"keyguard/internal/rules"
)

// IgnoreMarker on a line suppresses every finding on that line.
const IgnoreMarker = "keyguard:ignore"

type Detector struct {
	Rules   []*rules.Rule
	Entropy bool
}

func New(entropyOn bool) *Detector {
	return &Detector{Rules: rules.Default(), Entropy: entropyOn}
}

// Hit is a secret found on one line.
type Hit struct {
	RuleID      string
	Description string
	Severity    finding.Severity
	Fix         string
	Secret      string
	Start, End  int
	order       int // rule index, used to break ties
}

var base64Blob = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

const entropyRuleID = "high-entropy-string"

// minRuleEntropy is far below any real key (~4.5+) but above placeholders (~2).
const minRuleEntropy = 2.5

const maxEntropyPerLine = 20

// Line returns non-overlapping hits for one line of text.
func (d *Detector) Line(line string) []Hit {
	if strings.Contains(line, IgnoreMarker) {
		return nil
	}
	return d.find(line)
}

func (d *Detector) find(line string) []Hit {
	lower := strings.ToLower(line)
	var hits []Hit
	for i, r := range d.Rules {
		for _, m := range r.Find(line, lower) {
			// "sk_live_xxxxxxxxxxxxxxxx" matches the Stripe regex but is a
			// docs placeholder. Real keys are random; placeholders repeat.
			if entropy.Shannon(m.Secret) < minRuleEntropy {
				continue
			}
			hits = append(hits, Hit{
				RuleID: r.ID, Description: r.Description, Severity: r.Severity, Fix: r.Fix,
				Secret: m.Secret, Start: m.Start, End: m.End, order: i,
			})
		}
	}
	if d.Entropy {
		toks := entropy.Find(line)
		if len(toks) > maxEntropyPerLine { // bound the O(n²) dedupe on generated lines
			toks = toks[:maxEntropyPerLine]
		}
		for _, t := range toks {
			hits = append(hits, Hit{
				RuleID: entropyRuleID, Description: "High-entropy string (possible secret)",
				Severity: finding.Medium, Secret: t.Value, Start: t.Start, End: t.End,
				Fix:   "If this is a credential, move it to an environment variable. If it's not, add a `keyguard:ignore` comment on the line.",
				order: len(d.Rules),
			})
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
		if hits[i].Severity != hits[j].Severity {
			return hits[i].Severity > hits[j].Severity
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

// RedactLine masks every secret on a line so it can be shown as context.
// It ignores the ignore marker: an allowlisted secret is still never printed.
func (d *Detector) RedactLine(line string) string {
	// The body of a PEM private key is bare base64 lines that no rule matches
	// on their own (only the BEGIN header does). Never echo such a blob.
	if t := strings.TrimSpace(line); len(t) >= 40 && base64Blob.MatchString(t) {
		return "[redacted base64 block]"
	}
	hits := d.find(line)
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
