package detect

import (
	"strings"
	"testing"
)

var stripeKey = "sk_" + "live_" + strings.Repeat("aB3xY7kQ", 3)

func TestDedupePrefersSpecificRule(t *testing.T) {
	// Matches stripe-live-key, generic-secret and high-entropy-string.
	hits := New(true).Line(`const STRIPE_SECRET = "` + stripeKey + `";`)
	if len(hits) != 1 || hits[0].RuleID != "stripe-live-key" {
		t.Fatalf("want one stripe-live-key hit, got %+v", hits)
	}
}

func TestIgnoreMarker(t *testing.T) {
	if hits := New(true).Line(`key = "` + stripeKey + `" // keyguard:ignore`); len(hits) != 0 {
		t.Errorf("ignored line still produced %d hits", len(hits))
	}
}

func TestPlaceholderSkipped(t *testing.T) {
	if hits := New(true).Line("// e.g. sk_" + "live_" + strings.Repeat("x", 24)); len(hits) != 0 {
		t.Errorf("placeholder flagged: %+v", hits)
	}
}

func TestRedactLine(t *testing.T) {
	d := New(true)
	for _, line := range []string{
		`a = "` + stripeKey + `", b = "` + stripeKey + `"`,
		`x = "` + stripeKey + `" // keyguard:ignore`, // allowlisted secrets are still masked in context
	} {
		got := d.RedactLine(line)
		if strings.Contains(got, stripeKey) {
			t.Errorf("RedactLine leaked the secret: %s", got)
		}
		if !strings.Contains(got, "sk_l****") {
			t.Errorf("RedactLine(%q) = %q, want masked value", line, got)
		}
	}
}

func BenchmarkLineNoMatch(b *testing.B) {
	d := New(true)
	line := `export function formatDate(d: Date): string { return d.toISOString().slice(0, 10); }`
	for i := 0; i < b.N; i++ {
		d.Line(line)
	}
}

func TestRedactLineBase64Block(t *testing.T) {
	body := strings.Repeat("MIIEpAIBAAKCAQEA7x+/", 3)
	if got := New(true).RedactLine(body); strings.Contains(got, "MIIE") {
		t.Errorf("PEM body not redacted: %s", got)
	}
}

// Same line with the keyword pre-filter disabled, to measure what it saves.
func BenchmarkLineNoMatchWithoutKeywords(b *testing.B) {
	d := New(true)
	for _, r := range d.Rules {
		r.Keywords = nil
	}
	line := `export function formatDate(d: Date): string { return d.toISOString().slice(0, 10); }`
	for i := 0; i < b.N; i++ {
		d.Line(line)
	}
}
