package detect

import (
	"math/rand"
	"strings"
	"testing"
)

func newDetector(tb testing.TB) *Detector {
	tb.Helper()
	d, err := New(true)
	if err != nil {
		tb.Fatal(err)
	}
	return d
}

var stripeKey = "sk_" + "live_" + strings.Repeat("aB3xY7kQ", 3)

func TestDedupePrefersSpecificRule(t *testing.T) {
	// Matches stripe-live-key, generic-secret and high-entropy-string.
	hits := newDetector(t).Line(`const STRIPE_SECRET = "` + stripeKey + `";`)
	if len(hits) != 1 || hits[0].Rule.ID != "stripe-live-key" {
		t.Fatalf("want one stripe-live-key hit, got %+v", hits)
	}
}

func TestIgnoreMarker(t *testing.T) {
	if hits := newDetector(t).Line(`key = "` + stripeKey + `" // keyguard:ignore`); len(hits) != 0 {
		t.Errorf("ignored line still produced %d hits", len(hits))
	}
}

func TestPlaceholderSkipped(t *testing.T) {
	if hits := newDetector(t).Line("// e.g. sk_" + "live_" + strings.Repeat("x", 24)); len(hits) != 0 {
		t.Errorf("placeholder flagged: %+v", hits)
	}
}

func TestRedactLine(t *testing.T) {
	d := newDetector(t)
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
	d := newDetector(b)
	line := `export function formatDate(d: Date): string { return d.toISOString().slice(0, 10); }`
	for i := 0; i < b.N; i++ {
		d.Line(line)
	}
}

func TestRedactLineBase64Block(t *testing.T) {
	body := strings.Repeat("MIIEpAIBAAKCAQEA7x+/", 3)
	if got := newDetector(t).RedactLine(body); strings.Contains(got, "MIIE") {
		t.Errorf("PEM body not redacted: %s", got)
	}
}

// Same line with the keyword pre-filter disabled, to measure what it saves.
func BenchmarkLineNoMatchWithoutKeywords(b *testing.B) {
	d := newDetector(b)
	// Copy each rule: the catalogue is cached and shared, so editing the
	// originals would leak into every later test in this process.
	for i, r := range d.Rules {
		c := *r
		c.Keywords = nil
		d.Rules[i] = &c
	}
	line := `export function formatDate(d: Date): string { return d.toISOString().slice(0, 10); }`
	for i := 0; i < b.N; i++ {
		d.Line(line)
	}
}

// Entropy is file-aware: backticks are strings in TypeScript, code spans in
// Markdown. Identifiers are skipped everywhere.
func TestEntropyBackticksByFile(t *testing.T) {
	d := newDetector(t)
	r := rand.New(rand.NewSource(1)) // built at runtime: this file holds no key
	b := make([]byte, 32)
	for i := range b {
		b[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[r.Intn(62)]
	}
	key := string(b)
	tests := []struct {
		file, line string
		want       int
	}{
		{"src/api.ts", "const url = `https://api.example.com?k=" + "${id}`; const k = `" + key + "`;", 1},
		{"docs/devlog/04-entropy.md", "a code span like `handleOAuth2CallbackV2` (22 chars)", 0},
		{"docs/notes.md", "set `" + key + "` here", 0},
		{"src/routes.ts", `router.get("/cb", "handleOAuth2CallbackV2")`, 0},
		{"", "`" + key + "`", 1}, // unknown file: backticks still count
	}
	for _, tt := range tests {
		if got := len(d.LineIn(tt.file, tt.line)); got != tt.want {
			t.Errorf("LineIn(%q, %q) = %d hits, want %d", tt.file, tt.line, got, tt.want)
		}
	}
}
