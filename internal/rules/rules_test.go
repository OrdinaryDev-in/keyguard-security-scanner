package rules

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Secrets are built with strings.Repeat / concatenation so this file never
// contains a literal key that a scanner (including keyguard) would flag.
func r(s string, n int) string { return strings.Repeat(s, n) }

func jwt(role string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(`{"role":"`+role+`"}`)) + "." + r("aB3", 12)
}

func TestRules(t *testing.T) {
	tests := []struct {
		rule string
		line string
		want bool
	}{
		{"aws-access-key-id", `id = "AK` + `IA` + r("Q7", 8) + `"`, true},
		{"aws-access-key-id", `id = "AKIA` + r("q7", 8) + `"`, false}, // lowercase isn't a valid key
		{"aws-secret-access-key", `AWS_SECRET_ACCESS_KEY="` + r("aB3/x", 8) + `"`, true},
		{"github-token", `token: "gh` + `p_` + r("aB3x", 9) + `"`, true},
		{"github-token", `token: "ghp_short"`, false},
		{"stripe-live-key", `new Stripe("sk_` + `live_` + r("aB3", 8) + `")`, true},
		{"stripe-live-key", `new Stripe("sk_test_` + r("aB3", 8) + `")`, false},
		{"stripe-test-key", `new Stripe("sk_test_` + r("aB3", 8) + `")`, true},
		{"openai-api-key", `OPENAI_API_KEY=sk-proj-` + r("aB3x", 6) + "T3Blbk" + "FJ" + r("aB3x", 6), true},
		{"anthropic-api-key", `key = "sk-ant-api03-` + r("aB3x_", 20) + `"`, true},
		{"slack-token", `"xo` + `xb-` + r("12345", 3) + `"`, true},
		{"supabase-secret-key", `"sb_` + `secret_` + r("aB3", 8) + `"`, true},
		{"supabase-service-role-jwt", `"` + jwt("service_role") + `"`, true},
		{"supabase-service-role-jwt", `"` + jwt("anon") + `"`, false},
		{"jwt", `"` + jwt("anon") + `"`, false}, // anon keys are public by design
		{"jwt", `"` + jwt("authenticated") + `"`, true},
		{"private-key", "-----BEGIN OPENSSH " + "PRIVATE KEY-----", true},
		{"private-key", "-----BEGIN PUBLIC KEY-----", false},
		{"google-api-key", `apiKey: "AI` + `za` + r("aB3_x", 7) + `"`, true},
		{"database-url-password", `postgres://admin:Xk9vQ2mLp7@db:5432/app`, true},
		{"database-url-password", `postgres://user:password@localhost/db`, false},
		{"database-url-password", `postgres://user:${DB_PASS}@localhost/db`, false},
		{"generic-secret", `const apiSecret = "Xk9vQ2mLp7Rt"`, true},
		{"generic-secret", `password: "your-password-here"`, false},
		{"generic-secret", `const apiKey = process.env.API_KEY`, false},
		{"generic-secret", `token: "aaaaaaaaaa"`, false}, // too low entropy
	}
	cat, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*Rule{}
	for _, rule := range cat.Patterns {
		byID[rule.ID] = rule
	}
	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			rule, ok := byID[tt.rule]
			if !ok {
				t.Fatalf("no rule %q", tt.rule)
			}
			got := len(rule.Find(tt.line, strings.ToLower(tt.line))) > 0
			if got != tt.want {
				t.Errorf("%s on %q: matched=%v, want %v", tt.rule, tt.line, got, tt.want)
			}
		})
	}
}

// IDs that Go code looks up with MustLookup. Keep in sync when adding one.
var referencedIDs = []string{
	"high-entropy-string", "secret-in-public-env-var", "supabase-admin-key-in-client",
	"debug-in-production-config", "env-file-committed", "env-file-not-ignored",
	"env-file-in-history", "too-many-findings",
}

func TestReferencedIDsExist(t *testing.T) {
	for _, id := range referencedIDs {
		MustLookup(id) // panics (fails the test) if missing
	}
}

func TestBuiltinLoads(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Patterns) != 17 {
		t.Errorf("want 17 pattern rules (README says so), got %d", len(cat.Patterns))
	}
	if len(cat.All()) != len(cat.Patterns)+len(referencedIDs) {
		t.Errorf("catalogue has %d rules; is a non-pattern rule unused?", len(cat.All()))
	}
}

func TestLoadRejects(t *testing.T) {
	rule := func(fields string) string {
		return `{"rules": [{"id": "x", "kind": "pattern", "description": "d", "severity": "high", "fix": "f", ` + fields + `}]}`
	}
	tests := []struct {
		name, data, want string
	}{
		{"duplicate id", `{"rules": [` +
			`{"id": "a", "kind": "limit", "description": "d", "severity": "low", "fix": "f"},` +
			`{"id": "a", "kind": "limit", "description": "d", "severity": "low", "fix": "f"}]}`, "duplicate id"},
		{"empty fix", `{"rules": [{"id": "a", "kind": "limit", "description": "d", "severity": "low", "fix": ""}]}`, "missing fix"},
		{"uppercase keyword", rule(`"regex": "(a)", "secret_group": 1, "keywords": ["AKIA"]`), "lowercase"},
		{"group out of range", rule(`"regex": "(a)", "secret_group": 2`), "secret_group 2"},
		{"bad regex", rule(`"regex": "(a"`), "missing closing )"},
		{"unknown validator", rule(`"regex": "a", "validators": ["is-real"]`), `unknown validator "is-real"`},
		{"bad validator arg", rule(`"regex": "a", "validators": ["min-entropy:high"]`), "min-entropy"},
		{"unknown field", rule(`"regex": "a", "secret_grop": 1`), "unknown field"},
		{"bad severity", `{"rules": [{"id": "a", "kind": "limit", "description": "d", "severity": "urgent", "fix": "f"}]}`, "unknown severity"},
		{"regex on config rule", `{"rules": [{"id": "a", "kind": "config", "description": "d", "severity": "low", "fix": "f", "regex": "a"}]}`, "only pattern rules"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load([]byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestValidatorsCombine(t *testing.T) {
	cat, err := Load([]byte(`{"rules": [{"id": "x", "kind": "pattern", "description": "d", "severity": "high", "fix": "f",
		"regex": "=(\\S+)", "secret_group": 1, "validators": ["not-placeholder", "min-entropy:3.0"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := cat.Patterns[0]
	for line, want := range map[string]bool{"=Xk9vQ2mLp7Rt": true, "=your-key-here-x": false, "=aaaaaaaaaaaa": false} {
		if got := len(r.Find(line, strings.ToLower(line))) > 0; got != want {
			t.Errorf("%q matched=%v, want %v", line, got, want)
		}
	}
}
