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
	byID := map[string]*Rule{}
	for _, rule := range Default() {
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

func TestRuleIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range Default() {
		if seen[rule.ID] {
			t.Errorf("duplicate rule ID %s", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Fix == "" {
			t.Errorf("rule %s has no fix advice", rule.ID)
		}
	}
}

// Keywords must be lowercase, or the pre-filter silently disables the rule.
func TestKeywordsLowercase(t *testing.T) {
	for _, rule := range Default() {
		for _, k := range rule.Keywords {
			if k != strings.ToLower(k) {
				t.Errorf("rule %s keyword %q is not lowercase", rule.ID, k)
			}
		}
	}
}
