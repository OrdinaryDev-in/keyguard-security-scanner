// Package rules defines the known secret formats keyguard looks for.
//
// Go's regexp package uses RE2: matching is guaranteed linear-time (no
// catastrophic backtracking on a hostile file), but there are no lookaheads or
// backreferences. Anything RE2 can't express goes in a Rule's Validate func.
package rules

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"keyguard/internal/entropy"
	"keyguard/internal/finding"
)

type Rule struct {
	ID          string
	Description string
	Severity    finding.Severity
	// Keywords are cheap lowercase substrings checked before running the
	// regex. Most lines contain none of them, so most regexes never run.
	Keywords []string
	Regex    *regexp.Regexp
	// SecretGroup is the capture group holding the secret (0 = whole match).
	SecretGroup int
	// Validate rejects regex matches that aren't real secrets. Optional.
	Validate func(secret string) bool
	Fix      string
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

const rotate = "Revoke/rotate this key in the provider's dashboard first (assume it is compromised), then load it from a server-side environment variable."

// Default returns the built-in rules. Order matters: when two rules match the
// same text with equal severity, the earlier (more specific) rule wins.
func Default() []*Rule {
	return []*Rule{
		{
			ID: "aws-access-key-id", Description: "AWS access key ID", Severity: finding.High,
			Keywords: []string{"akia", "asia"},
			Regex:    regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`), SecretGroup: 1,
			Fix: rotate + " Prefer IAM roles or short-lived credentials over long-lived keys.",
		},
		{
			ID: "aws-secret-access-key", Description: "AWS secret access key", Severity: finding.High,
			Keywords: []string{"aws"},
			Regex:    regexp.MustCompile(`(?i)aws[\w.-]{0,20}?(?:secret|private)[\w.-]{0,20}?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})\b`), SecretGroup: 1,
			Fix: rotate,
		},
		{
			ID: "github-token", Description: "GitHub token", Severity: finding.High,
			Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
			Regex:    regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b`), SecretGroup: 1,
			Fix: "Revoke it at github.com/settings/tokens, then use a fine-grained token stored in your CI secrets.",
		},
		{
			ID: "stripe-live-key", Description: "Stripe live secret/restricted key", Severity: finding.High,
			Keywords: []string{"_live_"},
			Regex:    regexp.MustCompile(`\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b`), SecretGroup: 1,
			Fix: "Roll the key in the Stripe dashboard (Developers → API keys). It can move real money.",
		},
		{
			ID: "stripe-test-key", Description: "Stripe test secret key", Severity: finding.Low,
			Keywords: []string{"sk_test_"},
			Regex:    regexp.MustCompile(`\b(sk_test_[0-9a-zA-Z]{24,99})\b`), SecretGroup: 1,
			Fix: "Test keys can't move money, but still belong in env vars so live keys never end up here by habit.",
		},
		{
			ID: "anthropic-api-key", Description: "Anthropic API key", Severity: finding.High,
			Keywords: []string{"sk-ant-"},
			Regex:    regexp.MustCompile(`\b(sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,120})`), SecretGroup: 1,
			Fix: rotate,
		},
		{
			ID: "openai-api-key", Description: "OpenAI API key", Severity: finding.High,
			// "T3BlbkFJ" is base64 for "OpenAI" — every OpenAI key embeds it.
			Keywords: []string{"t3blbkfj"},
			Regex:    regexp.MustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})`), SecretGroup: 1,
			Fix: rotate,
		},
		{
			ID: "slack-token", Description: "Slack token", Severity: finding.High,
			Keywords: []string{"xox"},
			Regex:    regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,})`), SecretGroup: 1,
			Fix: rotate,
		},
		{
			ID: "slack-webhook", Description: "Slack incoming webhook URL", Severity: finding.Medium,
			Keywords: []string{"hooks.slack.com"},
			Regex:    regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)`), SecretGroup: 1,
			Fix: "Anyone with this URL can post to your channel. Regenerate it in the Slack app settings.",
		},
		{
			ID: "sendgrid-api-key", Description: "SendGrid API key", Severity: finding.High,
			Keywords: []string{"sg."},
			Regex:    regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`), SecretGroup: 1,
			Fix: rotate,
		},
		{
			ID: "supabase-secret-key", Description: "Supabase secret API key", Severity: finding.High,
			Keywords: []string{"sb_secret_"},
			Regex:    regexp.MustCompile(`\b(sb_secret_[A-Za-z0-9_-]{20,})`), SecretGroup: 1,
			Fix: "This key bypasses Row Level Security. Rotate it in Supabase → Project Settings → API and use it only on the server.",
		},
		{
			ID: "supabase-service-role-jwt", Description: "Supabase service_role JWT", Severity: finding.High,
			Keywords: []string{"eyj"},
			Regex:    jwtRegex, SecretGroup: 1,
			Validate: func(s string) bool { return jwtRole(s) == "service_role" },
			Fix:      "service_role bypasses Row Level Security — anyone holding it owns your database. Rotate the JWT secret in Supabase and keep this key server-side only.",
		},
		{
			ID: "jwt", Description: "JSON Web Token", Severity: finding.Low,
			Keywords: []string{"eyj"},
			Regex:    jwtRegex, SecretGroup: 1,
			// A Supabase anon key is meant to be public; don't flag it.
			Validate: func(s string) bool { r := jwtRole(s); return r != "anon" && r != "service_role" },
			Fix:      "Check whether this token grants access. If it does, remove it and issue tokens at runtime instead.",
		},
		{
			ID: "private-key", Description: "Private key", Severity: finding.High,
			Keywords: []string{"private key"},
			Regex:    regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)`), SecretGroup: 1,
			Fix: "Delete the key file from the repo, generate a new key pair, and revoke the old public key wherever it is trusted.",
		},
		{
			ID: "google-api-key", Description: "Google API key", Severity: finding.Medium,
			Keywords: []string{"aiza"},
			Regex:    regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`), SecretGroup: 1,
			Fix: "Firebase web keys are designed to be public, but only if restricted. Add HTTP-referrer and API restrictions in Google Cloud Console; rotate it if it's a server key.",
		},
		{
			ID: "database-url-password", Description: "Password in database connection string", Severity: finding.High,
			Keywords: []string{"://"},
			Regex:    regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:\s/'"@]+:([^@\s'"/]+)@`), SecretGroup: 1,
			Validate: notPlaceholder,
			Fix:      "Change the database password, then read the full URL from an environment variable (DATABASE_URL).",
		},
		{
			ID: "generic-secret", Description: "Hardcoded secret in assignment", Severity: finding.Medium,
			Keywords:    []string{"secret", "passw", "pwd", "token", "key", "auth", "credential"},
			Regex:       regexp.MustCompile(`(?i)[\w.-]*(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|access[_-]?key|auth[_-]?key|credential)[\w.-]*['"]?\s*(?::=|=|:|=>)\s*['"]([^'"\s]{8,})['"]`),
			SecretGroup: 1,
			Validate: func(s string) bool {
				return notPlaceholder(s) && entropy.IsRandom(s, 3.0)
			},
			Fix: "Move the value into an environment variable or a secrets manager and rotate it if it was ever committed.",
		},
	}
}

var jwtRegex = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`)

// jwtRole decodes the (unsigned, readable by anyone) JWT payload and returns its "role" claim.
func jwtRole(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	return claims.Role
}

var placeholders = []string{
	"your", "example", "xxxx", "changeme", "change-me", "placeholder", "dummy", "sample",
	"fake", "redacted", "<", ">", "${", "{{", "process.env", "os.environ", "****", "...", "password",
}

func notPlaceholder(s string) bool {
	l := strings.ToLower(s)
	for _, p := range placeholders {
		if strings.Contains(l, p) {
			return false
		}
	}
	return true
}
