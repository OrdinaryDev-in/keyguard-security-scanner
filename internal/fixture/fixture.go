// Package fixture writes a fake "vulnerable app" used by tests and demos.
//
// Every fake secret is assembled at runtime from fragments and a seeded
// random generator, so this repository never contains a literal secret.
// Otherwise keyguard (and GitHub push protection) would flag its own test data.
package fixture

import (
	"encoding/base64"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Expected lists "file|rule" pairs a scan of the fixture must report, and nothing else.
var Expected = []string{
	".env.example|openai-api-key",
	".env.local|env-file-not-ignored",
	".env.local|secret-in-public-env-var",
	"app/dashboard/page.tsx|supabase-admin-key-in-client",
	"config/aws.js|aws-access-key-id",
	"config/aws.js|aws-secret-access-key",
	"config/production.json|debug-in-production-config",
	"keys/id_rsa|private-key",
	"scripts/deploy.sh|database-url-password",
	"src/firebase.ts|google-api-key",
	"src/lib/github.ts|github-token",
	"src/lib/stripe.ts|stripe-live-key",
	"src/lib/supabase-admin.ts|supabase-service-role-jwt",
	"src/utils/webhook.js|high-entropy-string",
}

type gen struct{ r *rand.Rand }

func (g gen) str(charset string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(charset[g.r.Intn(len(charset))])
	}
	return b.String()
}

func jwt(role string, sig string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"iss":"supabase","ref":"demoproject","role":"`+role+`","iat":1700000000}`)) + "." + sig
}

// Files returns the fixture as path -> content.
func Files() map[string]string {
	g := gen{rand.New(rand.NewSource(42))}
	stripe := "sk_" + "live_" + g.str(alnum, 24)
	return map[string]string{
		"src/lib/stripe.ts": "import Stripe from \"stripe\";\n\n" +
			"// TODO: move to env before launch\n" +
			"export const stripe = new Stripe(\"" + stripe + "\");\n",

		"config/aws.js": "module.exports = {\n" +
			"  region: \"us-east-1\",\n" +
			"  accessKeyId: \"" + "AK" + "IA" + g.str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) + "\",\n" +
			"  aws_secret_access_key: \"" + g.str(alnum+"/+", 40) + "\",\n" +
			"};\n",

		"src/lib/github.ts": "const octokit = new Octokit({ auth: \"" + "gh" + "p_" + g.str(alnum, 36) + "\" });\n",

		"src/firebase.ts": "export const firebaseConfig = {\n  apiKey: \"" + "AI" + "za" + g.str(alnum+"_-", 35) + "\",\n  projectId: \"demo-app\",\n};\n",

		"app/dashboard/page.tsx": "\"use client\";\n\nimport { createClient } from \"@supabase/supabase-js\";\n\n" +
			"const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n",

		"src/lib/supabase-admin.ts": "export const SERVICE_KEY =\n  \"" + jwt("service_role", g.str(alnum+"_-", 43)) + "\";\n",

		".env.local": "NEXT_PUBLIC_SUPABASE_URL=https://demoproject.supabase.co\n" +
			"NEXT_PUBLIC_STRIPE_SECRET_KEY=" + g.str(alnum, 30) + "\n",

		".env.example": "# Copy to .env.local and fill in\nOPENAI_API_KEY=" +
			"sk-proj-" + g.str(alnum, 24) + "T3Blbk" + "FJ" + g.str(alnum, 24) + "\n",

		"scripts/deploy.sh": "#!/bin/sh\nexport DATABASE_URL=\"postgres://admin:" + g.str(alnum, 14) + "@db.internal:5432/app\"\nnpm run migrate\n",

		"keys/id_rsa": "-----BEGIN RSA " + "PRIV" + "ATE KEY-----\n" + g.str(alnum+"+/", 64) + "\n" + g.str(alnum+"+/", 64) +
			"\n-----END RSA " + "PRIV" + "ATE KEY-----\n",

		"src/utils/webhook.js": "const cfg = { endpoint: \"/hooks/deploy\", signing: \"" + g.str(alnum, 40) + "\" };\nexport default cfg;\n",

		"config/production.json": "{\n  \"port\": 8080,\n  \"debug\": true\n}\n",

		// Everything below must produce NO findings.
		"src/safe.ts": "// None of these are secrets.\n" +
			"const apiKey = process.env.API_KEY;\n" +
			"const login = { password: \"your-password-here\" };\n" +
			"export const SUPABASE_ANON_KEY = \"" + jwt("anon", g.str(alnum+"_-", 43)) + "\";\n" +
			"const requestId = \"3f2c9a1e-8b4d-4e6f-9a2b-7c1d5e8f0a3b\";\n" +
			"const handler = \"handleOAuth2CallbackV2Route\";\n" +
			"// Example: sk_" + "live_" + strings.Repeat("x", 24) + "\n",

		"src/ignored.ts": "const legacy = \"" + "sk_" + "live_" + g.str(alnum, 24) + "\"; // keyguard:ignore — revoked key kept for docs\n",

		"package-lock.json": "{\n  \"packages\": {\n    \"node_modules/stripe\": {\n      \"integrity\": \"sha512-" +
			g.str(alnum+"+/", 86) + "==\"\n    }\n  }\n}\n",

		"README.md": "# Demo app\n\nA deliberately insecure app for trying keyguard. All keys are fake.\n",
	}
}

// Write creates the fixture under dir.
func Write(dir string) error {
	for rel, content := range Files() {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
