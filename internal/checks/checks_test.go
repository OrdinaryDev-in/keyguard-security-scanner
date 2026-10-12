package checks

import "testing"

func TestPublicSecretVar(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{`const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY`, true},
		{`import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY`, true},
		{`EXPO_PUBLIC_ADMIN_KEY`, true},
		{`process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY`, false}, // public by design
		{`process.env.STRIPE_SECRET_KEY`, false},             // server-only: fine
		{`NEXT_PUBLIC_MAPBOX_TOKEN`, false},                  // public tokens are a thing
	}
	for _, tt := range tests {
		got := len(Line("a.ts", tt.line, 1, false)) > 0
		if got != tt.want {
			t.Errorf("Line(%q) flagged=%v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestEnvFileReportsNamesOnly(t *testing.T) {
	data := []byte("# comment\nexport NEXT_PUBLIC_DB_PASSWORD=hunter2hunter2\nSTRIPE_SECRET_KEY=abc\n")
	fs := EnvFile(".env", data)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %+v", fs)
	}
	if fs[0].Secret != "NEXT_PUBLIC_DB_PASSWORD" || fs[0].Line != 2 {
		t.Errorf("got %+v", fs[0])
	}
}

func TestIsClientFile(t *testing.T) {
	tests := []struct {
		path string
		head string
		want bool
	}{
		{"app/page.tsx", `"use client";`, true},
		{"app/page.tsx", `export default async function Page() {}`, false},
		{"src/components/Button.tsx", ``, true},
		{"src/components/api/route.ts", ``, false},
		{"src/lib/db.server.ts", ``, false},
		{"components/readme.md", ``, false},
	}
	for _, tt := range tests {
		if got := IsClientFile(tt.path, []byte(tt.head)); got != tt.want {
			t.Errorf("IsClientFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSupabaseAdminInClient(t *testing.T) {
	line := `createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)`
	if len(Line("app/page.tsx", line, 1, true)) != 1 {
		t.Error("client usage not flagged")
	}
	if len(Line("app/api/route.ts", line, 1, false)) != 0 {
		t.Error("server usage should be fine")
	}
	if len(Line("app/page.tsx", "// "+line, 1, true)) != 0 {
		t.Error("comment should be ignored")
	}
}
