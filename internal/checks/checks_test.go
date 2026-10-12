package checks

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsEnvFile(t *testing.T) {
	for name, want := range map[string]bool{
		".env": true, ".env.local": true, "apps/web/.env.production": true,
		".env.example": false, ".env.sample": false, "env.ts": false, ".envrc": false, "config.env": false,
	} {
		if got := IsEnvFile(name); got != want {
			t.Errorf("IsEnvFile(%q) = %v, want %v", name, got, want)
		}
	}
}

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

func TestEnvExposureGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.co", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.co")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	write := func(name, s string) { os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644) }

	run("init", "-q")
	write(".gitignore", ".env.local\n")
	write(".env.local", "A=1\n")      // ignored: fine
	write(".env", "A=1\n")            // not ignored
	write(".env.production", "A=1\n") // committed
	run("add", ".gitignore", ".env.production")
	run("commit", "-q", "-m", "x")

	got := map[string]string{}
	for _, f := range EnvExposure(dir, []string{".env.local", ".env", ".env.production"}) {
		got[f.File] = f.RuleID
	}
	want := map[string]string{".env": "env-file-not-ignored", ".env.production": "env-file-committed"}
	if len(got) != len(want) || got[".env"] != want[".env"] || got[".env.production"] != want[".env.production"] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEnvExposureNoRepo(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env*\n"), 0o644)
	if fs := EnvExposure(dir, []string{".env"}); len(fs) != 0 {
		t.Errorf(".gitignore covers .env but got %+v", fs)
	}
}
