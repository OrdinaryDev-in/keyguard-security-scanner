package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

	fs, err := envExposure(context.Background(), dir, []string{".env.local", ".env", ".env.production"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.File] = f.RuleID
	}
	want := map[string]string{".env": "env-file-not-ignored", ".env.production": "env-file-committed"}
	if len(got) != len(want) || got[".env"] != want[".env"] || got[".env.production"] != want[".env.production"] {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, f := range fs {
		if f.RuleID == "env-file-committed" && !strings.HasPrefix(f.Fix, "Run `git rm --cached .env.production`") {
			t.Errorf("file name not filled into fix: %q", f.Fix)
		}
	}
}

func TestEnvExposureNoRepo(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env*\n"), 0o644)
	fs, err := envExposure(context.Background(), dir, []string{".env"})
	if err != nil || len(fs) != 0 {
		t.Errorf(".gitignore covers .env but got %+v, %v", fs, err)
	}
}

func TestEnvExposureCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := envExposure(ctx, t.TempDir(), []string{".env"}); err == nil {
		t.Error("cancelled context should be reported, not turned into findings")
	}
}
