package gitscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", // ignore the user's hooks/signing config
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// The scenario this feature exists for: a key is committed, then "removed".
func TestFindsDeletedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	key := "sk_" + "live_" + strings.Repeat("aB3xY7kQ", 3)
	write := func(name, content string) {
		os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
	}

	gitRun(t, dir, "init", "-q")
	write("app.js", "console.log('hi')\n")
	gitRun(t, dir, "add", ".")
	gitRun(t, dir, "commit", "-q", "-m", "init")

	write("pay.js", "// pay\nconst stripe = Stripe(\""+key+"\");\n")
	write(".env", "API_TOKEN=abc\n")
	gitRun(t, dir, "add", ".")
	gitRun(t, dir, "commit", "-q", "-m", "add payments")

	os.Remove(filepath.Join(dir, "pay.js"))
	os.Remove(filepath.Join(dir, ".env"))
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "remove secrets")

	res, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Commits != 3 {
		t.Errorf("commits = %d, want 3", res.Commits)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.File+"|"+f.RuleID] = true
		if f.Commit == nil || len(f.Commit.SHA) != 40 {
			t.Errorf("finding without commit: %+v", f)
		}
		if strings.Contains(f.Secret, key) || (len(f.Context) > 0 && strings.Contains(f.Context[0].Text, key)) {
			t.Error("raw secret leaked into finding")
		}
		if f.RuleID == "stripe-live-key" && f.Line != 2 {
			t.Errorf("line = %d, want 2 (from the hunk header)", f.Line)
		}
	}
	for _, want := range []string{"pay.js|stripe-live-key", ".env|env-file-in-history"} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
}

// Content lines that start with "++" become "+++" in a diff and must not be
// mistaken for a file header.
func TestParserPlusPlusContent(t *testing.T) {
	p := newParser(nil, "")
	p.line(commitMarker + "abc\x1fme\x1f2026-01-01")
	p.line("diff --git a/a.c b/a.c")
	p.line("+++ b/a.c")
	p.line("@@ -0,0 +1,2 @@")
	if p.inHeader {
		t.Fatal("still in header after @@")
	}
	if p.file != "a.c" || p.lineNo != 1 {
		t.Fatalf("file=%q line=%d", p.file, p.lineNo)
	}
}

func TestNotARepo(t *testing.T) {
	if _, err := Scan(context.Background(), Options{Root: t.TempDir()}); err == nil {
		t.Error("want error outside a git repo")
	}
}

// A multi-megabyte line (committed minified bundle) must neither abort nor hang the scan.
func TestEachLineTruncatesLongLines(t *testing.T) {
	long := strings.Repeat("x", 3*maxLine)
	var got []string
	err := eachLine(strings.NewReader("a\n"+long+"\nb"), func(l string) { got = append(got, l) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "a" || len(got[1]) != maxLine || got[2] != "b" {
		t.Errorf("got %d lines, middle len %d", len(got), len(got[1]))
	}
}

func TestHistoryHonoursIgnorePolicy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	key := "sk_" + "live_" + strings.Repeat("aB3xY7kQ", 3)
	os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o755)
	os.MkdirAll(filepath.Join(dir, "docs"), 0o755)
	os.WriteFile(filepath.Join(dir, "node_modules", "x", "i.js"), []byte(`"`+key+`"`), 0o644)
	os.WriteFile(filepath.Join(dir, "docs", "a.md"), []byte(key), 0o644)
	os.WriteFile(filepath.Join(dir, ".keyguardignore"), []byte("docs/\n"), 0o644)
	gitRun(t, dir, "init", "-q")
	gitRun(t, dir, "add", "-A", "-f")
	gitRun(t, dir, "commit", "-q", "-m", "x")
	res, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("ignored paths reported: %+v", res.Findings)
	}
}

// Security review repro: a scanned repo's own .git/config must not be able to
// make keyguard run a program (diff textconv).
func TestTextconvNotExecuted(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "pwned")
	gitRun(t, dir, "init", "-q")
	gitRun(t, dir, "config", "diff.evil.textconv", "touch "+marker+" && cat")
	os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.txt diff=evil\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644)
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "x")
	if _, err := Scan(context.Background(), Options{Root: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("textconv program was executed")
	}
}
