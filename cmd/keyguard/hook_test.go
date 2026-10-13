package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gitRepo makes an empty repo in a temp dir. It also points git at an empty
// global config for the whole test: install-hook runs git itself, and a
// core.hooksPath in the developer's ~/.gitconfig would otherwise make the
// test write into their real hooks folder.
func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	return dir
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	if out, err := gitCmd(dir, args...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func gitCmd(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=t@example.com",
	)
	return cmd
}

func installHookCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(append([]string{"install-hook"}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInstallHook(t *testing.T) {
	dir := gitRepo(t)
	code, out, errOut := installHookCmd(t, dir)
	if code != exitClean {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if !strings.Contains(out, "installed pre-commit hook at "+hook) {
		t.Errorf("stdout = %q", out)
	}
	if got := readFile(t, hook); got != preCommitHook {
		t.Errorf("hook content = %q", got)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(hook)
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("hook is not executable: %v", info.Mode())
		}
	}
}

func TestInstallHookIdempotent(t *testing.T) {
	dir := gitRepo(t)
	installHookCmd(t, dir)
	code, out, _ := installHookCmd(t, dir)
	if code != exitClean || !strings.Contains(out, "already installed") {
		t.Errorf("second run: exit %d, stdout %q", code, out)
	}
	hooks := filepath.Join(dir, ".git", "hooks")
	if _, err := os.Stat(filepath.Join(hooks, "pre-commit.bak")); err == nil {
		t.Error("re-running made a backup of our own hook")
	}

	// An older keyguard hook (same marker, different body) is updated in place.
	hook := filepath.Join(hooks, "pre-commit")
	os.WriteFile(hook, []byte("#!/bin/sh\n"+hookMarker+"\nold version\n"), 0o755)
	code, out, _ = installHookCmd(t, dir)
	if code != exitClean || !strings.Contains(out, "updated") || readFile(t, hook) != preCommitHook {
		t.Errorf("update: exit %d, stdout %q", code, out)
	}
}

func TestInstallHookRefusesForeignHook(t *testing.T) {
	dir := gitRepo(t)
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	os.MkdirAll(filepath.Dir(hook), 0o755)
	foreign := "#!/bin/sh\nnpm test\n"
	os.WriteFile(hook, []byte(foreign), 0o755)

	code, _, errOut := installHookCmd(t, dir)
	if code != exitError {
		t.Errorf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errOut, "not installed by keyguard") || !strings.Contains(errOut, "--force") {
		t.Errorf("unhelpful message: %s", errOut)
	}
	if readFile(t, hook) != foreign {
		t.Error("foreign hook was modified")
	}
}

func TestInstallHookForceBacksUp(t *testing.T) {
	dir := gitRepo(t)
	hooks := filepath.Join(dir, ".git", "hooks")
	hook := filepath.Join(hooks, "pre-commit")
	os.MkdirAll(hooks, 0o755)
	os.WriteFile(hook, []byte("#!/bin/sh\necho first\n"), 0o755)
	os.WriteFile(hook+".bak", []byte("#!/bin/sh\necho older backup\n"), 0o755)

	code, out, errOut := installHookCmd(t, dir, "--force")
	if code != exitClean {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if readFile(t, hook) != preCommitHook {
		t.Error("hook not replaced")
	}
	// The existing .bak is kept too: the new backup takes the next free name.
	if got := readFile(t, hook+".bak.1"); got != "#!/bin/sh\necho first\n" {
		t.Errorf("backup = %q", got)
	}
	if got := readFile(t, hook+".bak"); got != "#!/bin/sh\necho older backup\n" {
		t.Errorf("earlier backup overwritten: %q", got)
	}
	if !strings.Contains(out, "pre-commit.bak.1") {
		t.Errorf("stdout doesn't mention the backup: %q", out)
	}
}

// A symlinked hook (common with shared hook scripts) must be replaced, not
// written through, or the shared script would be overwritten.
func TestInstallHookForceDoesNotFollowSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra privileges on Windows")
	}
	dir := gitRepo(t)
	shared := filepath.Join(t.TempDir(), "shared-hook")
	os.WriteFile(shared, []byte("#!/bin/sh\necho shared\n"), 0o755)
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	os.MkdirAll(filepath.Dir(hook), 0o755)
	if err := os.Symlink(shared, hook); err != nil {
		t.Fatal(err)
	}

	if code, _, errOut := installHookCmd(t, dir, "--force"); code != exitClean {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if readFile(t, shared) != "#!/bin/sh\necho shared\n" {
		t.Error("wrote through the symlink into the shared script")
	}
	if target, err := os.Readlink(hook + ".bak"); err != nil || target != shared {
		t.Errorf("backup should be the symlink itself: %q, %v", target, err)
	}
}

func TestInstallHookRespectsHooksPath(t *testing.T) {
	dir := gitRepo(t)
	gitRun(t, dir, "config", "core.hooksPath", "githooks")
	if code, _, errOut := installHookCmd(t, dir); code != exitClean {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if readFile(t, filepath.Join(dir, "githooks", "pre-commit")) != preCommitHook {
		t.Error("hook not written to core.hooksPath")
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "hooks", "pre-commit")); err == nil {
		t.Error("hook written to .git/hooks despite core.hooksPath")
	}
}

func TestInstallHookNotARepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	// Stop git from finding a repo above the temp dir.
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	code, _, errOut := installHookCmd(t, dir)
	if code != exitError || !strings.Contains(errOut, "not inside a git repository") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
	if code, _, _ := installHookCmd(t, dir, "extra-arg", "--force", dir); code != exitError {
		t.Errorf("two paths: exit %d, want %d", code, exitError)
	}
}

// The installed script itself: it must block the commit when keyguard exits
// 1, let it through on 0, and fail loudly when keyguard isn't on PATH. A fake
// keyguard keeps this fast; the real binary is exercised by TestExitCodes.
func TestPreCommitHookScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh to run the hook")
	}
	dir := gitRepo(t)
	if code, _, errOut := installHookCmd(t, dir); code != exitClean {
		t.Fatalf("install: exit %d: %s", code, errOut)
	}
	os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hi')\n"), 0o644)
	gitRun(t, dir, "add", ".")

	commit := func(path string) (string, error) {
		cmd := gitCmd(dir, "commit", "-q", "-m", "test")
		cmd.Env = append(cmd.Env, "PATH="+path)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	fakeKeyguard := func(exit string) string {
		bin := t.TempDir()
		os.WriteFile(filepath.Join(bin, "keyguard"), []byte("#!/bin/sh\necho \"fake keyguard $*\"\nexit "+exit+"\n"), 0o755)
		return bin
	}

	out, err := commit(t.TempDir()) // empty PATH dir: no keyguard
	if err == nil || !strings.Contains(out, "keyguard is not on PATH") {
		t.Errorf("missing keyguard: err=%v, output %q", err, out)
	}
	out, err = commit(fakeKeyguard("1"))
	if err == nil || !strings.Contains(out, "fake keyguard scan .") || !strings.Contains(out, "commit blocked") {
		t.Errorf("findings: err=%v, output %q", err, out)
	}
	out, err = commit(fakeKeyguard("0"))
	if err != nil {
		t.Errorf("clean scan should allow the commit: %v\n%s", err, out)
	}
}
