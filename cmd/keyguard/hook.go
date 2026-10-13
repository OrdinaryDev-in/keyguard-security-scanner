package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/gitcmd"
)

// hookMarker identifies a pre-commit hook written by keyguard, so a re-run
// can update it while anyone else's hook is left alone.
const hookMarker = "# keyguard-pre-commit-hook"

// preCommitHook is POSIX sh so it also runs under Git for Windows. Git starts
// pre-commit hooks in the root of the working tree, hence `scan .`.
const preCommitHook = `#!/bin/sh
` + hookMarker + `
# Installed by "keyguard install-hook". Scans the working tree before each
# commit and blocks it on findings at or above the default --fail-on (high).
# Skip once with: git commit --no-verify

if ! command -v keyguard >/dev/null 2>&1; then
	echo "keyguard pre-commit hook: keyguard is not on PATH, so the commit was not scanned." >&2
	echo "  Install it: go install github.com/OrdinaryDev-in/keyguard-security-scanner/cmd/keyguard@latest" >&2
	echo "  (and add \"\$(go env GOPATH)/bin\" to PATH), or skip once with: git commit --no-verify" >&2
	exit 1
fi

keyguard scan .
status=$?
case $status in
0) ;;
1) echo "keyguard: commit blocked. Fix the findings above, mark false positives with keyguard:ignore, or skip once with: git commit --no-verify" >&2 ;;
*) echo "keyguard: scan failed (exit $status), commit blocked. Skip once with: git commit --no-verify" >&2 ;;
esac
exit $status
`

func runInstallHook(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install-hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	force := fs.Bool("force", false, "replace an existing pre-commit hook (it is kept as pre-commit.bak)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: keyguard install-hook [path] [--force]

Installs a git pre-commit hook in the repo at path (default: .) that runs
"keyguard scan" and blocks the commit on high-severity findings. keyguard must
be on PATH when you commit.

The hook scans the working tree, not only the staged changes: unstaged edits
are scanned too, and a secret that is staged but then deleted from the file
before committing is not caught.

Flags:
`)
		fs.PrintDefaults()
	}
	pos, err := parseInterleaved(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitClean
	}
	if err != nil {
		return exitError
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, "keyguard: install-hook takes one path")
		return exitError
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	}

	hooks, err := hooksDir(context.Background(), dir)
	if err != nil {
		fmt.Fprintln(stderr, "keyguard:", err)
		return exitError
	}
	msg, err := installHook(hooks, *force)
	if err != nil {
		fmt.Fprintln(stderr, "keyguard:", err)
		return exitError
	}
	fmt.Fprintln(stdout, "keyguard:", msg)
	return exitClean
}

// hooksDir asks git where hooks live, so core.hooksPath and linked worktrees
// (which share the main repo's hooks) are respected.
func hooksDir(ctx context.Context, dir string) (string, error) {
	out, err := gitcmd.Command(ctx, dir, "rev-parse", "--is-inside-work-tree", "--git-path", "hooks").Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("%s is not inside a git repository", dir)
		}
		return "", fmt.Errorf("running git: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		return "", fmt.Errorf("unexpected output from git rev-parse: %q", out)
	}
	if lines[0] != "true" {
		return "", fmt.Errorf("%s has no working tree (bare repo or inside .git), so there is nothing to commit from", dir)
	}
	hooks := lines[1]
	if !filepath.IsAbs(hooks) {
		// --git-path is relative to the directory git ran in.
		hooks = filepath.Join(dir, hooks)
	}
	return hooks, nil
}

// installHook writes the pre-commit hook into hooks and returns what it did.
// It never overwrites a hook it didn't write unless force is set, and then
// backs the old one up first.
func installHook(hooks string, force bool) (string, error) {
	path := filepath.Join(hooks, "pre-commit")
	existing, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Also true for a dangling symlink; replacing that is harmless.
		existing = nil
	case err != nil:
		return "", fmt.Errorf("reading existing hook: %w", err)
	}

	backup := ""
	if existing != nil {
		switch {
		case bytes.Equal(existing, []byte(preCommitHook)):
			return "pre-commit hook already installed at " + path, nil
		case !bytes.Contains(existing, []byte(hookMarker)) && !force:
			return "", fmt.Errorf(`%s already exists and was not installed by keyguard. Not overwriting it.
  To keep it and add keyguard, put this line in it:  keyguard scan . || exit 1
  To replace it (the old hook is saved as pre-commit.bak):  keyguard install-hook --force`, path)
		case !bytes.Contains(existing, []byte(hookMarker)):
			if backup, err = backupHook(path); err != nil {
				return "", err
			}
		}
	}

	if err := os.MkdirAll(hooks, 0o755); err != nil {
		return "", fmt.Errorf("creating hooks directory: %w", err)
	}
	if err := writeExecutable(path, []byte(preCommitHook)); err != nil {
		return "", fmt.Errorf("writing hook: %w", err)
	}
	switch {
	case backup != "":
		return fmt.Sprintf("installed pre-commit hook at %s (previous hook saved as %s)", path, backup), nil
	case existing != nil:
		return "updated keyguard pre-commit hook at " + path, nil
	}
	return "installed pre-commit hook at " + path, nil
}

// backupHook renames path to the first free pre-commit.bak, .bak.1, ... name,
// so an earlier backup is never overwritten either. Rename moves a symlink
// itself, not the file it points to.
func backupHook(path string) (string, error) {
	for i := 0; i < 100; i++ {
		bak := path + ".bak"
		if i > 0 {
			bak = fmt.Sprintf("%s.bak.%d", path, i)
		}
		if _, err := os.Lstat(bak); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(path, bak); err != nil {
				return "", fmt.Errorf("backing up existing hook: %w", err)
			}
			return bak, nil
		}
	}
	return "", fmt.Errorf("backing up existing hook: too many %s.bak files", path)
}

// writeExecutable writes via a temp file and rename, so an existing symlink
// is replaced rather than followed (writing through it would clobber the
// shared script it points to), and a crash never leaves a half-written hook.
func writeExecutable(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pre-commit-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp uses 0600; git needs the hook to be executable.
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
