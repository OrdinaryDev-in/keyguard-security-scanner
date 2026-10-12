// Package gitcmd builds hardened git commands. Every git invocation in
// keyguard goes through here, so the hardening can't be forgotten in one place.
package gitcmd

import (
	"context"
	"os/exec"
)

// Command returns `git -c core.fsmonitor=false -C dir args...`.
//
// A scanned repo's .git/config is attacker-controlled: core.fsmonitor names a
// program git would run on status-like commands. Callers that render diffs
// must also pass --no-textconv/--no-ext-diff themselves.
func Command(ctx context.Context, dir string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "git", append([]string{"-c", "core.fsmonitor=false", "-C", dir}, args...)...)
}
