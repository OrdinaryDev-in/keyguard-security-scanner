# 13 · `keyguard install-hook`: catching the leak before the commit

**Built:** `keyguard install-hook [path] [--force]`, which writes a git `pre-commit` hook that runs `keyguard scan .` and blocks the commit on findings.
**Concepts:** git hooks, asking git where things live, never clobbering someone else's file, atomic writes with temp file + rename.

## Why

Devlog 06 showed that "I deleted the key" doesn't help once the key is in a commit. CI catches it, but only after it's pushed. A pre-commit hook stops it before the commit exists, so there's nothing to rewrite or rotate. Devlog 08's notes already suggested doing this by hand. Now it's one command:

```
$ keyguard install-hook
keyguard: installed pre-commit hook at .git/hooks/pre-commit

$ git commit -m "add payments"
Secrets in code (1)
  HIGH    Stripe live secret/restricted key  pay.js:1  sk_l****
✖ 1 finding: 1 high, 0 medium, 0 low (2 files, 0ms)
keyguard: commit blocked. Fix the findings above, mark false positives with keyguard:ignore, or skip once with: git commit --no-verify
```

## How a hook works

A hook is just an executable file named after the event (`pre-commit`) in the hooks folder. Git runs it before creating the commit. A non-zero exit cancels the commit. That's the whole contract, and keyguard's exit codes already fit it (`1` = findings, `2` = error). The hook is a few lines of POSIX `sh`, so it also runs under Git for Windows:

```sh
if ! command -v keyguard >/dev/null 2>&1; then
	echo "keyguard pre-commit hook: keyguard is not on PATH, so the commit was not scanned." >&2
	exit 1
fi
keyguard scan .
```

If keyguard is missing, the hook **fails closed**: it blocks the commit and says why. A hook that passes when it can't scan would be devlog 11's "silent ✔" again.

## Ask git, don't assume `.git/hooks`

The hooks folder isn't always `.git/hooks`:

- `core.hooksPath` can point anywhere (husky sets it to `.husky/`).
- In a linked worktree, `.git` is a *file*, and hooks live in the main repo's git dir.

`git rev-parse --git-path hooks` answers all of that. One call also checks we're in a working tree:

```go
gitcmd.Command(ctx, dir, "rev-parse", "--is-inside-work-tree", "--git-path", "hooks")
```

It goes through `gitcmd`, so the `core.fsmonitor` hardening from devlog 09 applies here too. Outside a repo, git exits non-zero and keyguard reports `not inside a git repository` with exit 2.

## Never clobber someone else's hook

People already have pre-commit hooks (linters, husky, tests). Overwriting one silently would be a nasty surprise, so the rules are:

| What's there | What happens |
|---|---|
| nothing | install |
| our hook, identical | "already installed", nothing written (idempotent) |
| our hook, older version | update in place |
| someone else's hook | refuse (exit 2), and suggest adding `keyguard scan . \|\| exit 1` to it or using `--force` |
| someone else's hook + `--force` | rename it to `pre-commit.bak` (or `.bak.1`, … if that exists), then install |

"Ours" means the file contains the marker line `# keyguard-pre-commit-hook`. Comparing against the exact script wouldn't work, because then an upgraded keyguard would see its own older hook as foreign.

## Gotcha 1: writing through a symlink

Shared hook setups often make `pre-commit` a **symlink** to a script used by many repos. `os.WriteFile(path, …)` follows symlinks, so `--force` would have overwritten the shared script itself, in every repo that uses it. The fix is to never write to the path directly:

```go
tmp, _ := os.CreateTemp(filepath.Dir(path), ".pre-commit-*")
// write, close, chmod 0755 ...
os.Rename(tmp.Name(), path) // replaces the symlink itself, not its target
```

`os.Rename` acts on the directory entry, so it replaces the symlink and moves it when backing up. A bonus: rename is atomic, so a crash never leaves a half-written hook. `CreateTemp` makes files `0600`, so the explicit `Chmod(0o755)` matters. Without it, git skips the hook with only a warning. `TestInstallHookForceDoesNotFollowSymlink` covers this.

## Gotcha 2: tests that touch your real config

The tests run `git init` in a temp dir, but `install-hook` asks git for the hooks path, and git reads `~/.gitconfig`. If my global config had a `core.hooksPath`, the test would have installed a hook into **my real global hooks folder**. The test helper sets `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_NOSYSTEM=1` with `t.Setenv`, so every git process the code starts sees a clean config. The "not a repo" test also sets `GIT_CEILING_DIRECTORIES`. Otherwise git walks up from the temp dir and might find a repo above it.

The hook script itself is tested with a **fake `keyguard`** (a 2-line shell script on `PATH` that exits 0 or 1). That checks the sh wiring (PATH lookup, exit code passed through, blocking message) in milliseconds, without building the real binary.

## Trade-off: working tree, not staged content

The hook scans the files on disk, not what's staged. That keeps it simple and keeps the `.env` checks working (they ask git whether the file is tracked). Two side effects:

- Unstaged edits are scanned too, so a secret you haven't `git add`ed still blocks the commit. That's annoying but safe.
- A secret that's staged and then deleted from the file before committing **is not caught**. That's the real gap. CI with `--history` still catches it after the push.

Scanning only the index (export it with `git checkout-index --prefix=<tmp>/` and scan that) is a possible v2. The `.env` checks would then need to run against the real repo, not the temp copy.

## Your notes
<!-- Try: keyguard install-hook in this repo, then commit a fake key built at runtime. Does `git commit --no-verify` feel too easy? -->
