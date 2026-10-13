# What I learned building keyguard

My first Go project: a secret scanner I can put in front of my own deploys. Built in milestones, pairing with Claude Code, and every bug below was real.

## Devlog

| # | Topic | Headline |
|---|---|---|
| [01](devlog/01-setup-and-cli.md) | Setup & CLI | Go's `flag` silently ignores flags after the path |
| [02](devlog/02-regex-rules.md) | Regex rules | One `strings.Contains` pre-filter made the scanner ~16× faster |
| [03](devlog/03-concurrency.md) | Concurrency | A worker pool, and why reading `walkErr` without a mutex isn't a race |
| [04](devlog/04-entropy.md) | Entropy | A fixed threshold ignores every short secret, because max entropy is log2(n) |
| [05](devlog/05-config-checks.md) | Config checks | The worst leaks often contain no secret in the code at all |
| [06](devlog/06-git-history.md) | Git history | "I deleted the key" doesn't mean it's gone |
| [07](devlog/07-reports-and-html.md) | Reports & HTML | My own leak test caught private-key bodies in the context lines |
| [08](devlog/08-dogfooding.md) | Dogfooding | The scanner flagged its own tests |
| [09](devlog/09-security-review.md) | Security review | Scanning an untrusted repo could execute code via git textconv |
| [10](devlog/10-refactor.md) | Refactor | One embedded rule catalogue, and channels instead of a happens-before proof |
| [11](devlog/11-no-silent-gaps.md) | No silent gaps | A ✔ that means "I didn't look" is the worst bug a scanner can have |
| [12](devlog/12-more-stacks.md) | More stacks | Secrets look the same everywhere; how they leak is what's stack-specific |
| [13](devlog/13-install-hook.md) | Pre-commit hook | Writing through a symlinked hook would overwrite someone else's script |
| [14](devlog/14-identifiers.md) | Identifiers | A filter that hides findings must be tested against the keys it could hide |

## Top 5 lessons

1. **False positives are the product.** A noisy scanner gets turned off. Most of the work was *removing* findings: quoted-only entropy, placeholder detection, anon-vs-service_role JWT decoding, lockfile skipping.
2. **Every output is a leak vector.** The secret value wasn't the only risk: context lines, PEM bodies, and even hashes all needed thought. A test that greps every output for every fake secret earned its keep immediately.
3. **Go's concurrency is easy to start and subtle to finish.** Goroutines and channels make a worker pool ~20 lines. Knowing *which channel close ends which loop*, and why that makes unsynchronised reads safe, is the actual skill. `go test -race` should always be on.
4. **Delegate to git, don't re-implement it.** `git check-ignore`, `git ls-files` and `git log -p` handle edge cases I'd never get right.
5. **A security tool's own repo is a target.** Fake secrets are built at runtime so the repo has none, and `make self-scan` keeps it that way.

## Reviews

After the build I ran three automated reviews (security, code quality, UX/accessibility). The security one attacked the binary and found 6 issues, including a **code-execution path via git textconv** and a **private-key leak** in context lines. All are fixed with regression tests (see [devlog 09](devlog/09-security-review.md)). Code quality caught SARIF fingerprint collisions and the history scan ignoring `.keyguardignore`. UX fixed badge contrast, focus rings, color-only highlighting, and filter controls that showed without JS.

## Next (v2 ideas)

- Live key verification (opt-in): ask the provider whether a found key is still active.
- ~~A pre-commit hook installer: `keyguard install-hook`.~~ Done in [devlog 13](devlog/13-install-hook.md).
- ~~A dictionary-word check to stop flagging identifiers like `handleOAuth2CallbackV2`.~~ Done in [devlog 14](devlog/14-identifiers.md).
