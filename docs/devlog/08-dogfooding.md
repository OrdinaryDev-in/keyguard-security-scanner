# 08 · Dogfooding: the scanner flagged itself

**Concept:** a security tool's own test data is a liability.

The first `keyguard scan .` on its own repo reported **9 findings**, all in test files: fake DB passwords, high-entropy test strings, the fixture's `NEXT_PUBLIC_STRIPE_SECRET_KEY`. Every secret scanner has this problem. GitHub push protection would also block a push containing realistic-looking Stripe or GitHub tokens.

## Two-part fix

1. **No literal secrets in the repo, ever.** Fake keys in tests and in the demo app are built at runtime:
   ```go
   stripe := "sk_" + "live_" + g.str(alnum, 24)   // seeded math/rand
   ```
   `internal/fixture` writes a deliberately vulnerable demo app this way (`go run ./cmd/mkfixture /tmp/demo`). The test suite asserts the scan of it reports **exactly** the expected findings, no more and no fewer, so any false positive or regression fails CI.
2. **Use keyguard's own allowlist** for what's left:
   ```
   # .keyguardignore
   *_test.go
   internal/fixture/
   ```

Now `make self-scan` exits 0 and could run as a pre-commit check on this repo itself.

## Your notes
<!-- Add `make self-scan` as a git pre-commit hook: .git/hooks/pre-commit -->
