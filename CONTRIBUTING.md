# Contributing to keyguard

Thanks for helping. Bug reports, false-positive/false-negative reports and new
rules are the most useful contributions.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

> **Never paste a real secret** into an issue, PR, test or commit, even a
> revoked one. Use a fake value or describe its shape (e.g. `sk_live_` + 24
> alphanumerics). Found a security bug in keyguard itself? See
> [SECURITY.md](SECURITY.md) instead of opening an issue.

## Setup

You need Go 1.21+ (the toolchain in `go.mod` is downloaded automatically) and
`git`. `make` is optional.

```bash
git clone https://github.com/OrdinaryDev-in/keyguard-security-scanner.git
cd keyguard-security-scanner
make test
```

## Before you open a PR

Run what CI runs:

```bash
make vet        # gofmt -l . must print nothing, then go vet
make race       # tests with the race detector
make self-scan  # keyguard must find nothing in its own source
```

CI also runs `./bin/keyguard scan . --history --fail-on low`, so a fake secret
committed in *any* commit of your branch fails the build. Squash it out rather
than deleting it in a follow-up commit.

## Adding or changing a rule

Rules live in [`internal/rules/rules.json`](internal/rules/rules.json). Most
new detections are one JSON entry:

```json
{
  "id": "example-api-key",
  "kind": "pattern",
  "description": "Example API key",
  "severity": "high",
  "keywords": ["exk_"],
  "regex": "\\b(exk_[A-Za-z0-9]{32})\\b",
  "secret_group": 1,
  "fix": "Revoke it in the Example dashboard, then load it from a server-side environment variable."
}
```

- **`id`**: kebab-case, unique.
- **`keywords`**: lowercase substrings that must appear on the line before the
  regex runs. This pre-filter is what keeps clean lines fast, so pick
  something specific.
- **`regex`**: Go RE2 syntax (no lookarounds or backreferences). Anchor with
  `\b` or a prefix to avoid matching inside longer tokens.
- **`secret_group`**: the capture group holding the secret, which is what gets
  redacted.
- **`files`** (optional): a glob limiting the rule to certain files, for
  stack-specific checks.
- **`fix`**: one or two sentences shown in the HTML report. Lead with
  "revoke/rotate" if the key could already be compromised.

Then add test coverage:

1. **Fixture**: add a sample to [`internal/fixture/fixture.go`](internal/fixture/fixture.go)
   and its `"file|rule-id"` pair to `Expected`. Build the fake secret at
   runtime from fragments and the seeded generator (`"exk" + "_" + g.str(alnum, 32)`)
   so the repo never contains a literal match, or GitHub push protection and
   the self-scan will flag it.
2. **Look-alike**: add something that must *not* match (a placeholder, an
   env-var reference, a test key) to the same file. The fixture test fails on
   any unexpected finding.
3. Run `make test` and `make demo` to see the finding as a user would.

Severity guide: **high** means the value can be used as-is to access money,
data or infrastructure. **medium** is a likely secret or risky config that needs
context. **low** is hygiene (test keys, minor misconfig).

## Code style

- Standard library only; keyguard has zero dependencies and should stay that way.
- `gofmt`, and match the surrounding code.
- Secrets must never be printed in full in any output format. If you touch
  reporting, check the redaction tests still cover your path.

## Commits and PRs

- One logical change per PR, with a short description of *why*.
- Link the issue it fixes, if there is one.
- For a false positive/negative fix, include the (fake) input that triggered it.
