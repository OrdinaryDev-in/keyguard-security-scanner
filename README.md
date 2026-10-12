# keyguard

**Find leaked API keys, secrets and risky config in your app before you deploy it.**
A single Go binary with zero dependencies. It scans your files *and* your git history, and produces a terminal summary, JSON, SARIF for GitHub code scanning, or a self-contained HTML report.

```
$ make demo        # generates a deliberately vulnerable app (fake keys) and scans it

Secrets in code (10)
  HIGH    OpenAI API key                           .env.example:2  sk-p****
  HIGH    AWS access key ID                        config/aws.js:3  AKIA****
  HIGH    Private key                              keys/id_rsa:1  ----****
  HIGH    Password in database connection string   scripts/deploy.sh:2  uCQp****
  HIGH    Stripe live secret/restricted key        src/lib/stripe.ts:4  sk_l****
  HIGH    Supabase service_role JWT                src/lib/supabase-admin.ts:2  eyJh****
  MEDIUM  Google API key                           src/firebase.ts:2  AIza****
  ...

Risky configuration (4)
  HIGH    Secret-looking variable uses a browser-exposed prefix .env.local:2  NEXT_PUBLIC_STRIPE_SECRET_KEY
  MEDIUM  Supabase admin key referenced in client-side code app/dashboard/page.tsx:5  SUPABASE_SERVICE_ROLE_KEY
  ...

✖ 14 findings: 9 high, 4 medium, 1 low (15 files, 11ms)

$ keyguard scan . --history     # a key committed, then "deleted" in a later commit
Secrets in git history (1)
  HIGH    Stripe live secret/restricted key        pay.js:1  sk_l****
          introduced in 7833b90f by Demo on 2026-10-12 (removed from current files)
```

Exit code `1` when anything at or above `--fail-on` (default `high`) is found, so it can gate a deploy.

> Built as a learning project, my first Go program. The **[devlog](docs/LEARNING.md)** covers what I built at each step, the bugs I hit, and what I learned.

## What it detects

| Category | Examples |
|---|---|
| **Known key formats** (17 rules) | AWS, GitHub, Stripe (live/test), OpenAI, Anthropic, Slack, SendGrid, Supabase (`sb_secret_`, `service_role` JWTs; `anon` keys are correctly ignored), Google/Firebase, private keys, passwords in DB URLs, `secret = "..."` assignments |
| **Unknown secrets** | Shannon-entropy detection of random-looking quoted strings |
| **Risky config** | `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_` vars named like secrets · `.env` not gitignored or already committed · Supabase admin key used in `"use client"` code · `debug: true` in prod config |
| **Git history** | Secrets in *any* past commit on *any* branch, including ones "deleted" later, with the commit that introduced them |

Run `keyguard rules` for the full list.

## Install

```bash
go install github.com/OrdinaryDev-in/keyguard-security-scanner/cmd/keyguard@latest
keyguard version
```

Or from a clone: `make build && ./bin/keyguard version`.

## Usage

```bash
keyguard scan                                  # current directory
keyguard scan ./app --history                  # + every commit in git history
keyguard scan . --format html -o report.html   # visual report (open in a browser)
keyguard scan . --format sarif -o out.sarif    # GitHub code scanning
keyguard scan . --format json                  # for other tools
keyguard scan . --fail-on medium               # stricter CI gate
keyguard scan . --no-entropy                   # fewer false positives
```

| Flag | Default | |
|---|---|---|
| `--format` | `text` | `text`, `json`, `sarif`, `html` |
| `-o` | stdout | write report to a file |
| `--fail-on` | `high` | `high`, `medium`, `low`, `none` |
| `--history` | off | scan git history |
| `--max-commits`, `--since` | all | limit history (`--since "6 months ago"`) |
| `--context` | `3` | lines of code shown around findings |
| `--no-entropy`, `--no-color`, `--workers` | | |

### HTML report

One offline HTML file: summary, severity, rule and text filters, redacted code context with the offending line highlighted, and a **how to fix** note for each finding. It has light and dark themes, works on mobile, and is readable with JavaScript off. See [`docs/assets/sample-report.html`](docs/assets/sample-report.html).

### Suppressing false positives

- Add `keyguard:ignore` in a comment on the line.
- Add paths to `.keyguardignore` (gitignore syntax) at the project root.

### In CI

See [`docs/github-action.yml`](docs/github-action.yml): it fails the build on a leak and uploads SARIF so findings appear in the repo's Security tab.

## Privacy by design

- Secrets are **never printed in full**, in any format: `sk_live_abc…` becomes `sk_l****`, and short values become `****`. That includes the code-context lines and private-key bodies.
- `.env` files are never content-scanned. Only variable **names** are checked.
- No network calls, no telemetry.

## How it works

```
cmd/keyguard            CLI, flags, exit codes
internal/
  rules       rule catalogue (embedded rules.json): 17 regex rules + named
              validators (RE2 → linear-time, ReDoS-safe), plus metadata for every check
  entropy     Shannon entropy with length-scaled thresholds
  detect      rules + entropy per line, overlap de-dupe, redaction
  scan        parallel directory walk (goroutine worker pool), .env git exposure
  checks      pure risky-config checks (public env vars, client code, debug flags)
  pathpolicy  which paths to skip, shared by scan and gitscan
  gitcmd      hardened `git` invocations (no fsmonitor)
  gitscan     streams `git log -p` through a diff parser
  report      text / JSON / SARIF / HTML (html/template + go:embed)
  fixture     runtime-generated vulnerable demo app (no literal secrets in repo)
```

## Development

```bash
make test       # unit + end-to-end tests
make race       # with the race detector
make bench      # keyword pre-filter makes clean lines ~16× faster
make demo       # scan a generated vulnerable app
make self-scan  # keyguard must pass on its own source
```

## Compared to gitleaks / trufflehog

Use them for production. They have hundreds of rules, and trufflehog verifies keys live against provider APIs. keyguard is smaller and opinionated toward the Next.js/Supabase/Vercel stack: it checks *configuration* mistakes (public env prefixes, service-role keys in client components, un-ignored `.env`) that pure secret scanners don't, and ships a readable HTML report.

## License

MIT
