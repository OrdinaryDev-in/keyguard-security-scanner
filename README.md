# keyguard

[![CI](https://github.com/OrdinaryDev-in/keyguard-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/OrdinaryDev-in/keyguard-security-scanner/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Find leaked API keys, secrets and risky config in your app before you deploy it.**
A single Go binary with zero dependencies. It scans your files *and* your git history, and produces a terminal summary, JSON, SARIF for GitHub code scanning, or a self-contained HTML report.

![keyguard scanning a demo app, then finding a deleted Stripe key in git history](docs/assets/demo.gif)

<sub>All keys in the demo are fake, generated at runtime. Re-record with `make demo-gif` (needs [VHS](https://github.com/charmbracelet/vhs)).</sub>

```
$ make demo        # generates a deliberately vulnerable multi-stack app (fake keys) and scans it

Secrets in code (19)
  HIGH    Secret in Angular environment file (bundled into the browser)  angular-app/src/environments/environment.prod.ts:5  IfsO****
  HIGH    AWS access key ID                                              config/aws.js:3  AKIA****
  HIGH    Firebase / Google Cloud service account key file               firebase-admin.json:2  serv****
  HIGH    Secret baked into a Docker image (ENV/ARG)                     node-api/Dockerfile:4  Ohzs****
  HIGH    Hardcoded JWT signing secret (Node.js)                         node-api/src/auth.js:3  j9mD****
  HIGH    Stripe live secret/restricted key                              src/lib/stripe.ts:4  sk_l****
  HIGH    Supabase service_role JWT                                      src/lib/supabase-admin.ts:2  eyJh****
  MEDIUM  Hardcoded secret in config file                                spring-api/src/main/resources/application.properties:3  tJOR****
  ...

Risky configuration (8)
  HIGH    Secret-looking variable uses a browser-exposed prefix               .env.local:2  NEXT_PUBLIC_STRIPE_SECRET_KEY
  HIGH    Firebase security rules allow anyone to write                       angular-app/firestore.rules:5  read, write
  HIGH    Firebase "test mode" rule: database is open until a date            angular-app/firestore.rules:6
  HIGH    Terraform state file in the project                                 infra/terraform.tfstate:3
  ...

✖ 27 findings: 19 high, 7 medium, 1 low (26 files, 13ms)

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
| **Known key formats** (works in any language) | AWS, GitHub, Stripe (live/test), OpenAI, Anthropic, Slack, SendGrid, npm tokens, Supabase (`sb_secret_`, `service_role` JWTs; `anon` keys are correctly ignored), Google/Firebase API keys, Firebase/GCP service-account JSON, private keys, passwords in DB URLs, `secret = "..."` assignments |
| **Unknown secrets** | Shannon-entropy detection of random-looking quoted strings |
| **Git history** | Secrets in *any* past commit on *any* branch, including ones "deleted" later, with the commit that introduced them |

### Stack-specific checks

Secret formats are the same in every language. What differs per stack is *how* secrets leak, so keyguard has checks for each:

| Stack | What it checks |
|---|---|
| **Next.js / React / Vite / Vue / Nuxt / SvelteKit / Expo / Angular (ngx-env)** | Secret-named vars with a browser-exposed prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `VUE_APP_`, `NUXT_PUBLIC_`, `PUBLIC_`, `EXPO_PUBLIC_`, `NG_APP_`, `GATSBY_`) |
| **Angular** | Secrets in `environments/environment*.ts`, which is compiled into the browser bundle (public config like the Firebase `apiKey` is allowed) |
| **Firebase / Firestore** | Security rules open to everyone (`allow read, write: if true;`), leftover **test-mode** rules (`request.time < timestamp.date(...)`), open Realtime Database rules, committed service-account key files |
| **Supabase** | `service_role` / secret key referenced in `"use client"` code; `service_role` JWTs anywhere |
| **Node.js / Express** | Hardcoded `jwt.sign/verify` secrets, npm tokens in `.npmrc` |
| **Java / Spring, Rails, Python, docker-compose** | Unquoted secrets in `application.properties`/`.yml`, `.yaml`, `.toml`, `.ini`, `.conf` (`${ENV}` references are fine) |
| **Docker** | Secrets baked into image layers via `ENV`/`ARG` in a `Dockerfile` |
| **Terraform** | `*.tfstate` files in the project (they hold every secret in plain text) |
| **Any project** | `.env` not gitignored or already committed · `debug: true` in prod config |

Stack rules are plain data in [`internal/rules/rules.json`](internal/rules/rules.json): a regex, validators, and a `files` glob limiting where the rule runs. Adding a stack is usually one JSON entry plus a fixture sample.

Run `keyguard rules` for the full list.

## Requirements

- **Go 1.21+** to install or build. The module targets Go 1.27; older 1.21+ toolchains download it automatically on first build.
- **git**: needed for `--history` and for checking whether `.env` files are ignored or committed. Without it, the file scan still works.
- **make** is optional, for the shortcuts below. On Windows, use `go build ./cmd/keyguard` and `go test ./...` directly.

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
| `--max-size` | `2` | skip files larger than this many MiB (they're listed as not scanned) |
| `--no-entropy`, `--no-color`, `--workers` | | |

### HTML report

One offline HTML file: summary, severity, rule and text filters, redacted code context with the offending line highlighted, and a **how to fix** note for each finding. It has light and dark themes, works on mobile, and is readable with JavaScript off. See [`docs/assets/sample-report.html`](docs/assets/sample-report.html).

### Suppressing false positives

- Add `keyguard:ignore` in a comment on the line.
- Add paths to `.keyguardignore` (gitignore syntax) at the project root.

### As a pre-commit hook

```bash
keyguard install-hook          # in your repo: runs `keyguard scan .` before every commit
keyguard install-hook --force  # replace an existing pre-commit hook (kept as pre-commit.bak)
```

The commit is blocked on findings at the default `--fail-on high`. The hook scans the working tree, not just staged changes, and needs `keyguard` on `PATH`. It respects `core.hooksPath` and refuses to overwrite a hook it didn't write. Skip it once with `git commit --no-verify`.

### In CI

See [`docs/github-action.yml`](docs/github-action.yml): it fails the build on a leak and uploads SARIF so findings appear in the repo's Security tab.

## Privacy by design

- Secrets are **never printed in full**, in any format: `sk_live_abc…` becomes `sk_l****`, and short values become `****`. That includes the code-context lines and private-key bodies.
- `.env` files are never content-scanned. Only variable **names** are checked.
- No network calls, no telemetry.
- **No silent gaps.** Files it couldn't read (permission denied) or that exceed `--max-size` are listed in every output format, and a clean result then says "in what was scanned" instead of a plain ✔.

## How it works

```
cmd/keyguard            CLI, flags, exit codes
internal/
  rules       rule catalogue (embedded rules.json): 23 regex rules + named
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

Use them for production secret scanning. They have hundreds of key formats, and trufflehog verifies keys live against provider APIs. keyguard has fewer key formats but goes further on **configuration mistakes** that pure secret scanners don't look for: public env prefixes, Angular environment files, open Firebase rules, secrets baked into Docker images, Terraform state, un-ignored `.env`. It also ships a readable HTML report. A sensible setup is to run both.

## License

[MIT](LICENSE)
