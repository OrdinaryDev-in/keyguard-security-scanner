# 10 · Refactoring for maintainability

**Built:** one rule catalogue (`internal/rules/rules.json`), `internal/pathpolicy`, `internal/gitcmd`, a channel-only `scan.Dir`. Same findings as before, byte for byte.
**Go concepts:** `go:embed`, `sync.OnceValues`, `errors.Join`, `json.Decoder.DisallowUnknownFields`, package dependency direction, "share memory by communicating".

The code-quality review left three architectural items: rule metadata scattered over five files, `gitscan` importing `scan`, and `checks` doing I/O. None were bugs. They were the kind of thing that makes the *next* change painful.

## 1. One rule catalogue

Before, a rule's description, severity and fix lived wherever the finding was built: `rules.go` for regexes, `detect.go` for entropy, `checks.go` for five config rules, `gitscan.go` for one, and a hard-coded line in `main.go`. `keyguard rules` listed 18 of the 25 things keyguard could report.

Now every rule is one entry in `rules.json`, embedded into the binary:

```go
//go:embed rules.json
var builtin []byte

var Default = sync.OnceValues(func() (*Catalogue, error) { return Load(builtin) })
```

- **`go:embed`** keeps it a single static binary with zero deps. The file is data, not code, so adding a rule is a JSON edit plus a test case.
- **Validators by name.** JSON can't hold a Go func, so a rule says `"validators": ["not-placeholder", "min-entropy:3.0"]` and a registry (`map[string]validatorFactory`) turns each spec into a check. Bad args fail at load time, not on the first matching line.
- **`Load` returns errors, never panics.** It checks unique IDs, lowercase keywords, `secret_group` ≤ `regex.NumSubexp()`, a non-empty fix, and rejects unknown JSON fields (`DisallowUnknownFields`), so a typo like `secret_grop` can't silently disable a rule. It collects *every* problem with **`errors.Join`**, so one run shows them all.
- **`sync.OnceValues`** (Go 1.21+) runs `Load` once, on first use, and caches both the catalogue *and* the error. Before, `Default()` recompiled 17 regexes every call.
- Code that builds non-regex findings asks for metadata by ID: `rules.MustLookup("env-file-committed").Finding(finding.SourceConfig)`. `Must` panics on an unknown ID, the same convention as `regexp.MustCompile`: that's a typo in our code, not bad input, and `TestReferencedIDsExist` catches it.

**Gotcha I hit:** a cached value is shared. The benchmark that sets `r.Keywords = nil` would have changed the rules for every later test. `detect.New` now `slices.Clone`s the slice, and the benchmark copies each rule before editing it.

## 2. Dependencies point one way

`gitscan` imported `scan` just to borrow `SkipPath`, `IgnoreFile` and `Sort`. Two peers depending on each other is how import cycles start. The shared parts moved down a level:

```
cmd/keyguard
  ├─▶ scan ─────┬─▶ detect, checks ──▶ rules ──▶ finding
  └─▶ gitscan ──┴─▶ pathpolicy, gitcmd           (leaves: stdlib only)
```

- `pathpolicy`: skip lists, `SkipPath`, `IsEnvFile`, `IgnoreFile`.
- `finding.Sort`: sorting findings belongs with the type.
- `gitcmd.Command(ctx, dir, args...)`: the one place that adds `-c core.fsmonitor=false`. The security fix from devlog 09 can't be forgotten in a new call site.

`checks.EnvExposure` shelled out to git, which made `checks` the only "pure" package that wasn't. It is now `scan`'s unexported `envExposure`, and it takes a `context.Context`, so Ctrl-C also stops those git calls. If the context is cancelled, it returns the error rather than findings. A killed `git check-ignore` would otherwise look like "not ignored".

## 3. A constructor for the duplicated Finding literal

`scan.Content` and `gitscan` both built the same 9-field `Finding` from a detector hit, including redaction and hashing. Now that's `Hit.Finding(src, file, line)`. A future change to how secrets are redacted happens once.

## 4. Share memory by communicating

Devlog 03 explained why reading `walkErr` and `envFiles` without a mutex was safe: a chain of `close` → `wg.Wait` → `close`. That was correct, but you had to understand the whole chain to change any line of `Dir`.

Now nothing is shared:

```go
walkErr := make(chan error, 1) // buffered: the walker can always send and exit
...
results <- fileResult{rel: rel, findings: found, scanned: ok, env: pathpolicy.IsEnvFile(rel)}
...
if err := <-walkErr; err != nil {
```

The env-file list is built by the collector from `fileResult.env`, and the walk error arrives on its own channel. The buffer of 1 matters: if nobody ever received from an unbuffered channel, the walker goroutine would block forever and leak. The Go proverb is *"Don't communicate by sharing memory; share memory by communicating."* This is that proverb applied.

## How I checked "no behaviour change"

Before touching code, I saved the JSON output of the old binary on the demo fixture, once as a git repo with `--history` and once as a plain folder. After the refactor, both diffs were empty. `go test -race ./...` and `make self-scan` stay green, and the keyword-prefilter benchmark still shows the same ~16× gap.

## Your notes
<!-- Try: add a rule to rules.json with "secret_group": 3 and run go test ./internal/rules/ -->
