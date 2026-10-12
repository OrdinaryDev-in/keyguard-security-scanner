# 01 · Setup and a CLI with zero dependencies

**Built:** Go module, project layout, `keyguard scan|rules|version` CLI.
**Go concepts:** modules, `cmd/` vs `internal/`, the standard `flag` package, exit codes.

## What I did

- `brew install go` → Go 1.27. `go mod init keyguard`.
- Layout follows the common Go convention:
  - `cmd/keyguard/main.go`: the binary, kept thin.
  - `internal/...`: everything else. The Go compiler **refuses** imports of `internal/` packages from outside this module, so it's a real API boundary, not just a naming habit.
- No CLI framework (Cobra etc.). The stdlib `flag` package was enough, and the binary has **zero third-party dependencies** (`go.mod` has no `require` block).

## Bug I designed around: flags after the path

```
keyguard scan . --history
```

Go's `flag` package **stops parsing at the first non-flag argument**, so `--history` above is silently ignored and the scan quietly skips history. That's a nasty failure mode for a security tool. The fix, `parseInterleaved` in `cmd/keyguard/main.go`, keeps calling `fs.Parse` on whatever's left after each positional argument. There's a test for it.

## Exit codes are the CI API

| Code | Meaning |
|---|---|
| 0 | clean (or nothing at/above `--fail-on`) |
| 1 | findings at/above `--fail-on` (default `high`) |
| 2 | usage or runtime error |

CI only looks at "non-zero = fail", so this is the whole integration contract. `main()` is just `os.Exit(run(args, stdout, stderr))`, which makes `run` testable without spawning a process (`TestExitCodes`).

## Your notes
<!-- What surprised you about Go so far? -->
