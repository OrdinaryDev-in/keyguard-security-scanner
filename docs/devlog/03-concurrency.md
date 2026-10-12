# 03 · Walking a repo with a goroutine worker pool

**Built:** `internal/scan`: directory walker, skip lists, binary detection, `.keyguardignore`, parallel scanning.
**Go concepts:** goroutines, channels, `sync.WaitGroup`, `context` cancellation, the happens-before rule.

## The pipeline

```
WalkDir goroutine ──paths──▶ N worker goroutines ──results──▶ collector (main goroutine)
```

- One goroutine walks the tree and sends relative paths on an **unbuffered** channel. It can't get ahead of the workers, so memory stays flat on huge repos.
- `runtime.NumCPU()` workers each `range` over `paths`, scan a file, and send its findings on `results`.
- A tiny goroutine does `wg.Wait(); close(results)`. Closing `results` is what ends the collector's `for r := range results` loop. **Forgetting this close is the classic Go deadlock.**
- `signal.NotifyContext` cancels the context on Ctrl-C. The walker's `select` notices and stops.

## Happens-before (the subtle part)

The walker writes `walkErr` and `envFiles`, and the collector reads them after the loop, with **no mutex**. Is that a data race? No, because of a chain of synchronisation:

1. walker writes `walkErr`, then `close(paths)` (deferred)
2. workers' `range paths` ends → `wg.Done()`
3. `wg.Wait()` returns → `close(results)`
4. collector's `range results` ends → reads `walkErr`

Each step "happens before" the next under the Go memory model. `go test -race ./...` agrees: it runs on every change.

## Skipping the right things

- Dirs: `node_modules`, `.git`, `.next`, `dist`, `vendor`, `.vercel`, ...
- Files: lockfiles (full of `sha512-` hashes that look random), media, `*.min.js`, `*.map`.
- Binary: a NUL byte in the first 512 bytes. It's the same heuristic git uses.
- `.env` files are **not** content-scanned. They're *supposed* to contain secrets; the risk is them being committed (see devlog 05). Only their variable *names* are checked.

## Your notes
<!-- Try: go test -bench . ./internal/scan/ with Workers: 1 vs NumCPU -->
