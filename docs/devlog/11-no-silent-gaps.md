# 11 · No silent gaps: a clean result has to say what it didn't check

**Built:** reporting of paths that couldn't be scanned, `--max-size`, CI for this repo, LICENSE.
**Concepts:** honest negative results, error paths in `filepath.WalkDir`, who closes a channel.

## The problem

Before this change, if a folder was permission-denied or a file was over the 2 MiB limit, keyguard skipped it **silently** and still printed:

```
✔ No secrets or risky config found
```

For a security tool that's the worst kind of bug: a confident "all clear" that's actually "I didn't look". Users act on the ✔, not on the fine print.

## What it does now

```
! 2 paths could not be scanned:
    bundle.js  larger than 2 MiB (raise with --max-size)
    private  unreadable (permission denied or I/O error)

! No secrets or risky config found in what was scanned (1 files, 2ms), but 2 paths were not checked
```

- The same list is in the JSON (`"skipped": [...]`, always present, so CI scripts can rely on it) and in the HTML report as a highlighted section.
- **Deliberate** skips (`node_modules/`, lockfiles, images, minified bundles) stay silent. They're policy, not failure, and listing them would bury the real gaps.
- If the scan root itself can't be read, it's an error (exit 2), not an empty "clean" report.

## The Go part: one more sender on the results channel

Unreadable directories are discovered by the **walker** goroutine, not the workers. To report them over the same `results` channel, the walker now also counts in the `WaitGroup`. Otherwise `wg.Wait(); close(results)` could close the channel while the walker is still sending on it, and **sending on a closed channel panics**. The rule: whoever closes a channel must know every sender is done.

## Repo hygiene

- **LICENSE**: the README said MIT, but without the file the code isn't actually licensed for reuse.
- **CI** (`.github/workflows/ci.yml`): gofmt, vet, race-detector tests, then keyguard scans **its own code and full git history** with `--fail-on low`. The tool's credibility depends on its own repo being clean.

## Your notes
<!-- Try: chmod 000 a folder in a test project and run keyguard on it. -->
