# 06 · Git history: "I deleted the key" doesn't mean it's gone

**Built:** `internal/gitscan`, which streams `git log -p` through the same detector.
**Go concepts:** `os/exec` with `StdoutPipe`, `bufio.Scanner` streaming, writing a small state-machine parser.

## The scenario

```
commit 1  add pay.js with sk_live_...      ← key introduced
commit 2  "oops, remove key"               ← file deleted
```

The working tree is clean, but anyone who clones the repo can `git show <commit1>`. Bots scrape public GitHub for exactly this within minutes.

```
$ keyguard scan . --history
Secrets in git history (1)
  HIGH    Stripe live secret/restricted key        pay.js:1  sk_l****
          introduced in 7833b90f by Demo on 2026-10-12 (removed from current files)
```

## How it works

```
git log -p --all --no-color --no-renames -U0 --pretty=format:\x1eKG%H\x1f%an\x1f%aI
```

- `-p` prints every patch, `--all` covers every branch, and `-U0` drops unchanged context lines (we only care about **added** lines).
- A custom `--pretty` header with `\x1e`/`\x1f` separator bytes, which can't appear in normal text, makes commit lines unambiguous to parse.
- Output is **streamed** through `bufio.Scanner`, never loaded into memory. Repos with 100k commits produce gigabytes of patch text.
- The parser is a small state machine: commit header → `diff --git` → `+++ b/file` → `@@ -a,b +c,d @@` (start line number) → `+added lines`.

## Bug I hit while designing it: content that looks like a header

An added line whose content starts with `++` appears in the diff as `+++...`, which looks exactly like the `+++ b/file` header. The parser tracks an `inHeader` flag (true between `diff --git` and the first `@@`), and only treats `+++ ` as a header there. `TestParserPlusPlusContent` covers it.

## De-duplicating across commits

`git log` prints newest first. Findings are keyed by `rule + file + hash(secret)`, and each repeat **overwrites** the earlier entry, so the one kept is the *oldest* commit: where the secret was introduced. Then `main.go` compares hashes against the current scan to label each finding "still in current files" or "removed, but still in history".

## Your notes
<!-- Fixing it for real: rotate the key, then git filter-repo or BFG to rewrite history. -->
