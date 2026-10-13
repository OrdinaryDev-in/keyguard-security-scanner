# 14 · Identifiers aren't secrets: file-aware backticks and a word check

**Built:** `entropy.FindIn(file, line)`, which only treats backticks as quotes in JS/TS and Go, and `looksLikeWords`, which skips strings built from identifier words. Word list embedded in `internal/entropy/words.txt`.
**Concepts:** splitting camelCase, word-break dynamic programming, `go:embed` for data, testing a filter against the thing it could hide.

## The bug

Devlog 04's known limitation: `` `handleOAuth2CallbackV2` `` in markdown was reported as a possible secret. `keyguard scan docs/` showed it three times. It passes every entropy check: 22 chars, mixed case, digits, and entropy above the length-scaled threshold. To the math it looks random. To a person it's obviously four words.

## Fix 1: backticks are only strings in some languages

| File | What `` `...` `` means |
|---|---|
| `.js .jsx .ts .tsx .mjs .cjs .mts .cts .vue .svelte .astro` | template string |
| `.go` | raw string |
| `.md` | code span |
| `.sh`, `Makefile` | command substitution |
| `.sql` (MySQL) | identifier |

So `FindIn` uses the old regex (with backticks) for the first two rows, and a quotes-only regex for everything else. The detector already knew the file (`LineIn(file, line)` since devlog 12), so this was one changed call.

**Unknown file (`Line(line)`, `rel == ""`): backticks still count.** If I don't know the language, an extra finding is cheaper than a missed key.

## Fix 2: a word check

```
handleOAuth2CallbackV2  →  handle · O · Auth · 2 · Callback · V · 2
                           word        word        word
```

`looksLikeWords(v)` returns true (= don't report) only if **all** of these hold:

1. No `+`, `/` or `=`. Only base64 uses them; identifiers never do.
2. At most 4 digits, and no more than 20% of the length. Random hex is ~60% digits, so it stops here.
3. Split on `_`, `-`, case changes and digit runs. At least 2 words, and at least 7 in 8 letters must be inside a word.

A fragment counts as a word if it's in the list, it's in the list after dropping one suffix (`throttled` → `throttle`), or it splits fully into 3+ letter words (`webhook` → `web` + `hook`). That last part is the classic **word-break** problem: `best[i]` = fewest words covering the first `i` letters, filled left to right. Two-letter words (`id`, `by`, `to`, `io`…) only count as a whole fragment, never as a piece, because random keys are full of two-letter runs.

It runs last in `classify`, so only strings that already passed every entropy check pay for it.

### Where the word list came from

5,494 lowercase words, 3+ letters, one per line, embedded with `go:embed` like `rules.json`. I mined them instead of typing them. A Python one-off split every identifier in the Go standard library and TypeScript's `lib.*.d.ts` on case changes, and kept fragments that appear in 5+ files and are either an English word (`/usr/share/dict/words`) or appear in 40+ files (that's how `ctx`, `utf` and `json` get in). Then I added ~300 web-app words the Go stdlib never says (`firebase`, `webhook`, `oauth`, `checkout`, `avatar`…).

**Gotcha:** the mined list had `xff`, `ffff`, `xffffffff`: hex constants from Go source. Words made only of `a`–`f` make random hex look more like words, so I deleted them and the rarer ones (`dab`, `cee`…).

## The real risk: a filter that hides findings

Every other filter in keyguard can only make things noisier. This one makes findings disappear. If it ever says a real key "looks like words", that key is silently missed. So the test is about keys, not identifiers:

```go
// 5 alphabets × every length 20..120 × 100 seeds = 50,500 random keys
for _, cs := range []string{alnum, base64Std, base64URL, hexLower, hexUpper} {
    for n := minLen; n <= maxLen; n++ {
        ...
        if looksLikeWords(key) { t.Fatalf(...) }
        if wouldFlag(key) && len(Find(`"`+key+`"`)) == 0 { t.Fatalf(...) }
```

None of them gets through. To see how close they came, I measured the best word coverage over 100k random base64/alphanumeric keys: **0.41**. The bar is **0.875**. Random keys switch case every couple of characters, so they break into 1–2 letter fragments that are almost never words. Other tests check that a word prefix doesn't hide a key: `handleOAuthCallback` + a random key is still reported.

## Does each fix pull its weight?

I ran the old and new binaries over real code I had on disk (none of it mine):

| Corpus | Before | Word check only | Both |
|---|---|---|---|
| 11,570 `.go/.ts/.js` files from node_modules and the Go module cache | 126 | 113 | 113 |
| 4,000 `.md` files from node_modules | 79 | 75 | 71 |

- **Word check:** removed `sha256WithRSAEncryption` (×6 variants), `DecodeBase64StringError`, `EC2ThrottledException`, `certValidity1UTCTime`, `i18nLegacyMessageIdFormat`, `X-Amz-Content-Sha256`, `useDateIso8601Format`. All identifiers. It added nothing.
- **Backticks:** in markdown it also removed a commit SHA, an `sha1-…` integrity hash, a temp path and a public Bitcoin donation address, all in code spans. None of those are identifiers, so the word check can't catch them.

So both earn their place, on different inputs. Neither changed the demo app: still exactly 27 findings.

## What can now be missed (honest list)

- **A random key in a markdown code span** (`` `Xy7…` ``) is no longer caught by entropy. Keys with a known format (`sk_live_`, `ghp_`, `AKIA`…) still are, because regex rules don't care about quotes. Same for a JS template string inside a fenced code block in a `.md` file, and in `.mdx`/`.html` files.
- **A secret made of words**: 7 in 8 letters from the list, at most 4 digits, no `+/=`. Most of these were never caught anyway: `"CorrectHorse7BatteryStaple"` scores 3.62 bits/char, under its 4.0 threshold. If the variable is named `password`/`secret`/`token`, the `generic-secret` rule still catches it.
- Backticks in shell (`` TOKEN=`…` ``) don't count. That's command output, not a literal.

## Still noisy (not fixed here)

- Alphabet constants: a quoted `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789` is the most common remaining false positive in library code.
- SRI hashes with `sha1-` (only `sha256/384/512-` are skipped).

## Benchmarks

`BenchmarkLineNoMatch` is unchanged (~2.4 µs median before and after): a line with no long quoted string never reaches the new code. `BenchmarkScanFixture` is ~7% slower at the median, and the before/after runs overlap. The first version was ~13% slower with +230 allocs/op. Counting digits before splitting anything, and stopping as soon as too many letters are uncovered, cut that to +41.

## Your notes
<!-- Try: go test -v -run 'TestLooksLikeWords|TestFindIn' ./internal/entropy/ then add one of your own Angular/Firebase identifiers. Does it need a word added to words.txt? -->
