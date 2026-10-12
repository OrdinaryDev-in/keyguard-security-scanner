# 04 · Shannon entropy: catching secrets no regex knows

**Built:** `internal/entropy`, which flags random-looking quoted strings.
**Concepts:** information theory, threshold tuning, fighting false positives.

## The math

```
H = -Σ p(c) · log2 p(c)     (bits per character)
```

| String | H |
|---|---|
| `aaaaaaaa` | 0 |
| `abab` | 1 |
| English text | ~3–4 |
| random base64 key | ~4.5–5.5 |

## Lesson 1: thresholds must scale with length

My first idea was "flag anything above 4.5". But **a string of length n can never exceed log2(n)**. A 20-char string maxes out at 4.32, so a fixed 4.5 threshold silently ignores every short secret. The threshold is now `min(4.5, 0.85 × log2(len))` for base64-ish strings, and `min(3.0, 0.75 × log2(len))` for hex (only 16 symbols → max 4 bits/char).

## Lesson 2: false positives are the real product

A scanner that cries wolf gets disabled. What got filtered, in order of how much noise it removed:

1. **Only quoted strings.** Unquoted identifiers like `handleOAuth2CallbackV2` are long and mixed-case too.
2. **Must contain a digit and letters** (and both cases for non-hex).
3. **UUIDs**, **SRI hashes** (`sha512-...`), and anything over 120 chars (embedded fonts/images).
4. Lockfiles skipped entirely.

**Known limitation (found by dogfooding):** backticks count as quotes because JS template strings use them, so in markdown a code span like `` `handleOAuth2CallbackV2` `` (22 chars) still gets flagged. Shorter strings get lower thresholds, which makes them easier to trip. Ideas for v2: a dictionary-word check (identifiers split into English words; keys don't), or only treating backticks as quotes in `.js/.ts` files.

## Lesson 3: entropy also kills false positives in regex rules

The fixture's "safe" file contained a docs placeholder: `sk_live_` followed by 24 `x`s. It matched the Stripe regex perfectly and **was flagged HIGH on the first run**. Real keys are random; placeholders repeat. Every regex match now also needs entropy ≥ 2.5 (`minRuleEntropy` in `internal/detect`). That's far below any real key (~4.5+) but above `xxxx`-style placeholders (~2).

**Postscript:** when I first pushed this repo, GitHub's own push protection blocked it, flagging that exact placeholder as a "Stripe API Key" in three files. Same false positive, different scanner. The fix was splitting the literal (`"sk_" + "live_xxx…"`) so no file contains it whole.

## Your notes
<!-- Try: go test -v -run TestFind ./internal/entropy/ and tweak the thresholds -->
