# 02 · Regex rules and a 16× speedup from one `strings.Contains`

**Built:** `internal/rules`: 17 rules for AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, SendGrid, Supabase, Google, private keys, DB URLs and generic `secret = "..."` assignments.
**Go concepts:** structs, `regexp` (RE2), capture groups, function fields, table-driven tests, benchmarks.

## RE2: why Go regex has no lookaheads

Go's `regexp` is RE2. Every match runs in **linear time**, so a hostile file can't trigger catastrophic backtracking (ReDoS) and hang the scanner. The cost: no lookaheads or backreferences. Anything a regex can't express goes into a `Validate func(string) bool` on the rule:

- **Supabase service_role vs anon key:** both are JWTs and look identical to a regex. `Validate` base64-decodes the payload and reads the `role` claim. JWT payloads aren't encrypted, anyone can read them. `anon` keys are public by design and aren't flagged; `service_role` keys bypass Row Level Security and are HIGH.
- **OpenAI keys** always contain `T3BlbkFJ`, which is base64 for "OpenAI". A neat fingerprint.

## Keyword pre-filter

Every rule lists cheap lowercase keywords (`"akia"`, `"sk-ant-"`, ...). A line only reaches a rule's regex if it contains one. Most lines contain none, so most regexes never run. This is the same trick gitleaks uses.

Measured with `go test -bench`, on a typical line with no secret (Apple M-series, 8 cores):

| | ns/line |
|---|---|
| all 17 regexes + entropy | **31,715** |
| keyword pre-filter first | **2,000** |

**~16× faster** from one `strings.Contains` loop. `BenchmarkLineNoMatchWithoutKeywords` in `internal/detect` reproduces this.

A trap here: keywords are compared against the *lowercased* line, so an uppercase keyword silently disables its rule. `TestKeywordsLowercase` guards against that.

## Overlapping matches

`const STRIPE_SECRET = "sk_live_..."` matches three things: the Stripe rule, the generic `SECRET = "..."` rule, and the entropy detector. `detect.dedupe` keeps the highest-severity, most specific rule for any overlapping span, so it's reported once, as a Stripe key.

## Your notes
<!-- Which rule was hardest to get right? -->
