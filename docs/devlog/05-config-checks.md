# 05 · Risky config: leaks that aren't a secret on their own

**Built:** `internal/checks`.
**Concepts:** how frontend frameworks expose env vars, `git check-ignore`, Supabase key types.

Some of the worst leaks contain no secret *value* in the code at all:

| Check | Why it matters |
|---|---|
| `NEXT_PUBLIC_*SECRET*`, `VITE_*SERVICE_ROLE*`, `REACT_APP_*`, `EXPO_PUBLIC_*` ... | These prefixes mean "inline into the JS bundle". Every visitor downloads the value. A `_SECRET` name with a public prefix is almost always a mistake. |
| `.env` not in `.gitignore` | One `git add .` away from being committed. |
| `.env` tracked by git | Already committed: every value is in history. |
| `SUPABASE_SERVICE_ROLE_KEY` in a `"use client"` file | The service-role key bypasses Row Level Security. It must only ever run server-side. |
| `debug: true` in `*prod*.json/yaml` | Debug output leaks stack traces and internals. |

## Asking git instead of re-implementing it

To know whether `.env` is ignored, I could parse `.gitignore` myself... but git's rules (nested `.gitignore`s, global excludes, negation) are complex. Inside a repo, keyguard just asks git:

```
git check-ignore -q -- .env        # exit 0 = ignored
git ls-files --error-unmatch -- .env   # exit 0 = tracked (committed!)
```

Outside a repo, it falls back to `internal/ignore`, a small gitignore-subset matcher that also powers `.keyguardignore`.

## Privacy rule

`EnvFile` only ever records **variable names**. Values are never stored, hashed or printed. `TestEnvFileReportsNamesOnly` checks this.

## Your notes
<!-- Run keyguard on one of your own Next.js projects. Anything surprising? -->
