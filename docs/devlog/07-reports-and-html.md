# 07 · Reports: text, JSON, SARIF, and a self-contained HTML page

**Built:** `internal/report`: four output formats, plus the HTML report as the visual frontend.
**Go concepts:** `html/template` context-aware escaping, `//go:embed`, `encoding/json` struct tags, `MarshalText`.

## The HTML report

```
keyguard scan . --format html -o report.html
```

![sample report](../assets/sample-report.html)

- **One file, zero network requests.** CSS and JS are inlined, so it opens offline and can be attached to a CI run or PR. A test fails if any `http://` or CDN URL sneaks in.
- Summary cards → severity chips, rule filter and search → expandable findings showing ±3 lines of (redacted) code, the offending line highlighted, and **how to fix it**.
- Native `<details>/<summary>` makes rows keyboard- and screen-reader-accessible for free. **It works with JavaScript disabled**; JS only filters what's already rendered.
- Light and dark via `prefers-color-scheme`; collapses to stacked cards on phones (checked at 375px: no horizontal scroll).

## `go:embed`

```go
//go:embed html/report.tmpl html/style.css html/app.js
var assets embed.FS
```

The template, CSS and JS are compiled **into the binary**. `keyguard` stays a single file to install.

## Security of the report itself

The report displays file names and code from the scanned repo, which is **attacker-controlled input**. A file named `<script>alert(1)</script>.ts` must not run script when you open the report. `html/template` (not `text/template`!) escapes each value for the context it lands in: element text, attribute, URL, etc. `TestHTMLEscapesScannedContent` uses exactly that file name.

## Bug: secrets leaking through "context" lines

Showing code around a finding is great UX, but every context line is a chance to leak. My test that greps the JSON output for every fake secret **caught a real leak**: the private key's *body* (bare base64 lines) was printed unredacted, because only the `-----BEGIN ... PRIVATE KEY-----` header matched a rule. `RedactLine` now replaces any 40+ char pure-base64 line with `[redacted base64 block]`.

## Bug: double-spaced code

Each code line is a `display:block` span **and** I had a newline after it inside the `<pre>`, so every line got an extra blank line. The fix was moving `{{end}}` onto the same line. Whitespace inside `<pre>` is content.

## SARIF

SARIF is the JSON format GitHub code scanning reads. Upload it in CI (`docs/github-action.yml`) and findings show up in the repo's **Security** tab and inline on pull requests.

## Your notes
<!-- Open docs/assets/sample-report.html in a browser and try the filters. -->
