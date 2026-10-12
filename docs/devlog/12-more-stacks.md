# 12 · Beyond Next.js: Angular, Firebase, Node, Spring, Docker, Terraform

**Built:** stack-specific checks for Angular, Firebase/Firestore, Node.js, Spring/Rails/Python config files, Docker, Terraform and Vue, plus a `files` filter on rules.
**Concepts:** how each stack leaks secrets, file-scoped rules as data, fighting false positives in unquoted config.

## Insight: secrets aren't stack-specific, leaks are

An AWS key is `AKIA…` whether it sits in TypeScript, Java or YAML, so the 17 original key-format rules already worked everywhere. What *was* tied to Next.js/Supabase were the configuration checks. So "support more stacks" didn't mean more key regexes. It meant learning how each ecosystem typically leaks:

| Stack | The classic leak |
|---|---|
| Angular | `environment.prod.ts` *feels* server-side but is compiled into the browser bundle |
| Firebase | Shipping the console's "test mode" rule (`if request.time < timestamp.date(...)`) or `allow read, write: if true;` |
| Node | `jwt.sign(payload, "my-secret")`, which lets anyone who reads the repo forge logins |
| Spring / Compose / Rails | `password=...` **without quotes** in `application.properties` / `docker-compose.yml` |
| Docker | `ENV DB_PASSWORD=...` survives in image layers (`docker history`) |
| Terraform | `terraform.tfstate` holds every resource attribute, passwords included, in plain text |

## Design: rules that only run on certain files

A Dockerfile rule makes no sense on a `.ts` file, and `password=abc123` means "secret" in `application.properties` but might be a variable in JavaScript. So rules got a `files` field:

```json
{ "id": "dockerfile-secret", "files": ["Dockerfile", "Dockerfile.*", "*.Dockerfile"], ... }
{ "id": "angular-environment-secret", "files": ["environments/environment*.ts"], ... }
```

A glob without `/` matches the file name; one with `/` matches the end of the path at a folder boundary. So `environments/environment*.ts` matches `src/environments/environment.prod.ts` but not `src/myenvironments/…`. The detector API became `LineIn(file, line)`. The old `Line(line)` still exists, means "unknown file", and skips file-scoped rules.

Most of the new stack support is **JSON, not Go**. Firebase rules and Terraform state are the exceptions: they're dangerous *settings*, not secret values, so they live in `internal/checks` where they aren't redacted like secrets.

## False positives: unquoted values

Quoted strings are easy: `"..."` is clearly a value. In YAML and `.properties` files, everything is unquoted:

```yaml
password: Zq8vLm2Rt7            # secret
password: ${DB_PASSWORD}        # reference: fine
password-encoder: bcrypt        # a name: fine
secretName: my-tls-cert         # Kubernetes object name: fine
```

The rule chains validators: `not-placeholder` rejects `${…}`, `{{…}}`, `your-…`, and the new **`has-digit-or-symbol`** requires a digit or one of `!@#$%^&*+=?~|`. Names use letters plus `- _ . /`; real passwords and keys almost never do.

## Security: short secrets in context lines

The HTML report shows ±3 lines around each finding. The old safety net masked any 24+ char letter-and-digit token, but `spring.datasource.password=Zq8vLm2Rt7` is short and unquoted, so it would have been printed in a neighbouring finding's context. Context redaction now also knows the file (`RedactLineIn(file, line)`), so file-scoped rules mask their values in context too. `TestStackSecretsNotLeaked` checks every unquoted fixture password against the full JSON output.

## How it's tested

The demo app (`go run ./cmd/mkfixture`) gained an Angular app, a Node API (with `.npmrc` and a Dockerfile), a Spring API, `docker-compose.yml`, a Django settings file, a Vue app, a service-account JSON and a Terraform state file. Each file also holds **look-alikes that must not fire**: `${MAIL_PASSWORD}`, `password-encoder=bcrypt`, `ARG NPM_TOKEN` with no value, `jwt.verify(t, secret)` with a variable, auth-gated Firestore rules, `VUE_APP_API_URL`. The fixture test asserts exactly 27 findings, so any new false positive or missed leak fails CI.

## Your notes
<!-- Try it on one of your Angular + Firestore projects. Did the rules checks find anything? -->
