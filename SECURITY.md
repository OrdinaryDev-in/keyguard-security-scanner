# Security Policy

## Supported versions

Security fixes go to the latest release and to `main`.

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| `main` | ✅ |

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/OrdinaryDev-in/keyguard-security-scanner/security/advisories/new).

Include what you can of:

- the keyguard version (`keyguard version`) and OS
- steps or a minimal input to reproduce
- what an attacker could achieve

Do not include real secrets. Use fake values.

You should get an acknowledgement within 7 days. Once a fix is ready it will be
released, and you'll be credited in the advisory unless you'd rather not be.

## What counts

In scope, for example:

- a secret printed unredacted in any output format (text, JSON, SARIF, HTML,
  code-context lines)
- HTML report injection (XSS) from scanned file contents or file names
- command or argument injection via the `git` invocations
- a crafted repo or file that makes keyguard read or write outside the scan
  target
- a regex or input that makes a scan hang or exhaust memory

Not a vulnerability (open a normal issue instead):

- a secret format keyguard doesn't detect (false negative)
- a non-secret flagged as one (false positive)
